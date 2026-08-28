#!/usr/bin/env python3
"""Normalize audit JSON and check outputs into audit.values.json."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

WORKLOAD_DIR = str(Path(__file__).resolve().parent)
if WORKLOAD_DIR not in sys.path:
    sys.path.insert(0, WORKLOAD_DIR)

from kubernetes_quantities import kubernetes_memory_gib

# Vendor prefixes that nvidia-smi / rocm-smi / k8s gpu.product labels prepend.
_VENDOR_PREFIX = re.compile(r"^(nvidia|amd|advanced[-_ ]?micro[-_ ]?devices|intel)[-_ ]", re.I)
# Sub-brand / line tokens that sit between the vendor and the model number
# ("AMD Instinct MI300X", "NVIDIA Tesla V100"). Dropped when they lead.
_BRAND_TOKEN = re.compile(r"^(instinct|tesla|geforce|rtx|gtx|quadro|radeon|titan)$", re.I)
# Packaging / form-factor / memory tokens to drop from the bare chip name.
_SUFFIX_TOKEN = re.compile(
    r"^(sxm\d*|pcie|oam|ac|nvl\d*|hbm\d*e?|\d+gb|\d+g|gpu|graphics|accelerator)$",
    re.I,
)


def normalize_chip_name(raw: Any) -> str:
    """Collapse a raw GPU model string to its bare accelerator name.

    "NVIDIA-H100-80GB-HBM3" -> "H100", "NVIDIA-B300-SXM6-AC" -> "B300",
    "NVIDIA-GB300" -> "GB300", "AMD-Instinct-MI300X" -> "MI300X".

    Mirrors `dashboard/src/lib/chip-name.ts` (normalizeChipName) so the value we
    RECORD in cluster.gpu_model matches what the dashboard SHOWS. The raw value
    is preserved untouched under audit_data.gpus.model for traceability and so
    the existing graders (which read the raw string) are unaffected.
    """
    if raw is None:
        return "unknown"
    trimmed = str(raw).strip()
    if trimmed == "":
        return "unknown"

    # The professional Blackwell part has been observed as "NVIDIA RTX PRO
    # 6000 Blackwell Server Edition" and "PRO-6000-Blackwell-Server-Edition".
    # Record the short product name instead of the tokenized long form.
    normalized = re.sub(r"\s+", " ", re.sub(r"[-_]+", " ", trimmed.upper()))
    if (
        "RTX PRO 6000" in normalized
        or "RTX 6000 PRO" in normalized
        or re.search(r"(^| )PRO 6000( |$)", normalized)
    ):
        return "RTX 6000 Pro"

    without_vendor = _VENDOR_PREFIX.sub("", trimmed)
    tokens = [t for t in re.split(r"[-_\s]+", without_vendor) if t]
    # Drop any leading sub-brand tokens so the model number leads ("Instinct"
    # before "MI300X", "Tesla" before "V100").
    while tokens and _BRAND_TOKEN.match(tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return trimmed

    out = [tokens[0]]
    for tok in tokens[1:]:
        if _SUFFIX_TOKEN.match(tok):
            continue
        if re.fullmatch(r"[a-z]", tok, re.I) and re.search(r"\d", out[-1]):
            # Single-letter variant: re-attach (AMD "MI300" + "X" -> "MI300X").
            out[-1] = out[-1] + tok.upper()
        elif re.fullmatch(r"[a-z]{2}", tok, re.I):
            # Bare two-letter tokens are packaging/cooling codes such as AC or
            # PC, not part of the accelerator family.
            continue
        else:
            # Preserve model numbers and product words (Gaudi 3).
            out.append(tok)

    return "-".join(out)


def load_check_data(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        with Path(path).open() as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("check data must be a JSON object")
        return data
    except (OSError, ValueError, KeyError) as exc:
        print(f"WARNING: failed to parse check data: {exc}", file=sys.stderr)
        return {}


def nested_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def first_known(*values: Any, default: Any = None) -> Any:
    """Return the first value that looks like a real measurement."""
    missing = {"", "unknown", "not-found", "none", "N/A", "n/a"}
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text.lower() in missing:
            continue
        return value
    return default


def host_check(audit: dict[str, Any]) -> dict[str, Any]:
    check = audit.get("hostCheck")
    return check if isinstance(check, dict) else {}


def audit_region(audit: dict[str, Any]) -> str:
    # Cloud region labels are the stable operational identity for Kubernetes
    # clusters. Human-readable ipinfo geolocation remains in audit_data.location
    # and supplies map coordinates.
    return str(
        first_known(
            nested_get(audit, "location", "cloudRegion"),
            nested_get(audit, "serverLocation", "cloudRegion"),
            nested_get(audit, "serverLocation", "region"),
            nested_get(audit, "location", "region"),
            nested_get(audit, "serverLocation", "country"),
            nested_get(audit, "location", "country"),
            default="unknown",
        )
    )


def audit_coordinates(audit: dict[str, Any]) -> tuple[float | None, float | None]:
    # ipinfo.io reports geolocation as "lat,lon" (e.g. "40.6097,-111.9391").
    # The standalone/slurm collectors store it under serverLocation.coordinates;
    # the k8s/legacy shape may use .loc. Parse into floats so the dashboard can
    # plot each cluster on a map; return (None, None) when missing or malformed
    # so the latitude/longitude columns stay NULL rather than carrying garbage.
    raw = first_known(
        nested_get(audit, "serverLocation", "coordinates"),
        nested_get(audit, "serverLocation", "loc"),
        nested_get(audit, "location", "coordinates"),
        nested_get(audit, "location", "loc"),
    )
    if not isinstance(raw, str) or "," not in raw:
        return None, None
    lat_str, _, lon_str = raw.partition(",")
    try:
        lat = float(lat_str.strip())
        lon = float(lon_str.strip())
    except ValueError:
        return None, None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None, None
    return lat, lon


def audit_driver_version(audit: dict[str, Any]) -> str:
    check = host_check(audit)
    return str(
        first_known(
            nested_get(audit, "gpus", "driverVersion"),
            check.get("WORKER_DRIVER_VERSION"),
            default="unknown",
        )
    )


def audit_cuda_version(audit: dict[str, Any]) -> str:
    check = host_check(audit)
    return str(
        first_known(
            nested_get(audit, "gpus", "cudaVersion"),
            check.get("WORKER_CUDA_VERSION"),
            default="unknown",
        )
    )


def audit_nccl_version(audit: dict[str, Any]) -> str:
    check = host_check(audit)
    return str(
        first_known(
            nested_get(audit, "software", "ncclVersion"),
            check.get("WORKER_NCCL_VERSION"),
            default="unknown",
        )
    )


def audit_gpu_direct_rdma(audit: dict[str, Any]) -> bool:
    gpus = audit.get("gpus")
    if isinstance(gpus, dict) and isinstance(gpus.get("gpuDirectRdma"), bool):
        return gpus["gpuDirectRdma"]
    check = host_check(audit)
    peermem = str(check.get("WORKER_PEERMEM", "")).lower()
    return peermem in {"true", "1", "yes"}


def audit_gpu_memory_mb(audit: dict[str, Any]) -> int:
    check = host_check(audit)
    return as_int(
        first_known(
            nested_get(audit, "gpus", "memoryMB"),
            check.get("WORKER_GPU_MEMORY"),
            default=0,
        )
    )


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "allowed", "on"}


def _boolean_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "allowed", "on", "pass"}:
        return True
    if normalized in {"false", "0", "no", "blocked", "off", "fail"}:
        return False
    return None


def _set_default(target: dict[str, Any], key: str, value: Any) -> None:
    """Set target[key] = value only when the key is currently absent.

    Keeps the remap additive: an existing richer value emitted by a collector is
    never overwritten, and a canonical field is only populated when the source
    fact exists.
    """
    if key not in target or target[key] is None:
        target[key] = value


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    child = parent.get(key)
    if not isinstance(child, dict):
        child = {}
        parent[key] = child
    return child


def remap_k8s_canonical(audit: dict[str, Any]) -> None:
    """Fold k8s host-check facts and k8s-native blocks onto the canonical
    audit_data.* paths the dashboard graders read.

    The k8s collector emits host facts under audit_data.hostCheck.WORKER_* and a
    few blocks (monitoring.*) in shapes the slurm-oriented graders do not read.
    This bridges them so graders stop returning "unknown" on k8s. Strictly
    additive and null-safe: a canonical field is only written when the source
    fact is present, and an existing value is never overwritten.
    """
    check = host_check(audit)

    # --- GPUDirect RDMA path (dma_buf / nvidia open / legacy peermem) ---
    gpus = _ensure_dict(audit, "gpus")
    rdma_path_present = any(
        k in check for k in ("WORKER_NVIDIA_DMABUF", "WORKER_NVIDIA_OPEN", "WORKER_PEERMEM_LEGACY")
    )
    if rdma_path_present:
        path = _ensure_dict(gpus, "gpuDirectRdmaPath")
        if "WORKER_NVIDIA_DMABUF" in check:
            _set_default(path, "dmaBuf", _truthy(check.get("WORKER_NVIDIA_DMABUF")))
        if "WORKER_NVIDIA_OPEN" in check:
            _set_default(path, "nvidiaOpen", _truthy(check.get("WORKER_NVIDIA_OPEN")))
        if "WORKER_PEERMEM_LEGACY" in check:
            _set_default(path, "nvidiaPeermemLegacy", _truthy(check.get("WORKER_PEERMEM_LEGACY")))

    # --- GDRCopy (library present + gdrdrv module) ---
    gdr_lib = check.get("WORKER_GDRCOPY_LIB")
    gdrdrv_loaded = (
        _truthy(check.get("WORKER_GDRCOPY_GDRDRV"))
        if "WORKER_GDRCOPY_GDRDRV" in check
        else None
    )
    if gdr_lib is not None or gdrdrv_loaded is not None:
        gdrcopy = _ensure_dict(gpus, "gdrcopy")
        lib_present = (
            gdr_lib is not None
            and str(gdr_lib).strip().lower() not in {"", "not-found", "none", "unknown"}
        )
        # The libgdrapi file lives in the node image; on k8s the check can run in
        # a container whose root lacks it even though gdrdrv is loaded on the
        # host. The gdrdrv kernel module is host-global (/proc/modules is not
        # namespaced), so it is the authoritative signal: treat GDRCopy as
        # installed if either the library is found OR gdrdrv is loaded.
        installed = bool(lib_present or gdrdrv_loaded)
        _set_default(gdrcopy, "installed", installed)
        if lib_present:
            _set_default(gdrcopy, "libraryPath", str(gdr_lib))
        if gdrdrv_loaded is not None:
            _set_default(gdrcopy, "gdrdrvLoaded", gdrdrv_loaded)

    # --- Idle thermals (max temp / power across sampled GPUs) ---
    if "WORKER_GPU_IDLE_TEMP_MAX" in check or "WORKER_GPU_IDLE_POWER_MAX" in check:
        thermals = _ensure_dict(gpus, "thermals")
        temp = check.get("WORKER_GPU_IDLE_TEMP_MAX")
        power = check.get("WORKER_GPU_IDLE_POWER_MAX")
        if temp is not None and str(temp).strip().lower() != "unknown":
            _set_default(thermals, "idleTempMax", temp)
        if power is not None and str(power).strip().lower() != "unknown":
            _set_default(thermals, "idlePowerMax", power)

    # --- dmesg Xid scan (count + last Xid) + AMD gpu error count ---
    # AMD-only hosts emit WORKER_DMESG_AMDGPU_ERRORS_COUNT without the NVIDIA Xid
    # keys, so it must be in the guard or amdgpuErrorsCount never lands.
    if (
        "WORKER_DMESG_XIDS_COUNT" in check
        or "WORKER_DMESG_XID_LAST" in check
        or "WORKER_DMESG_AMDGPU_ERRORS_COUNT" in check
    ):
        dmesg = _ensure_dict(gpus, "dmesgErrors")
        if "WORKER_DMESG_XIDS_COUNT" in check:
            _set_default(dmesg, "xidsCount", check.get("WORKER_DMESG_XIDS_COUNT"))
        if "WORKER_DMESG_XID_LAST" in check:
            _set_default(dmesg, "lastXid", check.get("WORKER_DMESG_XID_LAST"))
        if "WORKER_DMESG_AMDGPU_ERRORS_COUNT" in check:
            _set_default(dmesg, "amdgpuErrorsCount", check.get("WORKER_DMESG_AMDGPU_ERRORS_COUNT"))

    # --- CPU inventory: bridge hostCheck.WORKER_CPU_* -> computeNodeCpu so
    # the k8s runs land the same audit_data.computeNodeCpu block the slurm and
    # standalone collectors emit from build_audit_json().
    _CPU_KEY_MAP = (
        ("WORKER_CPU_MODEL", "model"),
        ("WORKER_CPU_SOCKETS", "sockets"),
        ("WORKER_CPU_CORES_PER_SOCKET", "coresPerSocket"),
        ("WORKER_CPU_THREADS", "threads"),
        ("WORKER_CPU_THREADS_PER_CORE", "threadsPerCore"),
        ("WORKER_CPU_BASE_MHZ", "baseMhz"),
        ("WORKER_CPU_MAX_MHZ", "maxMhz"),
        ("WORKER_CPU_CUR_MHZ", "curMhz"),
        ("WORKER_CPU_GOVERNOR", "governors"),
        ("WORKER_CPU_RAPL_PACKAGES", "raplPackages"),
        ("WORKER_CPU_PACKAGE_POWER_LIMIT_W", "packagePowerLimitW"),
    )
    if any(check_key in check for check_key, _ in _CPU_KEY_MAP):
        cpu = _ensure_dict(audit, "computeNodeCpu")
        for check_key, canonical_key in _CPU_KEY_MAP:
            if check_key in check:
                _set_default(cpu, canonical_key, str(check.get(check_key)))
        _set_default(cpu, "source", "host-check")

    # --- Memory inventory: bridge hostCheck.WORKER_MEM_* -> computeNodeMemory
    # so the k8s runs land the same audit_data.computeNodeMemory block the
    # slurm and standalone collectors emit from build_audit_json().
    _MEM_KEY_MAP = (
        ("WORKER_MEM_DIMMS", "populatedDimms"),
        ("WORKER_MEM_DIMM_SIZES_GB", "dimmSizesGB"),
        ("WORKER_MEM_TYPES", "types"),
        ("WORKER_MEM_RATED_SPEED_MTS", "ratedSpeedMts"),
        ("WORKER_MEM_CONFIGURED_SPEED_MTS", "configuredSpeedMts"),
        ("WORKER_MEM_BW_PER_SOCKET_GBS", "effectiveBandwidthPerSocketGBs"),
        ("WORKER_MEM_BW_PER_CORE_GBS", "effectiveBandwidthPerCoreGBs"),
    )
    if any(check_key in check for check_key, _ in _MEM_KEY_MAP):
        memory = _ensure_dict(audit, "computeNodeMemory")
        for check_key, canonical_key in _MEM_KEY_MAP:
            if check_key in check:
                _set_default(memory, canonical_key, str(check.get(check_key)))
        _set_default(
            memory, "source", str(check.get("WORKER_MEM_SOURCE", "unknown"))
        )

    # --- BMC / IPMI exposure (mirror the slurm security.bmcIpmi fold) ---
    user_access = check.get("WORKER_IPMI_USER_ACCESS")
    sudo_access = check.get("WORKER_IPMI_SUDO_ACCESS")
    ipmitool_path = check.get("WORKER_IPMITOOL_PATH")
    if user_access is not None or sudo_access is not None or ipmitool_path is not None:
        security = _ensure_dict(audit, "security")
        bmc = _ensure_dict(security, "bmcIpmi")
        if ipmitool_path is not None:
            installed = str(ipmitool_path).strip() not in {"", "none", "not-found"}
            _set_default(bmc, "ipmitoolInstalled", installed)
            _set_default(bmc, "ipmitoolPath", str(ipmitool_path) if installed else "none")
        if user_access is not None:
            _set_default(bmc, "userAccess", str(user_access))
        if sudo_access is not None:
            _set_default(bmc, "sudoAccess", str(sudo_access))
        exposed = _truthy(user_access) or _truthy(sudo_access)
        _set_default(bmc, "exposed", exposed)

    # --- Monitoring stack: bridge monitoring.* -> healthChecks.monitoringStack.*
    # so the existing monitoring-stack grader resolves on k8s, and surface DCGM +
    # node-problem-detector alongside Prometheus/Grafana/node-exporter.
    monitoring = audit.get("monitoring")
    if isinstance(monitoring, dict):
        health = _ensure_dict(audit, "healthChecks")
        stack = _ensure_dict(health, "monitoringStack")
        prom = monitoring.get("prometheus")
        graf = monitoring.get("grafana")
        dcgm = monitoring.get("dcgm")
        gme = monitoring.get("gpuMetricsExporter")
        comps = monitoring.get("components")
        if isinstance(prom, dict) and "installed" in prom:
            _set_default(stack, "prometheus", _truthy(prom.get("installed")))
        if isinstance(graf, dict) and "installed" in graf:
            _set_default(stack, "grafana", _truthy(graf.get("installed")))
        if isinstance(dcgm, dict) and "installed" in dcgm:
            _set_default(stack, "dcgmExporter", _truthy(dcgm.get("installed")))
        # Vendor-neutral GPU-metrics exporter: NVIDIA dcgm-exporter OR AMD
        # device-metrics-exporter. Lets the monitoring-stack grader credit AMD
        # clusters that have no DCGM but full GPU telemetry via the AMD exporter.
        amd_exp = None
        if isinstance(gme, dict):
            if "installed" in gme:
                _set_default(stack, "gpuMetricsExporter", _truthy(gme.get("installed")))
            if gme.get("vendor"):
                _set_default(stack, "gpuMetricsVendor", gme.get("vendor"))
            if "jobAttribution" in gme:
                _set_default(stack, "gpuMetricsJobAttribution", _truthy(gme.get("jobAttribution")))
            if gme.get("jobAttributionMethod"):
                _set_default(stack, "gpuMetricsJobAttributionMethod", gme.get("jobAttributionMethod"))
            if "amdDeviceMetricsExporter" in gme:
                amd_exp = gme.get("amdDeviceMetricsExporter")
        if isinstance(comps, dict):
            if "nodeExporter" in comps:
                _set_default(stack, "nodeExporter", _truthy(comps.get("nodeExporter")))
            if amd_exp is None and "amdDeviceMetricsExporter" in comps:
                amd_exp = comps.get("amdDeviceMetricsExporter")
            if "nodeProblemDetector" in comps:
                _set_default(stack, "nodeProblemDetector", _truthy(comps.get("nodeProblemDetector")))
        if amd_exp is not None:
            _set_default(stack, "amdDeviceMetricsExporter", _truthy(amd_exp))


def remap_criteria_checks(audit: dict[str, Any], harness: str) -> None:
    """Normalize binary public-criteria evidence across all audit harnesses."""
    check = host_check(audit)
    software = _ensure_dict(audit, "software")
    lmod = _ensure_dict(software, "lmod")
    if "installed" not in lmod and "WORKER_LMOD_PATH" in check:
        lmod["installed"] = bool(str(check.get("WORKER_LMOD_PATH") or "").strip())
    module_inventory = audit.get("lmod")
    module_values = (
        tuple(module_inventory.get(key) for key in ("hasCudaModule", "hasHpcxModule", "hasNcclModule"))
        if isinstance(module_inventory, dict)
        else ()
    )
    if harness == "slurm":
        if _truthy(lmod.get("installed")) and any(_truthy(value) for value in module_values):
            lmod["modulesStatus"] = "pass"
        elif lmod.get("installed") is False or module_values:
            lmod["modulesStatus"] = "fail"
        else:
            lmod["modulesStatus"] = "unknown"
    else:
        lmod["modulesStatus"] = "not_applicable"

    storage = _ensure_dict(audit, "storage")
    if harness == "k8s":
        storage_ready = _boolean_value(storage.get("storageReady"))
        rwx_capable = _boolean_value(storage.get("rwxCapable"))
        if storage_ready is True and rwx_capable is True:
            storage["rwxStatus"] = "pass"
        elif storage_ready is False or rwx_capable is False:
            storage["rwxStatus"] = "fail"
        else:
            storage["rwxStatus"] = "unknown"
    else:
        storage["rwxStatus"] = "not_applicable"

    cuda_visible = check.get("WORKER_CUDA_VISIBLE_DEVICES")
    if cuda_visible is not None:
        _set_default(software, "cudaVisibleDevices", str(cuda_visible))
    nvidia_visible = check.get("WORKER_NVIDIA_VISIBLE_DEVICES")
    if nvidia_visible is not None:
        _set_default(software, "nvidiaVisibleDevices", str(nvidia_visible))
    if harness in {"slurm", "k8s"}:
        if "cudaVisibleDevices" not in software and "nvidiaVisibleDevices" not in software:
            software["cudaVisibleDevicesStatus"] = "unknown"
        else:
            visible = (
                str(software.get("cudaVisibleDevices") or "unset").strip().lower(),
                str(software.get("nvidiaVisibleDevices") or "unset").strip().lower(),
            )
            unknown = {"", "unknown"}
            unassigned = {"unset", "-1", "void", "none"}
            if all(value in unknown for value in visible):
                software["cudaVisibleDevicesStatus"] = "unknown"
            elif any(value not in unknown | unassigned for value in visible):
                software["cudaVisibleDevicesStatus"] = "pass"
            else:
                software["cudaVisibleDevicesStatus"] = "fail"
    else:
        software["cudaVisibleDevicesStatus"] = "not_applicable"


def refine_rdma_fabric_from_topology(audit: dict[str, Any], nic_topology: dict[str, Any]) -> None:
    """Disambiguate a generic "rdma" fabric using the NIC link layer.

    Shared-device-plugin clusters (e.g. Moonlite Spectrum-X via
    rdma/rdma_shared_device) classify only as a generic "rdma" because the k8s
    resource name does not reveal IB vs RoCE — which leaves the UFM
    "Secured Bare Metal Cloud" profile graded "unknown". nic_topology (collected
    after the main audit) records each NIC's link layer, so once it is available
    we can settle the fabric: Ethernet -> RoCE (UFM not applicable), InfiniBand
    -> IB (UFM manual review applies). Only refines the ambiguous "rdma" case.
    """
    networking = audit.get("networking")
    if not isinstance(networking, dict) or networking.get("rdmaType") != "rdma":
        return
    layers = {
        str(nic.get("layer", "")).lower()
        for nics in nic_topology.values() if isinstance(nics, list)
        for nic in nics if isinstance(nic, dict) and nic.get("role") == "fabric"
    }
    if not layers:  # fall back to all NICs if none were tagged "fabric"
        layers = {
            str(nic.get("layer", "")).lower()
            for nics in nic_topology.values() if isinstance(nics, list)
            for nic in nics if isinstance(nic, dict)
        }
    if "infiniband" in layers:
        networking["rdmaType"] = "infiniband"
        status, applicable = "manual", True
    elif "ethernet" in layers:
        networking["rdmaType"] = "roce"
        status, applicable = "not_applicable", False
    else:
        return  # link layer unknown; leave as generic "rdma"
    security = audit.get("security")
    if isinstance(security, dict) and isinstance(security.get("ufmSecuredBareMetalCloud"), dict):
        security["ufmSecuredBareMetalCloud"]["status"] = status
        security["ufmSecuredBareMetalCloud"]["applicable"] = applicable


def build_values(
    audit: dict[str, Any],
    *,
    harness: str,
    check_data: dict[str, Any],
    environment: str | None = None,
) -> dict[str, Any]:
    audit.update(check_data)
    nic_topology = check_data.get("nic_topology")
    if not isinstance(nic_topology, dict):
        nic_topology = {}
    audit["nic_topology"] = nic_topology
    refine_rdma_fabric_from_topology(audit, nic_topology)

    if harness == "k8s":
        remap_k8s_canonical(audit)

    remap_criteria_checks(audit, harness)

    primary_profile = nested_get(audit, "gpus", "primaryProfile", default={})
    if not isinstance(primary_profile, dict):
        primary_profile = {}
    total_gpus = as_int(nested_get(audit, "gpus", "total"))
    inventory_nodes = as_int(nested_get(audit, "nodes", "total"), default=1)
    gpu_nodes = as_int(
        first_known(primary_profile.get("nodeCount"), nested_get(audit, "gpus", "nodeCount"), default=0)
    )
    cluster_nodes = gpu_nodes if gpu_nodes > 0 else inventory_nodes
    # Prefer the audited per-node GPU count (from node labels/capacity). Dividing
    # total GPUs by the full node count under-reports on clusters with mixed
    # GPU/CPU node pools, so only use that as a fallback.
    per_node = as_int(
        first_known(primary_profile.get("perNode"), nested_get(audit, "gpus", "perNode"), default=0)
    )
    if per_node > 0:
        gpus_per_node = per_node
    elif cluster_nodes > 0:
        gpus_per_node = total_gpus // cluster_nodes
    else:
        gpus_per_node = 0
    if gpu_nodes > 0:
        total_cpus = as_int(
            first_known(primary_profile.get("totalCpus"), nested_get(audit, "gpus", "totalCpus"), default=0)
        )
        total_memory_gb = as_int(
            first_known(
                primary_profile.get("totalMemoryGB"),
                nested_get(audit, "gpus", "totalMemoryGB"),
                default=0,
            )
        )
    else:
        total_cpus = as_int(nested_get(audit, "nodes", "totalCpus"))
        total_memory_gb = as_int(nested_get(audit, "nodes", "totalMemoryGB"))
    # The Kubernetes collector historically emitted per-worker sample
    # quantities instead of canonical totals. Use them only as a fallback so
    # newer collectors and SLURM inventory remain authoritative.
    if total_cpus <= 0:
        total_cpus = as_int(nested_get(audit, "nodes", "sampleCpu")) * cluster_nodes
    if total_memory_gb <= 0:
        sample_memory_gib = kubernetes_memory_gib(
            nested_get(audit, "nodes", "sampleMemory")
        )
        total_memory_gb = int(sample_memory_gib * cluster_nodes)

    cluster: dict[str, Any] = {
        # Record the bare accelerator name (B300, GB300, H100, MI300X, ...).
        # The raw nvidia-smi / label string stays under audit_data.gpus.model.
        "gpu_model": normalize_chip_name(
            first_known(primary_profile.get("model"), nested_get(audit, "gpus", "model"), default="unknown")
        ),
        "nodes": cluster_nodes,
        "gpus_per_node": gpus_per_node,
        "gpu_memory_mb": as_int(
            first_known(primary_profile.get("memoryMB"), audit_gpu_memory_mb(audit), default=0)
        ),
        "total_cpus": total_cpus,
        "total_memory_gb": total_memory_gb,
        "driver_version": audit_driver_version(audit),
        "cuda_version": audit_cuda_version(audit),
        "nccl_version": audit_nccl_version(audit),
        "gpu_direct_rdma": audit_gpu_direct_rdma(audit),
        "orchestrator": harness,
        "region": audit_region(audit),
        "audited_at": nested_get(audit, "audit", "timestamp", default=""),
    }

    slurm_version = first_known(nested_get(audit, "slurm", "version"))
    if slurm_version is not None:
        cluster["slurm_version"] = str(slurm_version)
    if environment:
        cluster["environment"] = environment

    latitude, longitude = audit_coordinates(audit)
    if latitude is not None and longitude is not None:
        cluster["latitude"] = latitude
        cluster["longitude"] = longitude

    return {
        "schema_version": 1,
        "runner": "audit",
        "cluster": cluster,
        "audit_data": audit,
    }


def print_summary(out_path: Path, values: dict[str, Any], nic_topology: dict[str, list[dict[str, Any]]]) -> None:
    cluster = values["cluster"]
    audit = values["audit_data"]
    print(f"Wrote {out_path}")
    print(f"  gpu_model     = {cluster['gpu_model']}")
    print(f"  nodes         = {cluster['nodes']} x {cluster['gpus_per_node']} gpus")
    print(f"  total_cpus    = {cluster['total_cpus']}")
    print(f"  total_mem_gb  = {cluster['total_memory_gb']}")
    print(f"  driver        = {cluster['driver_version']}")
    print(f"  cuda          = {cluster['cuda_version']}")
    if "slurm_version" in cluster:
        print(f"  slurm         = {cluster['slurm_version']}")
    print(f"  nccl          = {cluster['nccl_version']}")
    print(f"  region        = {cluster['region']}")
    print(f"  orchestrator  = {cluster['orchestrator']}")
    print(f"  audit_data    = {len(json.dumps(audit))} bytes (full nested blob)")
    gpu_controls = audit.get("gpu_controls") if isinstance(audit, dict) else None
    vboost = gpu_controls.get("vboost") if isinstance(gpu_controls, dict) else None
    if isinstance(vboost, dict):
        print(
            "  vboost       = "
            f"{vboost.get('status', 'unknown')} "
            f"({vboost.get('allowed_nodes', 0)}/{vboost.get('checked_nodes', 0)} node(s) allowed, "
            f"target={vboost.get('target', 'unknown')})"
        )
    if nic_topology:
        total_nics = sum(len(nics) for nics in nic_topology.values())
        by_role: dict[str, int] = {}
        for nics in nic_topology.values():
            for nic in nics:
                by_role[nic["role"]] = by_role.get(nic["role"], 0) + 1
        print(f"  nic_topology  = {len(nic_topology)} node(s), {total_nics} NIC(s) total: {by_role}")


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(
            "usage: merge_audit.py <audit.json> <audit.values.json> <slug> <harness> <check-data.json>",
            file=sys.stderr,
        )
        return 2

    audit_path = Path(argv[1])
    out_path = Path(argv[2])
    _slug = argv[3]
    harness = argv[4]
    check_data_path = argv[5]

    with audit_path.open() as f:
        audit = json.load(f)

    check_data = load_check_data(check_data_path)
    values = build_values(
        audit,
        harness=harness,
        check_data=check_data,
        environment=os.environ.get("CLUSTERMAX_AUDIT_ENVIRONMENT"),
    )

    with out_path.open("w") as f:
        json.dump(values, f, indent=2)

    print_summary(out_path, values, values["audit_data"].get("nic_topology") or {})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
