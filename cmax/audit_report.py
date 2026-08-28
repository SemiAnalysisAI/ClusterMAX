#!/usr/bin/env python3
"""Render the full cluster audit as a concise terminal report."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cmax import criteria_links, minimum_links, report_style, runtime_paths
from cmax.audit_profiles import (
    AUDIT_CATEGORIES,
    AUDIT_PROFILE_NAMES,
    category_for_key,
    profile_includes,
)

PASS = "pass"
WARNING = "warning"
FAIL = "fail"
SKIPPED = "skipped"
_STATUS_ORDER = {PASS: 0, SKIPPED: 1, WARNING: 2, FAIL: 3}
_SECURITY_EXTENSION_IDS = frozenset(
    {"bmc-ipmi", "ufm-profile", "pcie-passthrough", "nvlink-boundary"}
)
_SECURITY_EXTENSION_HARNESSES = {
    "ufm-profile": frozenset({"slurm", "k8s"}),
}


def _criteria_reference(key: str) -> tuple[str, str] | None:
    """Return the public criteria permalink for one report check."""
    url = criteria_links.audit_check_url(key)
    return (criteria_links.REFERENCE_LABEL, url) if url else None


def _with_criteria_reference(
    key: str, references: tuple[tuple[str, str], ...] = ()
) -> tuple[tuple[str, str], ...]:
    """Append and deduplicate a check's public criteria permalink."""
    criteria = _criteria_reference(key)
    if criteria is None:
        return references
    return tuple(dict.fromkeys((*references, criteria)))


def _harness_not_applicable(harness: str) -> str:
    """Describe a check excluded from the selected machine type."""
    return f"n/a for {harness} machines"


_PASS_ASSESSMENTS = {
    "securityVersions.nvidiaDriver.status": (
        "The NVIDIA driver meets the published security minimum."
    ),
    "securityVersions.nvidiaContainerToolkit.status": (
        "The NVIDIA Container Toolkit meets the published security minimum."
    ),
    "securityVersions.cudaToolkit.status": (
        "The CUDA Toolkit meets the published security minimum."
    ),
    "securityVersions.runc.status": (
        "The runc version meets the published security minimum."
    ),
    "securityVersions.docker.status": (
        "The Docker Engine version meets the published security minimum."
    ),
    "securityVersions.connectxFirmware.status": (
        "The ConnectX firmware meets the published security minimum."
    ),
    "securityVersions.dcgm.status": (
        "The DCGM version meets the published security minimum."
    ),
    "securityVersions.dcgmExporter.status": (
        "The DCGM Exporter version meets the published security minimum."
    ),
    "securityVersions.virtioNetBluefield.status": (
        "The BlueField VIRTIO-Net controller meets the published security minimum."
    ),
    "securityVersions.dpuHostIsolation.status": (
        "The host cannot reach the BlueField DPU control plane through the checked interfaces."
    ),
    "security.guestKernel.newerInstalled": (
        "The audit did not find a newer installed kernel that is waiting for a reboot."
    ),
    "security.fragnesia.status": (
        "The running kernel does not match the affected Fragnesia or Dirty Frag ranges."
    ),
    "containers.nvidiaContainerToolkit": (
        "The worker has NVIDIA Container Toolkit support."
    ),
    "containers.workerCheckOk": (
        "The worker container check completed, so its runtime observations are valid."
    ),
    "containers.pyxisRuntimeWorks": (
        "The Slurm command-line interface exposes the Pyxis container options."
    ),
    "containers.enroot": "Enroot is installed on the worker.",
    "containers.enrootImportWorks": "Enroot can import container images.",
    "containers.dockerOnWorkers": "Docker is installed on the worker nodes.",
    "containers.singularity": "Singularity or Apptainer is installed on the worker.",
    "software.nccl.installed": "NCCL is installed.",
    "software.perf.installed": "perf (Linux performance counters) is installed.",
    "software.perf.perfEventParanoid": (
        "perf_event_paranoid permits unprivileged perf profiling."
    ),
    "software.perf.kptrRestrict": "Kernel symbols are visible to perf.",
    "gpus.pcieAcs.enabled": (
        "PCIe ACS is disabled on the GPU-NIC path, so peer-to-peer traffic is not redirected."
    ),
    "networking.ncclAutoConfig": (
        "NCCL relies on auto-configuration without an overriding /etc/nccl.conf."
    ),
    "healthChecks.dcgmInstalled": "DCGM is installed.",
    "healthChecks.dcgmSlurm": (
        "DCGM health checks are wired into the Slurm HealthCheckProgram."
    ),
    "access.sudoAvailable": "Passwordless sudo is available to the audited user.",
    "access.userManagement": (
        "User and group management commands (useradd / groupadd) are usable."
    ),
    "access.sshToComputeNodes": (
        "Compute nodes are reachable over passwordless SSH."
    ),
    "access.externalIdp.detected": (
        "An external identity provider integration was detected."
    ),
    "access.slurmCommandsOk": (
        "Core Slurm commands (sinfo / squeue / scontrol / sbatch / srun) are functional."
    ),
    "slurm.accounting.sacctAvailable": "Slurm job accounting (sacct) is available.",
    "software.nvhpc.status": (
        "The NVIDIA HPC SDK release is supported and its compiler, communication, "
        "math, and profiling payload is complete."
    ),
    "software.ncu.installed": "NVIDIA Nsight Compute is installed.",
    "software.ncu.profilingEnabled": (
        "NVIDIA Nsight Compute profiling is enabled for the audited user."
    ),
    "software.lmod.modulesStatus": (
        "The Slurm environment provides GPU or fabric software through Lmod."
    ),
    "software.cudaVisibleDevicesStatus": (
        "The scheduler assigned CUDA devices to the audited worker environment."
    ),
    "gpus.gdrcopy.installed": "GDRCopy is installed.",
    "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy": (
        "The deprecated nvidia_peermem path is not in use."
    ),
    "gpu_controls.vboost.allowed": (
        "The audit confirmed that the operator can use the GPU vBoost control."
    ),
    "hbm_memory_exposure.status": (
        "GPU HBM is not exposed as ordinary memory that the operating system manages."
    ),
    "kubelet_cpu_manager_policy.status": (
        "Kubelet uses the static CPU Manager policy for GPU workload isolation."
    ),
    "vm_iommu.status": (
        "GPU and RDMA devices use the expected IOMMU passthrough configuration."
    ),
    "arm_smmu_virtualization.status": (
        "The Arm virtual machine exposes the required virtualization for the SMMU command queue."
    ),
    "nccl_topo_file.status": (
        "The host NCCL topology file is available inside the benchmark container."
    ),
    "nccl_ib_qps.status": (
        "The NCCL InfiniBand queue-pair setting is suitable for the detected fabric."
    ),
    "networking.topologyConfigured": (
        "The scheduler has a topology configuration."
    ),
    "networking.hcaNamingValid": (
        "The HCA and NIC device names use the expected naming convention."
    ),
    "storage.rwxStatus": (
        "The Kubernetes cluster has working storage and ReadWriteMany capability."
    ),
    "healthChecks.nhcInstalled": "Node Health Check is installed.",
    "healthChecks.monitoringStack.dcgmExporter": "DCGM Exporter is installed.",
}


@dataclass(frozen=True)
class AuditCheck:
    key: str
    title: str
    category: str
    status: str
    observed: Any
    assessment: str = ""
    recommendation: str = ""
    references: tuple[tuple[str, str], ...] = ()
    reproduce: str = ""


@dataclass(frozen=True)
class AuditCheckSpec:
    key: str
    title: str
    category: str


def _load_findings(repo_root: Path):
    path = repo_root / runtime_paths.AUDIT_FINDINGS_RELATIVE
    spec = importlib.util.spec_from_file_location("cmax_audit_findings", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load audit findings from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _title(key: str) -> str:
    if key == "containers.pyxisRuntimeWorks":
        return "Containers / Pyxis CLI Available"
    parts = key.split(".")
    if parts[-1] in {"status", "allowed", "configured", "installed"}:
        parts.pop()
    words = []
    for part in parts:
        words.append(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", part).replace("_", " "))
    title = " / ".join(
        " ".join(token[:1].upper() + token[1:] for token in word.split())
        for word in words
    )
    for source, replacement in {
        "Hbm": "HBM",
        "Nvidia": "NVIDIA",
        "Nvcc": "NVCC",
        "Ncu": "NCU",
        "Nvhpc": "NVHPC",
        "Gdrcopy": "GDRCopy",
        "Gpus": "GPUs",
        "Gpu": "GPU",
        "Rdma": "RDMA",
        "Hca": "HCA",
        "Dpu": "DPU",
        "Dcgm": "DCGM",
        "Smmu": "SMMU",
        "Iommu": "IOMMU",
        "Nccl": "NCCL",
        "Cpu": "CPU",
        "Cve": "CVE",
        "Qemu": "QEMU",
        "Cuda": "CUDA",
        "Rwx": "RWX",
        "Vmscape": "VMSCAPE",
        "Vboost": "vBoost",
        "Bmc": "BMC",
        "Ipmi": "IPMI",
        "Check": "Check",
    }.items():
        title = re.sub(rf"\b{source}\b", replacement, title, flags=re.IGNORECASE)
    title = re.sub(r"\bCve(?=\d)", "CVE", title, flags=re.IGNORECASE)
    return title


_VERSION_SOURCE_KEYS: dict[str, str] = {
    "software.nvhpc.status": "software.nvhpc",
}

_REPRODUCTION_COMMANDS = {
    "securityVersions.nvidiaDriver.status": (
        "on the audited worker: `nvidia-smi --query-gpu=driver_version "
        "--format=csv,noheader`"
    ),
    "securityVersions.nvidiaContainerToolkit.status": (
        "on the audited worker: `nvidia-container-toolkit --version` or "
        "`nvidia-ctk --version`"
    ),
    "securityVersions.cudaToolkit.status": (
        "on the audited worker: `nvcc --version` (installed toolkit); "
        "`nvidia-smi` (driver CUDA compatibility only)"
    ),
    "securityVersions.docker.status": (
        "on the audited worker: `docker version --format '{{.Server.Version}}'`"
    ),
    "securityVersions.runc.status": "on the audited worker: `runc --version`",
    "securityVersions.dcgm.status": "on the audited worker: `dcgmi --version`",
    "security.fragnesia.status": "on the audited worker: `uname -r`",
    "software.nvhpc.status": (
        "on the audited worker: run `nvc --version`, `nvc++ --version`, and "
        "`nvfortran --version`; inspect the selected SDK release tree for NCCL, "
        "HPC-X, NVSHMEM, CUDA math libraries, and profiling tools"
    ),
    "securityVersions.connectxFirmware.status": (
        "on every GPU worker: `for device in /sys/class/infiniband/*; do "
        "printf '%s ' \"$(basename \"$device\")\"; cat \"$device/fw_ver\"; done`"
    ),
    "securityVersions.dcgmExporter.status": (
        "from the Kubernetes control plane: `kubectl get pods -A -o "
        "custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,"
        "IMAGES:.spec.containers[*].image' | grep -i dcgm-exporter`"
    ),
    "securityVersions.dpuHostIsolation.status": (
        "on every BlueField GPU worker: read `INTERNAL_CPU_RSHIM` with "
        "`sudo -n mlxconfig -d <PCI-address> q`, inspect `/dev/rshim*`, and "
        "run `ip link show tmfifo_net0`"
    ),
    "securityVersions.virtioNetBluefield.exposure": (
        "on every GPU worker: identify BlueField PCI devices with `lspci -Dn`, "
        "read each mode with `sudo -n mlxconfig -d <PCI-address> q`, and run "
        "`virtnet version` on each DPU to read its running controller version"
    ),
    "securityVersions.virtioNetBluefield.status": (
        "on every GPU worker: identify BlueField PCI devices with `lspci -Dn`, "
        "read each mode with `sudo -n mlxconfig -d <PCI-address> q`, and run "
        "`virtnet version` on each DPU to read its running controller version"
    ),
    "gpus.gdrcopy.installed": (
        "on every GPU worker: `ldconfig -p | grep libgdrapi`; then run "
        "`lsmod | grep '^gdrdrv'` and `test -c /dev/gdrdrv`"
    ),
    "kubelet_cpu_manager_policy.status": (
        "on every GPU worker: `sudo jq -r .policyName "
        "/var/lib/kubelet/cpu_manager_state`"
    ),
    "networking.topologyConfigured": (
        "from the Kubernetes control plane: inspect `kubectl get nodes "
        "--show-labels` and run `kubectl api-resources | grep -Ei "
        "'topologies|hypernodes|jobsets'`"
    ),
    "software.cudaVisibleDevicesStatus": (
        "in a standard CUDA pod with one GPU: `printf '%s\\n' "
        "\"$CUDA_VISIBLE_DEVICES\" \"$NVIDIA_VISIBLE_DEVICES\"; nvidia-smi`"
    ),
    "software.ncu.profilingEnabled": (
        "in a CUDA development pod with one GPU: run `ncu --query-metrics`, "
        "then profile a minimal CUDA kernel"
    ),
    "software.perf.perfEventParanoid": (
        "on the audited worker: `sysctl kernel.perf_event_paranoid`"
    ),
    "software.perf.kptrRestrict": (
        "on the audited worker: `sysctl kernel.kptr_restrict`"
    ),
    "ufm-profile": (
        "provider-side verification: export the UFM security configuration and "
        "verify randomized management keys and rate limits for the tenant fabric"
    ),
    "nvlink-boundary": (
        "on every GPU host (or in the NVIDIA driver pod on Kubernetes): run "
        "`nvidia-smi topo -m`; then have the provider map the complete physical "
        "NVLink or NVSwitch domain and its partition to tenant ownership; once "
        "verified, rerun with `CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED=true`"
    ),
    "pcie-passthrough": (
        "on the physical host: inspect `find /sys/kernel/iommu_groups -type l` "
        "and `lspci -vv`; then verify reset isolation and VRAM clearing with "
        "provider host evidence"
    ),
}

_UNVERIFIED_RECOMMENDATIONS = {
    "securityVersions.virtioNetBluefield.exposure": (
        "Complete the BlueField inventory on every GPU host. For each BlueField "
        "device, record whether it uses NIC or DPU mode and record the controller "
        "firmware version."
    ),
    "software.cudaVisibleDevicesStatus": (
        "Make one GPU available on a worker, then run the check again so a "
        "standard CUDA pod can verify the injected visibility variables and "
        "nvidia-smi access."
    ),
    "software.ncu.profilingEnabled": (
        "Make one GPU available on a worker, then run the check again with a "
        "CUDA development image that contains Nsight Compute."
    ),
}

_CONTEXT_OBSERVATION_KEYS = frozenset(
    {
        "containers.workerCheckOk",
        "containers.nvidiaContainerToolkit",
        "containers.pyxisRuntimeWorks",
        "gpu_controls.vboost.allowed",
        "networking.hcaNamingValid",
        "security.januscape.status",
    }
)

def _nested(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _unverified_recommendation(audit: dict[str, Any], key: str) -> str:
    """Return guidance that distinguishes missing inventory from unread evidence."""
    if key != "securityVersions.virtioNetBluefield.exposure":
        return _UNVERIFIED_RECOMMENDATIONS.get(key, "")

    isolation = _nested(audit, "securityVersions.dpuHostIsolation")
    controller = _nested(audit, "securityVersions.virtioNetBluefield")
    presence = isolation.get("bluefieldPresent") if isinstance(isolation, dict) else None
    bluefield_present = presence is True or str(presence).strip().lower() in {
        "true",
        "1",
        "yes",
    }
    mode = controller.get("platformMode") if isinstance(controller, dict) else None
    bluefield_present = bluefield_present or str(mode).strip().lower() in {"nic", "dpu"}
    graded_version = (
        controller.get("gradedVersion") if isinstance(controller, dict) else None
    )
    bluefield_present = bluefield_present or str(graded_version).strip().lower() not in {
        "",
        "none",
        "not-found",
        "unknown",
        "n/a",
    }
    if bluefield_present:
        return (
            "Attest the controller version and exposure for every detected "
            "BlueField device. Record the running controller version with "
            "virtnet version and verify its tenant exposure."
        )
    return _UNVERIFIED_RECOMMENDATIONS[key]


def _version_observation(audit: dict[str, Any], key: str, value: Any) -> Any:
    """Show the evidence that lets an operator interpret each check."""
    if key == "containers.pyxisRuntimeWorks":
        version = _nested(audit, "containers.pyxisVersion") or "unknown"
        return f"CLI available {str(value).lower()}; installed version {version}"
    if key == "containers.workerCheckOk":
        worker = _nested(audit, "containers.workerNode") or "unknown"
        return f"check completed={str(value).lower()}; worker node={worker}"
    if key == "containers.nvidiaContainerToolkit":
        installed = f"installed={str(value).lower()}"
        if value is not True and str(value).strip().lower() != "true":
            # A version on a not-installed observation is noise: there is no
            # package the version could describe, and the collector's
            # placeholder rendered as a literal "version=unknown" beside the
            # finding that already says the toolkit is missing.
            return installed
        version = _nested(audit, "containers.nvidiaContainerToolkitVersion")
        return f"{installed}; version={version if version is not None else 'unknown'}"
    if key == "gpu_controls.vboost.allowed":
        vboost = _nested(audit, "gpu_controls.vboost")
        if isinstance(vboost, dict):
            allowed = vboost.get("allowed_nodes", "unknown")
            checked = vboost.get("checked_nodes", "unknown")
            return (
                f"allowed={str(value).lower()}; "
                f"status={vboost.get('status', 'unknown')}; "
                f"mode={vboost.get('mode', 'unknown')}; "
                f"allowed nodes={allowed}/{checked}"
            )
    if key == "networking.hcaNamingValid":
        devices = _nested(audit, "networking.hcaDevices")
        names: list[str] = []
        if isinstance(devices, list):
            for device in devices:
                if isinstance(device, dict):
                    name = device.get("name") or device.get("device") or "unknown"
                    names.append(str(name))
                else:
                    names.append(str(device))
        return (
            f"valid={str(value).lower()}; "
            f"devices={', '.join(names) if names else 'none reported'}"
        )
    if key == "security.januscape.status":
        januscape = _nested(audit, "security.januscape")
        if isinstance(januscape, dict):
            def display(field: str) -> str:
                observed = januscape.get(field, "unknown")
                if isinstance(observed, bool):
                    return str(observed).lower()
                return str(observed)

            return "; ".join(
                f"{label}={display(field)}"
                for label, field in (
                    ("CPU virtualization exposed", "cpuVirtualizationExposed"),
                    ("KVM device exposed", "kvmDeviceExposed"),
                    ("nested virtualization enabled", "nestedEnabled"),
                    ("status", "status"),
                )
            )
    if key == "security.guestKernel.newerInstalled":
        kernel = _nested(audit, "security.guestKernel")
        if isinstance(kernel, dict):
            return (
                f"observed version {kernel.get('running', 'unknown')}; "
                "minimum version not applicable; newest installed version "
                f"{kernel.get('newestInstalled', 'unknown')}"
            )
    if key == "security.fragnesia.status":
        fragnesia = _nested(audit, "security.fragnesia")
        kernel = _nested(audit, "security.guestKernel")
        if isinstance(fragnesia, dict):
            running = (
                kernel.get("running", "unknown")
                if isinstance(kernel, dict)
                else "unknown"
            )
            return (
                f"observed version {running}; minimum version "
                f"{fragnesia.get('ubuntuNoblePackageMinimum', 'unknown')}"
            )
    if key == "software.nvhpc.status":
        nvhpc = _nested(audit, "software.nvhpc")
        if isinstance(nvhpc, dict):
            compilers = nvhpc.get("compilers") or {}
            components = nvhpc.get("components") or {}
            compiler_versions = ", ".join(
                f"{label}={compilers.get(field, 'unknown')}"
                for label, field in (
                    ("nvc", "nvc"),
                    ("nvc++", "nvcxx"),
                    ("nvfortran", "nvfortran"),
                )
            )
            observation = (
                f"observed version {nvhpc.get('version', 'unknown')}; minimum version "
                f"{nvhpc.get('minimum', 'unknown')}; current version "
                f"{nvhpc.get('current', 'unknown')}; compilers {compiler_versions}"
            )
            missing = components.get("missing")
            if missing and str(missing).lower() not in {"none", "not-checked"}:
                observation += f"; missing components {missing}"
            return observation

    source_path = _VERSION_SOURCE_KEYS.get(key)
    if source_path is None and key.startswith("securityVersions.") and key.endswith(
        ".status"
    ):
        source_path = key.rsplit(".", 1)[0]
    if source_path is None:
        return value

    source = _nested(audit, source_path)
    if not isinstance(source, dict):
        return value
    minimum = source.get("minimum", "unknown")
    observed = source.get("version")
    if observed is None:
        devices = source.get("devices")
        if isinstance(devices, list):
            # Per-device readings stay labelled so a multi-NIC host remains
            # attributable. The collector pads a failed read with an entry
            # whose device and version are both "unknown"; rendering that
            # produced the literal "unknown unknown", which reads as if a
            # version had been observed. An all-placeholder list means no
            # device was actually read, and an empty list means a completed
            # scan found nothing to grade.
            def _field(entry: dict[str, Any], name: str) -> str:
                text = str(entry.get(name) or "").strip()
                return text or "unknown"

            readings = [
                f"device {_field(entry, 'device')}: version {_field(entry, 'version')}"
                for entry in devices
                if isinstance(entry, dict)
                and not (
                    _field(entry, "device") == "unknown"
                    and _field(entry, "version") == "unknown"
                )
            ]
            if readings:
                return f"{', '.join(readings)}; minimum version {minimum}"
            if devices:
                return f"no readable device; minimum version {minimum}"
            return f"no device present; minimum version {minimum}"
    observation = (
        f"observed version {observed if observed is not None else 'unknown'}; "
        f"minimum version {minimum}"
    )
    if key == "securityVersions.cudaToolkit.status":
        driver_compatibility = _nested(audit, "gpus.cudaVersion")
        normalized = _normalize_sentinel(driver_compatibility)
        absent = normalized in {"", "none", "unknown", *_NOT_APPLICABLE_VALUES}
        if not absent:
            observation += (
                "; CUDA driver compatibility "
                f"{driver_compatibility} (from nvidia-smi, not the installed toolkit)"
            )
        else:
            observation += "; measured from the installed toolkit with nvcc"
    return observation


def _reproduction(key: str) -> str:
    """Return a concise command that independently reproduces a check."""
    return _REPRODUCTION_COMMANDS.get(key, "")


def _references_for_finding(
    findings: Any, finding: Any | None, key: str
) -> tuple[tuple[str, str], ...]:
    """Return matching finding references and the public criteria."""
    references: list[tuple[str, str]] = []
    minimum_url = minimum_links.audit_check_url(key)
    if minimum_url:
        references.append((minimum_links.REFERENCE_LABEL, minimum_url))
    if finding is not None:
        references.extend(
            (cve, f"https://nvd.nist.gov/vuln/detail/{cve}")
            for cve in finding.cves
        )
        references.extend(
            findings._advisory_link(advisory)
            for advisory in finding.advisories
        )
    references = [reference for reference in references if reference[1]]
    return _with_criteria_reference(key, tuple(dict.fromkeys(references)))


def _pass_assessment(key: str, observed: Any) -> str:
    """Explain why a raw passing value satisfies its check."""
    normalized = str(observed).strip().lower().replace("-", "_")
    # Not-applicable values never reach this helper: `evaluate` skips them
    # through `_is_not_applicable` before it classifies a value as passing.
    if normalized == "unknown":
        return (
            "The collector could not verify this check. Treat this value as "
            "unverified."
        )
    if key == "security.januscape.status":
        if normalized == "not_exposed":
            return "The audit did not find Januscape exposure on this target."
        return (
            "The collector recorded a Januscape state that requires the separate "
            "Exposed result for interpretation."
        )
    if key == "securityVersions.virtioNetBluefield.exposure":
        if normalized == "none":
            return (
                "The audit did not find an active BlueField VIRTIO-Net controller "
                "exposure."
            )
        if normalized == "live":
            return (
                "The BlueField VIRTIO-Net controller is active. Its separate "
                "firmware status determines whether it meets the security minimum."
            )
        return (
            "The collector recorded the BlueField VIRTIO-Net exposure state shown "
            "below. Its separate firmware status supplies the security verdict."
        )
    if key == "gpus.gpuDirectRdmaPath" and isinstance(observed, dict):
        paths = []
        if observed.get("dmaBuf") is True:
            paths.append("DMA-BUF")
        if observed.get("nvidiaOpen") is True:
            paths.append("the NVIDIA open kernel modules")
        if paths:
            return (
                "The audit found a modern GPUDirect RDMA path through "
                + " and ".join(paths)
                + "."
            )
    return _PASS_ASSESSMENTS.get(
        key,
        "The collected evidence satisfies this check.",
    )


# The collectors and their upstream tools spell "does not apply" several ways
# ("not_applicable", "not-applicable", "not applicable", "N/A", "n/a").
# `_normalize_sentinel` folds separators so every spelling lands on one of
# these sentinels; real values such as versions carry digits or other words and
# never collapse to one of them.
_NOT_APPLICABLE_VALUES = frozenset({"not_applicable", "notapplicable", "n_a", "na"})


def _normalize_sentinel(value: Any) -> str:
    normalized = str(value).strip().lower()
    for separator in ("-", " ", "/"):
        normalized = normalized.replace(separator, "_")
    return normalized

# Counter-access results that mean the NCU check never reached a verdict, as
# opposed to "ncu ran (or was looked for) and is not there". Mirrors
# audit_findings._ncu_install_verdict_available, which suppresses the
# installed=false finding for the same reason: Kubernetes initializes that
# field to false before the GPU check pod runs, so a failed pod leaves a
# default, not a determination.
_NCU_INCONCLUSIVE_ACCESS = frozenset(
    {"compile-failed", "pod-failed", "resource-unavailable", "untested", "unknown"}
)


def _ncu_absence_is_conclusive(audit: dict[str, Any]) -> bool:
    access = _nested(audit, "software.ncu.hardwareCounterAccess")
    if access is None:
        # Older audits carry no counter-access result; their installed flag
        # was written directly by the collector and stands on its own.
        return True
    normalized = str(access).strip().lower()
    if normalized == "no-ncu":
        # On Kubernetes "no-ncu" can come from the pre-initialized default
        # when the check pod never delivered a result, so only a
        # non-Kubernetes harness may treat it as a real absence.
        return not isinstance(audit.get("kubernetes"), dict)
    return normalized not in _NCU_INCONCLUSIVE_ACCESS


@dataclass(frozen=True)
class _DependentCheck:
    """A prerequisite that must be conclusively absent for a skip to fire.

    ``prerequisite`` is the dotted path whose exact False makes the dependent
    check meaningless. ``absence_conclusive`` guards against harnesses where
    that False can be an unfilled default rather than a determination; when
    it returns False the dependent check falls through to normal grading, so
    "could not collect" stays a visible warning instead of a silent skip.
    """

    prerequisite: str
    absence_conclusive: Callable[[dict[str, Any]], bool] | None = None

    def skips(self, audit: dict[str, Any]) -> bool:
        if _nested(audit, self.prerequisite) is not False:
            return False
        return self.absence_conclusive is None or self.absence_conclusive(audit)


# Checks whose reading only means something when a prerequisite holds. When
# the prerequisite value is positively, conclusively False the dependent
# check is skipped: software.ncu.profilingEnabled says what a run of ncu
# would be allowed to do, and with no ncu installed there is no run to grade
# and nothing a provider could attest. Only an explicit False skips. A
# missing or unknown prerequisite keeps the dependent check graded, because
# "present but could not verify" must stay a warning.
_DEPENDENT_CHECK_PREREQUISITES: dict[str, _DependentCheck] = {
    "containers.enrootImportWorks": _DependentCheck(
        "containers.enroot",
        lambda audit: _nested(audit, "containers.workerCheckOk") is not False,
    ),
    "software.ncu.profilingEnabled": _DependentCheck(
        "software.ncu.installed", _ncu_absence_is_conclusive
    ),
    "software.perf.perfEventParanoid": _DependentCheck(
        "software.perf.installed"
    ),
    "software.perf.kptrRestrict": _DependentCheck("software.perf.installed"),
    "healthChecks.dcgmSlurm": _DependentCheck(
        "healthChecks.dcgmInstalled",
        lambda audit: _nested(audit, "gpus.amd.present") is not True,
    ),
}


def _is_not_applicable(audit: dict[str, Any], key: str, value: Any) -> bool:
    if _normalize_sentinel(value) in _NOT_APPLICABLE_VALUES:
        return True
    if key == "securityVersions.virtioNetBluefield.exposure":
        status = _nested(audit, "securityVersions.virtioNetBluefield.status")
        return _normalize_sentinel(status) in _NOT_APPLICABLE_VALUES
    return False


def _context_assessment(audit: dict[str, Any], key: str) -> str:
    parent = _nested(audit, key.rsplit(".", 1)[0])
    if isinstance(parent, dict):
        for field in ("detail", "message", "assessment", "reason"):
            value = parent.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _security_extension_specs(harness: str | None = None) -> list[AuditCheckSpec]:
    """Return security checks that do not have general finding rules.

    Keep harness-inapplicable checks in the catalog: live evaluation renders
    them as SKIPPED, so ``--show`` must advertise the same check set that a run
    prints.  ``harness`` remains accepted for API compatibility.
    """
    from cmax import security

    return [
        AuditCheckSpec(spec.id, spec.title, category_for_key(spec.id).name)
        for spec in security.CHECK_SPECS
        if spec.id in _SECURITY_EXTENSION_IDS
    ]


def _security_extension_checks(
    values: dict[str, Any],
    harness: str | None = None,
    environment: str | None = None,
) -> list[AuditCheck]:
    """Convert the additional security checks to the standard report shape."""
    from cmax import security

    status_map = {
        security.PASS: PASS,
        security.WARNING: WARNING,
        security.CRITICAL: FAIL,
        security.NOT_APPLICABLE: SKIPPED,
    }
    checks = []
    for check in security.evaluate_security(values):
        if check.id not in _SECURITY_EXTENSION_IDS:
            continue
        harnesses = _SECURITY_EXTENSION_HARNESSES.get(check.id)
        if (
            harness is not None
            and harnesses is not None
            and harness not in harnesses
        ):
            checks.append(
                AuditCheck(
                    check.id,
                    check.title,
                    category_for_key(check.id).name,
                    SKIPPED,
                    _harness_not_applicable(harness),
                    references=_with_criteria_reference(check.id),
                )
            )
            continue
        if check.id == "pcie-passthrough" and environment == "vm":
            checks.append(
                AuditCheck(
                    check.id,
                    check.title,
                    category_for_key(check.id).name,
                    SKIPPED,
                    "running in a VM",
                    "Skipped because this audit is running in a VM; PCIe "
                    "passthrough isolation is controlled by the physical host.",
                    references=_with_criteria_reference(
                        check.id,
                        tuple(
                            (reference.label, reference.url)
                            for reference in check.references
                        ),
                    ),
                )
            )
            continue
        checks.append(
            AuditCheck(
                check.id,
                check.title,
                category_for_key(check.id).name,
                status_map[check.status],
                check.observed,
                check.assessment,
                check.remediation,
                _with_criteria_reference(
                    check.id,
                    tuple(
                        (reference.label, reference.url)
                        for reference in check.references
                    ),
                ),
                _reproduction(check.id),
            )
        )
    return checks


def list_check_specs(
    repo_root: Path, *, category: str | None = None, harness: str | None = None
) -> list[AuditCheckSpec]:
    """List each check that the selected audit profile can evaluate."""
    if category is not None and category not in AUDIT_PROFILE_NAMES:
        raise ValueError(f"unknown audit profile: {category}")
    findings = _load_findings(repo_root)
    seen: set[str] = set()
    checks: list[AuditCheckSpec] = []
    for rule in findings.RULES:
        if rule.key in seen:
            continue
        seen.add(rule.key)
        check_category = category_for_key(rule.key).name
        if profile_includes(category, rule.key):
            checks.append(AuditCheckSpec(rule.key, _title(rule.key), check_category))
    checks.extend(
        check
        for check in _security_extension_specs(harness)
        if profile_includes(category, check.key)
    )
    return checks


def format_check_specs(checks: list[AuditCheckSpec]) -> str:
    """Group audit check descriptions by their stable category."""
    lines: list[str] = []
    for category in AUDIT_CATEGORIES:
        members = [check for check in checks if check.category == category.name]
        if not members:
            continue
        if lines:
            lines.append("")
        lines.append(f"[{category.name}] {category.title} ({len(members)} checks)")
        lines.extend(f"  {check.key}: {check.title}" for check in members)
    return "\n".join(lines)


def evaluate(
    values: dict[str, Any],
    repo_root: Path,
    *,
    category: str | None = None,
    harness: str | None = None,
    environment: str | None = None,
) -> list[AuditCheck]:
    """Evaluate each unique finding rule key for the selected audit target."""
    if category is not None and category not in AUDIT_PROFILE_NAMES:
        raise ValueError(f"unknown audit profile: {category}")
    findings = _load_findings(repo_root)
    audit = findings._audit_data(values)
    cluster = values.get("cluster")
    if harness is None and isinstance(cluster, dict):
        detected = str(cluster.get("orchestrator") or "").strip().lower()
        harness = detected or None
    if environment is None and isinstance(cluster, dict):
        detected = str(cluster.get("environment") or "").strip().lower()
        environment = detected or None
    detect_findings = getattr(findings, "detect_findings", lambda _values: [])
    detected_findings = detect_findings(values)
    findings_by_key = {finding.key: finding for finding in detected_findings}
    rules_by_key: dict[str, list[Any]] = {}
    for rule in findings.RULES:
        rules_by_key.setdefault(rule.key, []).append(rule)

    checks = []
    for key, rules in rules_by_key.items():
        try:
            check_category = category_for_key(key).name
        except ValueError:
            if category is not None:
                continue
            check_category = "uncategorized"
        if not profile_includes(category, key):
            continue
        applicable_rules = [
            rule
            for rule in rules
            if harness is None
            or getattr(rule, "harnesses", None) is None
            or harness in rule.harnesses
        ]
        if not applicable_rules:
            title = _title(key)
            checks.append(
                AuditCheck(
                    key,
                    title,
                    check_category,
                    SKIPPED,
                    _harness_not_applicable(harness),
                    references=_with_criteria_reference(key),
                )
            )
            continue
        rules = applicable_rules
        observed = findings.nested_get(audit, *key.split("."))
        if observed is None:
            if not any(rule.flag_when_missing for rule in rules):
                continue
            checks.append(
                AuditCheck(
                    key,
                    _title(key),
                    check_category,
                    SKIPPED,
                    "not collected",
                    "The collector did not emit a graded result for this check.",
                    references=_with_criteria_reference(key),
                )
            )
            continue
        effective = "not-present" if observed is None else observed
        display_observed = (
            _version_observation(audit, key, effective)
            if any(rule.severity == findings.VERSION for rule in rules)
            or key in _CONTEXT_OBSERVATION_KEYS
            else effective
        )
        if _is_not_applicable(audit, key, effective):
            checks.append(
                AuditCheck(
                    key,
                    _title(key),
                    check_category,
                    SKIPPED,
                    display_observed,
                    _context_assessment(audit, key)
                    or "The collector reported that this check does not apply to the target.",
                    references=_with_criteria_reference(key),
                )
            )
            continue
        dependent = _DEPENDENT_CHECK_PREREQUISITES.get(key)
        if dependent is not None and dependent.skips(audit):
            checks.append(
                AuditCheck(
                    key,
                    _title(key),
                    check_category,
                    SKIPPED,
                    display_observed,
                    f"Not applicable: its prerequisite {dependent.prerequisite} "
                    "is false on this target, so there is nothing to verify.",
                    references=_with_criteria_reference(key),
                )
            )
            continue
        unverified = str(effective).strip().lower() == "unknown"
        matched = [rule for rule in rules if rule.failing(effective)]
        failing = [
            rule
            for rule in matched
            if rule.guard is None or rule.guard(audit)
        ]
        if matched and not failing:
            # The finding rules suppress a matched failing value for one of
            # three reasons, and the report must not present them alike: the
            # check does not apply to this hardware or configuration (skip it
            # as not applicable, not as unverified), sibling evidence already
            # proves the checked property (a pass, naming that evidence), or
            # the check never produced a verdict (an unverified skip). The
            # classification reads only the audit blob and the rule key -
            # never the profile - so both audit commands render a suppressed
            # value identically and the subset property holds. Do not drop the
            # check either: an operator comparing profiles must see the same
            # check set.
            classify = getattr(findings, "classify_suppression", None)
            kind, reason = (
                classify(key, audit) if classify is not None else ("unverified", "")
            )
            if kind == getattr(findings, "VERIFIED_KIND", "verified_ok"):
                checks.append(
                    AuditCheck(
                        key,
                        _title(key),
                        check_category,
                        PASS,
                        display_observed,
                        reason,
                        references=_references_for_finding(findings, None, key),
                    )
                )
                continue
            if kind == getattr(findings, "NOT_APPLICABLE_KIND", "not_applicable"):
                assessment = f"Not applicable: {reason}" if reason else (
                    "Not applicable to this hardware or configuration."
                )
            else:
                assessment = reason or (
                    "The finding rules suppressed this value because the check "
                    "could not verify it. Treat this value as unverified, not "
                    "as evidence of absence."
                )
            checks.append(
                AuditCheck(
                    key,
                    _title(key),
                    check_category,
                    SKIPPED,
                    display_observed,
                    assessment,
                    references=_with_criteria_reference(key),
                )
            )
            continue
        if any(rule.severity in {findings.MISSING, findings.VERSION} for rule in failing):
            status = FAIL
        elif failing:
            status = WARNING
        elif unverified:
            status = WARNING
        else:
            status = PASS
        finding = findings_by_key.get(key)
        context_assessment = (
            ""
            if key == "securityVersions.virtioNetBluefield.exposure"
            else _context_assessment(audit, key)
        )
        assessment = (
            finding.detected
            if finding is not None
            else (
                _pass_assessment(key, observed)
                if unverified
                else context_assessment or _pass_assessment(key, observed)
            )
        )
        recommendation = (
            finding.recommendation
            if finding is not None
            else _unverified_recommendation(audit, key)
        )
        references = _references_for_finding(findings, finding, key)
        checks.append(
            AuditCheck(
                key,
                _title(key),
                check_category,
                status,
                display_observed,
                assessment,
                recommendation,
                references,
                _reproduction(key),
            )
        )
    checks.extend(
        check
        for check in _security_extension_checks(values, harness, environment)
        if profile_includes(category, check.key)
    )
    return sorted(checks, key=lambda check: (_STATUS_ORDER[check.status], check.title))


def format_report(
    checks: list[AuditCheck],
    *,
    verbosity: int = 1,
    color: bool = False,
    category: str | None = None,
    command: str | None = None,
) -> str:
    verbosity = min(max(verbosity, 1), 3)
    counts = {
        status: sum(check.status == status for check in checks)
        for status in (PASS, WARNING, FAIL, SKIPPED)
    }
    command = command or (f"cmax audit {category}" if category else "cmax audit")
    title = (
        f"# ClusterMAX {category} audit report"
        if category
        else "# ClusterMAX audit report"
    )
    lines = [report_style.paint(title, "bold", color=color)]
    visible = checks
    if visible:
        for check in visible:
            lines.append("")
            observed = (
                check.observed
                if isinstance(check.observed, str)
                else json.dumps(check.observed, sort_keys=True, default=str)
            )
            assessment = f"Observed: {observed}"
            details = []
            if verbosity >= 3:
                assessment = check.assessment
                details.append(
                    (
                        "Observed",
                        observed,
                    )
                )
                if check.reproduce:
                    details.append(("Reproduce", check.reproduce.replace("`", "")))
            lines.extend(
                report_style.format_check(
                    title=check.title,
                    check_id=check.key,
                    status=check.status,
                    assessment=assessment,
                    details=details,
                    recommendation=(
                        check.recommendation if verbosity >= 3 else ""
                    ),
                    references=(
                        minimum_links.canonical_references(check.references)
                        if verbosity >= 2
                        else tuple(
                            reference
                            for reference in minimum_links.canonical_references(
                                check.references
                            )
                            if reference[0] == minimum_links.REFERENCE_LABEL
                        )
                    ),
                    color=color,
                )
            )
    elif checks:
        lines.append("    No warnings or failures detected.")
    else:
        lines.append("    No classifiable audit checks were found.")
    summary = ", ".join(
        (
            report_style.count(f"{counts[FAIL]} failed", FAIL, color=color),
            report_style.count(
                f"{counts[WARNING]} warning"
                f"{'' if counts[WARNING] == 1 else 's'}",
                WARNING,
                color=color,
            ),
            report_style.count(f"{counts[PASS]} passed", PASS, color=color),
            report_style.count(
                f"{counts[SKIPPED]} skipped", SKIPPED, color=color
            ),
        )
    )
    lines.extend(("", summary))
    if verbosity < 3:
        hint = {
            1: f"run '{command} -vv' for CVE and documentation links, -vvv for issue details, reproduction, and remediation",
            2: f"run '{command} -vvv' for issue details, reproduction, and remediation",
        }[verbosity]
        lines.append(report_style.paint(hint, "dim", color=color))
    return "\n".join(lines)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def find_raw_log(values_path: Path) -> Path | None:
    return next(
        (
            candidate
            for candidate in (
                values_path.with_name("audit.out"),
                values_path.parent / "logs" / "audit.out",
            )
            if candidate.is_file()
        ),
        None,
    )


def render(
    values_path: Path,
    display_root: Path,
    *,
    verbosity: int = 1,
    rules_root: Path | None = None,
    color: bool = False,
    raw_path: Path | None = None,
    category: str | None = None,
    harness: str | None = None,
    environment: str | None = None,
) -> str:
    if rules_root is None:
        from cmax.security import find_runtime_root

        rules_root = find_runtime_root()
    values = json.loads(values_path.read_text())
    report = format_report(
        evaluate(
            values,
            rules_root,
            category=category,
            harness=harness,
            environment=environment,
        ),
        verbosity=verbosity,
        color=color,
        category=category,
    )
    if verbosity >= 3:
        raw_log = raw_path or find_raw_log(values_path)
        if raw_log is not None:
            report += "\n" + report_style.paint(
                f"Raw collector log: {_display_path(raw_log, display_root)}",
                "dim",
                color=color,
            )
    return report
