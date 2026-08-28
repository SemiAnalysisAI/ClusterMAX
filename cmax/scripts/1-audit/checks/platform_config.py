"""Shared implementation for platform configuration checks.

https://developer.nvidia.com/blog/nvidia-exemplar-cloud-lessons-for-unlocking-full-performance-on-ai-infrastructure/

The check emits four ``audit_data`` keys:

* ``vm_iommu`` - IOMMU mode (passthrough vs full DMA translation) and the
  IOMMU group of every GPU and RDMA NIC, plus whether the host is a virtual
  machine guest.
* ``arm_smmu_virtualization`` - Arm SMMUv3 Command Queue Virtualization
  (CMDQV / VCMDQ) exposure on Arm/Grace guests.
* ``nccl_topo_file`` - whether a host NCCL topology file also resolves inside
  the benchmark container. This is an active check: it globs ``/etc/nccl/*.xml``
  on the host, then starts a real Pyxis container through ``srun`` with no mount
  flag of its own and reads the file from inside it, comparing size and digest
  against the host copy. What it grades is the automatic mount; a per-job bind
  mount is a workaround and is never scored as a pass.
* ``nccl_ib_qps`` - the effective ``NCCL_IB_QPS_PER_CONNECTION`` against the
  shape of the fabric. Extra queue pairs only buy ECMP entropy once there is a
  spine tier to spread flows across, so the advisory is gated on a multi-tier
  Clos: the tier count read from the Slurm topology when there is one, and the
  GPU node count against ``CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD`` when there is
  not. A single-tier fabric reports ``not_applicable``.

All four read the same host state, so they share one fan-out: an ``srun``
worker per node on slurm, a privileged pod with host mounts per GPU node on
k8s, and a local read on standalone. Only ``nccl_topo_file`` needs a second
vantage - a container started by the same launcher - because the failure it
looks for is a mount that the launcher does not make.

No check in this check hard-fails on missing evidence. A platform the check
does not apply to reports ``not_applicable``, and an unreadable platform
reports ``unknown``, so an inconclusive check is never read as a provider
fault.

Environment variables:

* ``CLUSTERMAX_AUDIT_K8S_NAMESPACE`` (default ``default``)
* ``CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE`` (default ``python:3.12-alpine``)
* ``CLUSTERMAX_AUDIT_K8S_HOST_CHECK_PULL_POLICY`` (default ``IfNotPresent``)
* ``CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS`` (default: all GPU nodes)
* ``CLUSTERMAX_PYXIS_CHECK_IMAGE`` - container the mount check launches.
  Falls back to the campaign-wide ``CLUSTERMAX_CONTAINER_IMAGE``, then to
  ``nvcr.io#nvidia/pytorch:26.04-py3``.
* ``CLUSTERMAX_PYXIS_CHECK_TIMEOUT_S`` (default ``600``)
* ``CLUSTERMAX_AUDIT_NCCL_CONTAINER_CHECK`` - set ``0`` to skip the in-container
  arm of ``nccl_topo_file``.
* ``CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD`` (default ``64``) - GPU node count
  above which a fabric with no readable topology is treated as a multi-tier
  Clos, which is what makes the queue-pair advisory apply.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
CHECK_KEYS = ("vm_iommu", "arm_smmu_virtualization")
ALL_CHECK_KEYS = (*CHECK_KEYS, "nccl_topo_file", "nccl_ib_qps")
CACHE_PATH_ENV = "CLUSTERMAX_PLATFORM_CHECK_CACHE"
REQUESTED_CHECKS_ENV = "CLUSTERMAX_PLATFORM_CHECK_KEYS"

# NCCL reads exactly the path in NCCL_TOPO_FILE. These are the conventional
# locations providers place that file, checked so the check can tell "the host
# has a topology file the container cannot see" from "there is no file".
TOPO_FILE_CANDIDATES = (
    "/etc/nccl/topo.xml",
    "/etc/nccl/nccl-topology.xml",
    "/etc/nccl-topology.xml",
    "/var/run/nvidia-topologyd/virtualTopology.xml",
)

# Providers name the file in /etc/nccl inconsistently, so the directory is
# globbed rather than matched against the fixed names above.
TOPO_FILE_GLOB_DIR = "/etc/nccl"
TOPO_FILE_GLOB = "*.xml"

# Where NCCL looks when nothing declares a topology file. nvidia-topologyd
# writes here, so a container that only mounts this path resolves a topology
# file with no environment variable and no conf entry.
NCCL_DEFAULT_TOPO_FILE = "/var/run/nvidia-topologyd/virtualTopology.xml"

# NCCL reads this file at init, so it declares the topology file just as
# NCCL_TOPO_FILE does. Both the host read and the container read use it.
NCCL_CONF_PATH = "/etc/nccl.conf"

# The three steps NCCL resolves a topology file from, in its own order.
TOPO_SOURCE_ENV = "NCCL_TOPO_FILE"
TOPO_SOURCE_CONF = NCCL_CONF_PATH
TOPO_SOURCE_DEFAULT = "default_path"
TOPO_SOURCE_LABELS = {
    TOPO_SOURCE_ENV: TOPO_SOURCE_ENV,
    TOPO_SOURCE_CONF: TOPO_SOURCE_CONF,
    TOPO_SOURCE_DEFAULT: "the NCCL built-in default path",
}

# What the check grades is the automatic mount. A per-job bind mount reaches the
# same file, so it is named here as a workaround and never scored: the check adds
# no --container-mounts of its own, so a run that only passes with one still
# fails, which is the point.
TOPO_REMEDIATION = (
    f"Provider fix: add an enroot mount hook or a pyxis default mount so {TOPO_FILE_GLOB_DIR}/{TOPO_FILE_GLOB} "
    "is mounted into every container with no per-job flag. Per-job workaround, which this check does not "
    "score as a pass: --mount type=bind,source=/etc/nccl/topo.xml,target=/etc/nccl/topo.xml"
)

# Arm SMMUv3 command queue virtualization. The host driver is tegra241-cmdqv on
# Grace platforms; the kernel spells the module with an underscore and the
# devicetree compatible string with a dash.
CMDQV_DRIVER_DIRS = (
    "/sys/bus/platform/drivers/tegra241_cmdqv",
    "/sys/bus/platform/drivers/tegra241-cmdqv",
)
CMDQV_MODULE_DIRS = (
    "/sys/module/tegra241_cmdqv",
    "/sys/module/arm_smmu_v3",
)
CMDQV_COMPATIBLE = "nvidia,tegra241-cmdqv"

# Strings that name the Grace SoC or a product built on it. CMDQV / VCMDQ is a
# Grace extension to SMMUv3, so a plain Arm guest cannot expose it and must
# never be graded as if it should. Grace servers boot ACPI rather than
# devicetree and a hypervisor usually passes through the product name, not the
# SoC name, so the product strings carry the identification on exactly the
# virtualized GB200 the blog post measured. These markers only ever confirm
# Grace; not matching one is read as "this vantage did not identify the
# platform", never as "this is not Grace".
GRACE_DEVICETREE_MARKERS = (
    "nvidia,tegra241",
    "nvidia,grace",
    "nvidia,gh200",
    "nvidia,gb200",
    "nvidia,gb300",
)
GRACE_DMI_MARKERS = ("grace", "tegra241", "gh200", "gb200", "gb300")

NVIDIA_VENDOR_ID = "0x10de"
MELLANOX_VENDOR_ID = "0x15b3"

# Same pin the Slurm networking benchmarks default to
# used by workload launchers, so the mount check exercises
# the launcher against the image the campaign really runs.
PINNED_CHECK_IMAGE = "nvcr.io#nvidia/pytorch:26.04-py3"

DEFAULT_QPS_PER_CONNECTION = 1

# Queue pairs beyond one only help where ECMP has a spine tier to hash flows
# across, so the advisory is gated on the fabric having more than one tier. The
# tier count is exact when a Slurm topology dump is readable; without one, a
# cluster larger than this many GPU nodes is treated as multi-tier, because a
# single leaf switch does not reach that far.
DEFAULT_CLOS_NODE_THRESHOLD = 64

# The value the advisory asks for. Two is the minimum; the blog post's range is
# 2-4 and the right value is workload-dependent, which is why this never fails.
RECOMMENDED_QPS_PER_CONNECTION = 2

# Paths a site publishes its Slurm fabric topology at when `scontrol show
# topology` is unavailable from this vantage.
SLURM_TOPOLOGY_FILES = (
    "/etc/slurm/topology.conf",
    "/etc/slurm/topology.yaml",
    "/etc/slurm-llnl/topology.conf",
)

_FANOUT = None


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily.

    Lazy because the k8s worker arm runs this file via ``python3 -`` on stdin,
    where ``__file__`` does not point at the real check path. That arm never
    calls into _fanout.
    """
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import _fanout

        _FANOUT = _fanout
    return _FANOUT


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def under_root(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def file_state(path: Path) -> bool | None:
    """Whether ``path`` is a file, or ``None`` when the stat did not answer.

    ``Path.is_file()`` re-raises every OSError whose errno is outside a small
    allowlist, so ``ESTALE``, ``EIO``, ``ENOTCONN``, and ``EACCES`` propagate on
    the CI interpreter and would abort a whole host read. The third state is
    what keeps that failure honest: an entry we could not stat is neither a file
    we found nor a file we ruled out.
    """
    try:
        return path.is_file()
    except OSError:
        return None


def is_dir_confirmed(path: Path) -> bool:
    """True only when ``path`` is a directory this vantage could confirm.

    A stat we could not make means the vantage cannot see the tree, which is the
    reading that keeps a candidate under it unreachable rather than absent.
    """
    try:
        return path.is_dir()
    except OSError:
        return False


def exists_confirmed(path: Path) -> bool:
    """True only when ``path`` exists and this vantage could confirm it."""
    try:
        return path.exists()
    except OSError:
        return False


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def run_command(command: list[str], *, timeout: int = 30, input_text: str | None = None):
    return subprocess.run(
        command,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


# --------------------------------------------------------------------------
# Virtualization detection
# --------------------------------------------------------------------------

# DMI strings that only a hypervisor writes. No physical machine advertises
# these, so they decide on their own.
DMI_HYPERVISOR_MARKERS = (
    ("qemu", "qemu"),
    ("kvm", "kvm"),
    ("vmware", "vmware"),
    ("virtualbox", "oracle"),
    ("microsoft corporation virtual", "microsoft"),
    ("xen", "xen"),
    ("nutanix", "nutanix"),
)

# DMI strings that name a cloud provider. A ".metal" instance advertises the
# same string as a guest at the same provider, so these name the platform
# without deciding whether it is a guest.
DMI_CLOUD_MARKERS = (
    ("amazon ec2", "amazon"),
    ("google compute engine", "google"),
    ("alibaba cloud", "alibaba"),
)


def detect_virtualization(root: Path, *, runner=run_command) -> dict[str, Any]:
    """Report whether this host is a virtual machine guest.

    Three independent signals, in the order the brief lists them:
    ``systemd-detect-virt``, the DMI vendor strings, and the x86 ``hypervisor``
    CPUID flag. ``detected`` is ``None`` when no signal is readable, which the
    summaries turn into ``unknown`` rather than "bare metal".
    """
    evidence: list[str] = []
    virt_type = ""
    detected: bool | None = None

    if root == Path("/"):
        command = ["systemd-detect-virt"]
    elif exists_confirmed(under_root(root, "/proc/1/ns/mnt")):
        # A chrooted read cannot run the host's detector, and running it in the
        # pod reports the container instead. hostPID puts the host's init in
        # this namespace, so entering its mount namespace runs the host binary
        # against the host, which is the only strong signal aarch64 has: it
        # carries no cpuinfo hypervisor bit.
        command = ["nsenter", "--target", "1", "--mount", "--", "systemd-detect-virt"]
    else:
        command = []

    if command:
        try:
            proc = runner(command, timeout=10)
        except (OSError, subprocess.SubprocessError):
            proc = None
        if proc is not None:
            reported = (proc.stdout or "").strip()
            if reported:
                evidence.append(f"systemd-detect-virt: {reported}")
                virt_type = reported
                detected = reported != "none"

    cpuinfo = read_text(under_root(root, "/proc/cpuinfo"))
    if cpuinfo:
        flag_lines = [line for line in cpuinfo.splitlines() if line.startswith("flags")]
        hypervisor_flag = any(" hypervisor" in f" {line} " for line in flag_lines)
        if hypervisor_flag:
            evidence.append("cpuinfo: hypervisor flag present")
            # Xen Dom0 carries the CPUID hypervisor bit and is the host, which
            # is why systemd-detect-virt special-cases it and reports "none".
            # The bit decides only when that stronger answer was unavailable.
            if detected is None:
                detected = True
        elif detected is None and flag_lines:
            # x86 with a readable flag list and no hypervisor bit is bare metal.
            evidence.append("cpuinfo: no hypervisor flag")
            detected = False

    dmi_vendor = read_text(under_root(root, "/sys/class/dmi/id/sys_vendor")).strip()
    dmi_product = read_text(under_root(root, "/sys/class/dmi/id/product_name")).strip()
    dmi_text = f"{dmi_vendor} {dmi_product}".strip()
    if dmi_text:
        evidence.append(f"dmi: {dmi_text}")
        lowered = dmi_text.lower()
        for marker, name in DMI_HYPERVISOR_MARKERS:
            if marker in lowered:
                # Let DMI decide only when systemd-detect-virt and the cpuinfo
                # hypervisor bit were both unavailable, which is the aarch64
                # case DMI is here to cover. When something stronger already
                # found a guest, DMI still names the hypervisor.
                if detected is None:
                    detected = True
                if detected:
                    virt_type = virt_type or name
                break
        else:
            for marker, name in DMI_CLOUD_MARKERS:
                if marker in lowered:
                    # A cloud vendor string names the provider and nothing
                    # more. An EC2 ".metal" host and an EC2 guest write the
                    # same one, so promoting it would assert a guest on bare
                    # metal wherever no stronger signal exists, which on
                    # aarch64 is everywhere. An unresolved platform stays
                    # unknown instead.
                    if detected:
                        virt_type = virt_type or name
                    break

    hypervisor_type = read_text(under_root(root, "/sys/hypervisor/type")).strip()
    if hypervisor_type:
        evidence.append(f"sys/hypervisor/type: {hypervisor_type}")
        # A host that runs a hypervisor exposes this too. Xen Dom0 reads "xen"
        # here while systemd-detect-virt correctly reports "none", so this
        # names the hypervisor and only decides when nothing stronger did.
        if detected is None:
            detected = True
        if detected:
            virt_type = virt_type or hypervisor_type

    return {
        "detected": detected,
        "type": virt_type or ("none" if detected is False else "unknown"),
        "evidence": evidence,
    }


# --------------------------------------------------------------------------
# Check 1: IOMMU
# --------------------------------------------------------------------------


def parse_kernel_cmdline(text: str) -> dict[str, str]:
    """Kernel parameters as a mapping. A bare flag maps to an empty string.

    The kernel takes the last occurrence of a repeated parameter, so later
    values overwrite earlier ones here too.
    """
    params: dict[str, str] = {}
    for token in (text or "").split():
        key, sep, value = token.partition("=")
        if not key:
            continue
        params[key] = value if sep else ""
    return params


def iommu_passthrough_requested(params: dict[str, str]) -> bool:
    if params.get("iommu.passthrough", "").lower() in {"1", "y", "yes", "on", "true"}:
        return True
    return any(params.get(key, "").lower() == "pt" for key in ("iommu", "intel_iommu", "amd_iommu"))


def iommu_disabled_requested(params: dict[str, str]) -> bool:
    return any(params.get(key, "").lower() in {"off", "disabled"} for key in ("iommu", "intel_iommu", "amd_iommu"))


def classify_iommu_mode(
    *,
    cmdline_read: bool,
    sysfs_read: bool,
    params: dict[str, str],
    iommu_units: list[str],
    grouped_devices: int,
) -> str:
    """One of passthrough / translated / disabled / unknown."""
    if not cmdline_read and not sysfs_read:
        return "unknown"
    if iommu_disabled_requested(params) and not iommu_units:
        return "disabled"
    if iommu_passthrough_requested(params):
        return "passthrough"
    if iommu_units or grouped_devices:
        return "translated"
    if sysfs_read:
        return "disabled"
    return "unknown"


def sysfs_class_readable(root: Path) -> bool:
    """Whether this vantage can see sysfs at all.

    Distinguishes a class directory that is missing because the subsystem is
    not present from a check running where /sys is not mounted or not readable.
    """
    # os.listdir, not Path.iterdir: before Python 3.13 iterdir is a generator
    # function, so calling it reads nothing and cannot raise.
    try:
        os.listdir(under_root(root, "/sys/class"))
    except OSError:
        return False
    return True


def pci_device_kind(vendor: str, pci_class: str) -> str:
    vendor = (vendor or "").lower()
    pci_class = (pci_class or "").lower()
    if vendor == NVIDIA_VENDOR_ID and pci_class.startswith("0x03"):
        return "gpu"
    if pci_class.startswith("0x0207"):
        return "rdma_nic"
    if vendor == MELLANOX_VENDOR_ID and pci_class.startswith("0x02"):
        return "rdma_nic"
    return "other"


def collect_pci_devices(root: Path, *, include_rdma: bool = True) -> tuple[list[dict[str, Any]], bool]:
    """Selected GPU and RDMA NIC PCI functions with their IOMMU group.

    ``iommu_group`` is a symlink into ``/sys/kernel/iommu_groups/<n>``; an empty
    string means the device is in no group, which is what a disabled or
    unbound IOMMU looks like from sysfs.

    The second element is False when the sysfs directory could not be read, so
    a caller can tell "no GPU on this host" from "this vantage cannot see the
    PCI bus" instead of reporting the second as the first.

    A standalone audit sets ``include_rdma`` to False because RDMA NICs belong
    to the scale-out fabric. The local GPU IOMMU check remains applicable.
    """
    devices_dir = under_root(root, "/sys/bus/pci/devices")
    try:
        entries = sorted(devices_dir.iterdir())
    except OSError:
        return [], False

    devices: list[dict[str, Any]] = []
    for entry in entries:
        vendor = read_text(entry / "vendor").strip()
        pci_class = read_text(entry / "class").strip()
        kind = pci_device_kind(vendor, pci_class)
        if kind == "other" or (kind == "rdma_nic" and not include_rdma):
            continue
        group_path = entry / "iommu_group"
        group = ""
        if exists_confirmed(group_path):
            group = group_path.resolve().name
        devices.append(
            {
                "bdf": entry.name,
                "kind": kind,
                "vendor": vendor,
                "class": pci_class,
                "device": read_text(entry / "device").strip(),
                "iommu_group": group,
            }
        )
    return devices, True


def collect_iommu(root: Path, *, include_rdma: bool = True) -> dict[str, Any]:
    cmdline_text = read_text(under_root(root, "/proc/cmdline"))
    params = parse_kernel_cmdline(cmdline_text)

    # An unreadable /sys/class/iommu is not evidence of a disabled IOMMU. A
    # kernel with the subsystem present always shows the class directory, empty
    # when no unit is bound, so only a successful read can rule the IOMMU out.
    iommu_dir = under_root(root, "/sys/class/iommu")
    try:
        iommu_units = sorted(entry.name for entry in iommu_dir.iterdir())
        sysfs_read = True
    except OSError:
        iommu_units = []
        sysfs_read = False

    devices, devices_read = collect_pci_devices(root, include_rdma=include_rdma)
    grouped = [device for device in devices if device["iommu_group"]]

    acpi_dir = under_root(root, "/sys/firmware/acpi/tables")
    acpi_tables = {
        "dmar": exists_confirmed(acpi_dir / "DMAR"),
        "ivrs": exists_confirmed(acpi_dir / "IVRS"),
        "iort": exists_confirmed(acpi_dir / "IORT"),
    }

    mode = classify_iommu_mode(
        cmdline_read=bool(cmdline_text),
        sysfs_read=sysfs_read,
        params=params,
        iommu_units=iommu_units,
        grouped_devices=len(grouped),
    )

    return {
        "mode": mode,
        "cmdline_read": bool(cmdline_text),
        "cmdline_params": {
            key: params[key]
            for key in ("iommu", "intel_iommu", "amd_iommu", "iommu.passthrough", "iommu.strict")
            if key in params
        },
        "sysfs_units": iommu_units,
        "acpi_tables": acpi_tables,
        "devices": devices,
        "devices_read": devices_read,
        "grouped_device_count": len(grouped),
    }


def summarize_vm_iommu(report: dict[str, Any]) -> dict[str, Any]:
    iommu = report.get("iommu", {})
    virtualization = report.get("virtualization", {})
    mode = str(iommu.get("mode") or "unknown")
    virtualized = virtualization.get("detected")
    devices = iommu.get("devices") or []
    evidence = {"virtualization": virtualization, "iommu": iommu}

    if not devices:
        if not iommu.get("devices_read", True):
            return summary(
                "unknown",
                "the PCI bus is not readable from where this check ran; GPU and RDMA device presence is unknown",
                evidence=evidence,
            )
        return summary(
            "not_applicable",
            "no GPU or RDMA NIC PCI function on this host; IOMMU mapping overhead does not apply",
            evidence=evidence,
        )
    if mode == "unknown":
        return summary(
            "unknown",
            "IOMMU state is not observable from this guest",
            evidence=evidence,
        )
    if mode != "translated":
        return summary(
            "pass",
            f"IOMMU mode is {mode} for {len(devices)} GPU / RDMA device(s)",
            evidence=evidence,
        )

    where = "virtual machine guest" if virtualized else "host"
    if virtualized is None:
        where = "host of unknown virtualization"
    return summary(
        "warning",
        (
            f"{where} uses full DMA translation for {len(devices)} GPU / RDMA device(s); "
            "map and unmap cost is charged to every input and output operation"
        ),
        warnings=[
            f"IOMMU mode is translated with kernel parameters {iommu.get('cmdline_params') or '{}'}",
        ],
        evidence=evidence,
    )


# --------------------------------------------------------------------------
# Check 2: Arm SMMU command queue virtualization
# --------------------------------------------------------------------------


def devicetree_has_cmdqv(root: Path) -> bool:
    base = under_root(root, "/sys/firmware/devicetree/base")
    try:
        candidates = list(base.rglob("compatible"))
    except OSError:
        return False
    for candidate in candidates:
        if CMDQV_COMPATIBLE in read_text(candidate):
            return True
    return False


def devicetree_names_grace(root: Path) -> bool:
    base = under_root(root, "/sys/firmware/devicetree/base")
    try:
        candidates = list(base.rglob("compatible"))
    except OSError:
        return False
    for candidate in candidates:
        text = read_text(candidate).lower()
        if any(marker in text for marker in GRACE_DEVICETREE_MARKERS):
            return True
    return False


def dmi_names_grace(root: Path) -> bool:
    text = " ".join(
        read_text(under_root(root, f"/sys/class/dmi/id/{field}"))
        for field in ("sys_vendor", "product_name", "board_name")
    ).lower()
    return any(marker in text for marker in GRACE_DMI_MARKERS)


def collect_arm_smmu(root: Path, machine: str) -> dict[str, Any]:
    iommu_dir = under_root(root, "/sys/class/iommu")
    try:
        units = sorted(entry.name for entry in iommu_dir.iterdir())
    except OSError:
        units = []
    smmuv3_units = [unit for unit in units if unit.startswith("smmu3")]

    driver_dirs = [path for path in CMDQV_DRIVER_DIRS if is_dir_confirmed(under_root(root, path))]
    bound_devices: list[str] = []
    for path in driver_dirs:
        try:
            bound_devices.extend(
                sorted(
                    entry.name
                    for entry in under_root(root, path).iterdir()
                    if entry.is_symlink() and not entry.name.startswith(("bind", "uevent", "unbind", "module"))
                )
            )
        except OSError:
            continue

    module_dirs = [path for path in CMDQV_MODULE_DIRS if is_dir_confirmed(under_root(root, path))]
    devicetree = devicetree_has_cmdqv(root)
    # Anything that names the CMDQV driver or node is itself proof of Grace, so
    # the platform markers only have to answer for a host that exposes neither.
    grace = bool(driver_dirs or bound_devices or devicetree) or devicetree_names_grace(root) or dmi_names_grace(root)

    return {
        "machine": machine,
        "smmuv3_units": smmuv3_units,
        "iommu_units": units,
        "cmdqv_driver_dirs": driver_dirs,
        "cmdqv_bound_devices": bound_devices,
        "cmdqv_module_dirs": module_dirs,
        "cmdqv_devicetree_node": devicetree,
        "grace_platform": grace,
        "vcmdq_exposed": bool(bound_devices) or devicetree,
    }


def summarize_arm_smmu(report: dict[str, Any]) -> dict[str, Any]:
    smmu = report.get("arm_smmu", {})
    virtualization = report.get("virtualization", {})
    virtualized = virtualization.get("detected")
    machine = str(smmu.get("machine") or "")
    evidence = {"virtualization": virtualization, "arm_smmu": smmu}

    if not machine:
        return summary("unknown", "CPU architecture is not readable", evidence=evidence)
    if machine != "aarch64":
        return summary(
            "not_applicable",
            f"{machine} host; Arm SMMU command queue virtualization applies to Arm and Grace platforms only",
            evidence=evidence,
        )
    if virtualized is False:
        return summary(
            "not_applicable",
            "bare-metal Arm host; guest SMMU invalidations do not trap to a host command queue",
            evidence=evidence,
        )
    if virtualized is None:
        return summary(
            "unknown",
            "cannot determine whether this Arm host is a virtual machine guest",
            evidence=evidence,
        )
    if smmu.get("vcmdq_exposed"):
        return summary(
            "pass",
            "Arm SMMUv3 command queue virtualization (CMDQV / VCMDQ) is exposed to the guest",
            evidence=evidence,
        )
    if smmu.get("smmuv3_units"):
        if not smmu.get("grace_platform"):
            # CMDQV / VCMDQ is a Grace extension to SMMUv3. Warning about its
            # absence on a guest we could not identify as Grace would grade a
            # host against a capability its silicon cannot have. Nothing here
            # rules Grace out either, so this is inconclusive, not applicable.
            return summary(
                "unknown",
                (
                    "Arm virtual machine guest uses SMMUv3, and this vantage could not identify the "
                    "platform as Grace; CMDQV / VCMDQ exists only on Grace"
                ),
                evidence=evidence,
            )
        return summary(
            "warning",
            (
                "Arm virtual machine guest uses SMMUv3 without CMDQV / VCMDQ; "
                "guest invalidations serialize through one host command queue"
            ),
            warnings=[f"SMMUv3 unit(s) {', '.join(smmu.get('smmuv3_units') or [])} with no tegra241-cmdqv evidence"],
            evidence=evidence,
        )
    return summary(
        "unknown",
        "no Arm SMMUv3 or CMDQV evidence is readable from this guest",
        evidence=evidence,
    )


# --------------------------------------------------------------------------
# Checks 3 and 4: NCCL runtime configuration
# --------------------------------------------------------------------------


def parse_nccl_conf(text: str) -> dict[str, str]:
    """Parse /etc/nccl.conf. One ``KEY=VALUE`` per line, ``#`` starts a comment."""
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def collect_enroot_config(root: Path) -> dict[str, Any]:
    """Enroot files that could bind-mount the topology file into the container."""
    paths: list[str] = []
    mentions_topology: list[str] = []
    for relative in ("/etc/enroot/enroot.conf", "/etc/enroot/enroot.conf.d", "/etc/enroot/hooks.d", "/etc/enroot/mounts.d"):
        entry = under_root(root, relative)
        # pathlib's recursive glob swallows PermissionError, but not the rest of
        # OSError, and neither do exists() and is_dir(). This scan runs before
        # every check, so one unreadable config tree would cost all four verdicts
        # rather than this one field.
        if not exists_confirmed(entry):
            continue
        paths.append(relative)
        is_dir = is_dir_confirmed(entry)
        try:
            files = sorted(entry.rglob("*")) if is_dir else [entry]
        except OSError:
            continue
        for candidate in files:
            if file_state(candidate) is False:
                continue
            if "topo" in read_text(candidate).lower():
                mentions_topology.append(f"{relative}/{candidate.name}" if is_dir else relative)
    return {
        "present_paths": paths,
        "files_mentioning_topology": mentions_topology,
    }


def collect_rdma_devices(root: Path) -> dict[str, Any]:
    ib_dir = under_root(root, "/sys/class/infiniband")
    try:
        devices = sorted(entry.name for entry in ib_dir.iterdir())
        sysfs_read = True
    except FileNotFoundError:
        devices = []
        # A host with no RDMA driver loaded has no infiniband class directory at
        # all, so its absence is an answer. Only a vantage that cannot see
        # /sys/class in the first place leaves the question open.
        sysfs_read = sysfs_class_readable(root)
    except OSError:
        # The class directory is there and could not be read. That is a failed
        # read, not an absence, whatever /sys/class itself says.
        devices = []
        sysfs_read = False

    link_layers: list[str] = []
    for device in devices:
        ports = under_root(root, f"/sys/class/infiniband/{device}/ports")
        try:
            port_entries = sorted(ports.iterdir())
        except OSError:
            continue
        for port in port_entries:
            layer = read_text(port / "link_layer").strip()
            if layer:
                link_layers.append(layer)

    unique_layers = sorted(set(link_layers))
    return {
        "devices": devices,
        "sysfs_read": sysfs_read,
        "link_layers": unique_layers,
        "fabric": unique_layers[0] if len(unique_layers) == 1 else ("mixed" if unique_layers else "none"),
    }


def glob_topo_files(root: Path) -> list[str]:
    """Every ``/etc/nccl/*.xml`` on the host, as host-absolute paths.

    Providers do not agree on the name inside that directory, so matching the
    fixed candidate list alone misses a file that is really there and turns the
    check into a false not-applicable.
    """
    directory = under_root(root, TOPO_FILE_GLOB_DIR)
    try:
        entries = sorted(directory.glob(TOPO_FILE_GLOB))
    except OSError:
        return []
    # ``is not False`` keeps an entry the stat could not answer for. Dropping it
    # would let an unreadable entry stand for an absent file, which is the
    # asserted absence this check must never make.
    return [f"{TOPO_FILE_GLOB_DIR}/{entry.name}" for entry in entries if file_state(entry) is not False]


def describe_topo_file(path: Path) -> dict[str, Any]:
    """Size, digest, and XML well-formedness of one topology file.

    The digest is what lets the container arm tell a correctly mounted file from
    a stale or shadowed one that happens to sit at the same path.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"read": False, "error": str(exc)}
    try:
        ElementTree.fromstring(data)
        xml_ok = True
    except (ElementTree.ParseError, ValueError):
        xml_ok = False
    return {
        "read": True,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "xml_ok": xml_ok,
    }


def collect_nccl(root: Path, env: dict[str, str]) -> dict[str, Any]:
    conf_text = read_text(under_root(root, NCCL_CONF_PATH))
    conf = parse_nccl_conf(conf_text)

    env_topo = env.get("NCCL_TOPO_FILE", "")
    conf_topo = conf.get("NCCL_TOPO_FILE", "")
    declared = env_topo or conf_topo

    readable: list[str] = []
    unreachable: list[str] = []
    seen: set[str] = set()
    for candidate in (declared, *glob_topo_files(root), *TOPO_FILE_CANDIDATES):
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        state = file_state(under_root(root, candidate))
        if state:
            readable.append(candidate)
            continue
        if state is None:
            # The stat did not answer, so this vantage established neither a
            # file here nor the absence of one. That is the same reading as a
            # tree it cannot see.
            unreachable.append(candidate)
            continue
        parts = candidate.split("/")
        top = parts[1] if candidate.startswith("/") and len(parts) > 2 else ""
        if top and not is_dir_confirmed(under_root(root, f"/{top}")):
            # This vantage has no view of the tree the candidate lives in, so
            # its absence proves nothing about the host. The k8s host check
            # reads a chroot carrying only some of the host trees.
            unreachable.append(candidate)

    qps_env = env.get("NCCL_IB_QPS_PER_CONNECTION", "")
    qps_conf = conf.get("NCCL_IB_QPS_PER_CONNECTION", "")
    qps_source = "environment" if qps_env else ("nccl.conf" if qps_conf else "default")
    qps = as_int(qps_env or qps_conf, default=DEFAULT_QPS_PER_CONNECTION)

    return {
        "topo_file_env": env_topo,
        "topo_file_conf": conf_topo,
        "topo_file_declared": declared,
        "topo_files_readable": readable,
        "topo_file_evidence": {path: describe_topo_file(under_root(root, path)) for path in readable},
        "topo_candidates_unreachable": unreachable,
        "declared_topo_file_readable": bool(declared) and declared in readable,
        "nccl_conf_present": bool(conf_text),
        "qps_per_connection": qps if qps > 0 else DEFAULT_QPS_PER_CONNECTION,
        "qps_source": qps_source,
        "enroot": collect_enroot_config(root),
        "rdma": collect_rdma_devices(root),
    }


def safe_candidates(candidates: list[str]) -> list[str]:
    """Drop paths that cannot be embedded in a single-quoted shell word.

    The candidate list comes from host files and from ``NCCL_TOPO_FILE``, so it
    is site-controlled input that reaches a shell inside the container.
    """
    return [
        candidate
        for candidate in candidates
        if candidate and not any(character in candidate for character in "'\"\\ \t\n$`")
    ]


# Reading a path is not the same as resolving the file NCCL needs. This reports
# the size, the digest, and whether the bytes parse as XML, so the summary can
# tell a correct mount from an empty, truncated, or shadowed file at that path.
CONTAINER_REPORT_FUNCTION = (
    "report() {\n"
    '  path_="$1"\n'
    '  [ -r "$path_" ] || return 0\n'
    '  printf "readable=%s\\n" "$path_"\n'
    '  size_=$(wc -c < "$path_" 2>/dev/null | tr -d " ")\n'
    '  if [ -n "$size_" ]; then printf "size=%s|%s\\n" "$path_" "$size_"; fi\n'
    "  if command -v sha256sum >/dev/null 2>&1; then\n"
    '    sum_=$(sha256sum "$path_" 2>/dev/null | cut -d" " -f1)\n'
    '    if [ -n "$sum_" ]; then printf "sha256=%s|%s\\n" "$path_" "$sum_"; fi\n'
    "  fi\n"
    "  if command -v python3 >/dev/null 2>&1; then\n"
    '    if python3 -c "import sys, xml.etree.ElementTree as E; E.parse(sys.argv[1])" "$path_" '
    ">/dev/null 2>&1; then\n"
    '      printf "xml=%s|ok\\n" "$path_"\n'
    "    else\n"
    '      printf "xml=%s|bad\\n" "$path_"\n'
    "    fi\n"
    "  else\n"
    '    printf "xml=%s|unavailable\\n" "$path_"\n'
    "  fi\n"
    "}\n"
)


def container_check_script(candidates: list[str], conf_path: str = NCCL_CONF_PATH) -> str:
    """Shell run inside the benchmark container. One ``key=value`` per line.

    ``conf_path`` exists so a test can point the conf read at a fixture instead
    of the real ``/etc/nccl.conf`` of the machine running the test.
    """
    quoted = " ".join(f"'{candidate}'" for candidate in safe_candidates(candidates))
    conf = safe_candidates([conf_path])
    loop = ""
    if quoted:
        loop = f"for candidate in {quoted}; do\n" '  report "$candidate"\n' "done\n"
    # NCCL reads /etc/nccl.conf as well as the environment, so a container that
    # ships the conf resolves the topology file with no variable set. The sed
    # pair strips a trailing comment, surrounding whitespace, and one balanced
    # quote pair, which matches parse_nccl_conf for every real conf value.
    conf_block = ""
    if conf:
        conf_block = (
            f"if [ -r '{conf[0]}' ]; then\n"
            "  conf_topo=$(sed -n 's/#.*//; s/^[[:space:]]*NCCL_TOPO_FILE[[:space:]]*=[[:space:]]*//p' "
            f"'{conf[0]}'"
            " | sed -e 's/[[:space:]]*$//' -e 's/^\"\\(.*\\)\"$/\\1/' -e \"s/^'\\(.*\\)'\\$/\\1/\" | tail -n 1)\n"
            '  if [ -n "$conf_topo" ]; then\n'
            '    printf "topo_file_conf=%s\\n" "$conf_topo"\n'
            '    report "$conf_topo"\n'
            "  fi\n"
            "fi\n"
        )
    return (
        f"{CONTAINER_REPORT_FUNCTION}"
        'printf "topo_file_env=%s\\n" "${NCCL_TOPO_FILE-}"\n'
        # The container environment as NCCL sees it, kept as run-artifact
        # evidence for why the row graded the way it did.
        "env | sed -n 's/^\\(NCCL_[A-Za-z0-9_]*\\)=/nccl_env=\\1=/p' | sort | head -n 40\n"
        'if [ -n "${NCCL_TOPO_FILE-}" ]; then\n'
        '  report "${NCCL_TOPO_FILE}"\n'
        "fi\n"
        f"{conf_block}"
        f"{loop}"
        'printf "check=done\\n"\n'
    )


def parse_container_check(stdout: str) -> dict[str, Any]:
    topo_file_env = ""
    topo_file_conf = ""
    readable: list[str] = []
    evidence: dict[str, dict[str, Any]] = {}
    nccl_env: dict[str, str] = {}
    completed = False

    def field(path: str) -> dict[str, Any]:
        return evidence.setdefault(path, {})

    for line in (stdout or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep:
            continue
        if key == "topo_file_env":
            topo_file_env = value
        elif key == "topo_file_conf":
            topo_file_conf = value
        elif key == "readable":
            # NCCL_TOPO_FILE is usually also a candidate path, so the script
            # reports the same file twice.
            if value not in readable:
                readable.append(value)
        elif key in ("size", "sha256", "xml"):
            path, _, detail = value.partition("|")
            if path and detail:
                field(path)[key] = as_int(detail) if key == "size" else detail
        elif key == "nccl_env":
            name, _, setting = value.partition("=")
            if name:
                nccl_env[name] = setting
        elif key == "check" and value == "done":
            completed = True
    return {
        "topo_file_env": topo_file_env,
        "topo_file_conf": topo_file_conf,
        "topo_files_readable": readable,
        "topo_file_evidence": evidence,
        "nccl_env": nccl_env,
        "completed": completed,
    }


def check_container_image(env: dict[str, str]) -> str:
    """Image the mount check launches.

    What the check grades is whether the launcher mounts the topology file into
    the container the campaign actually runs, so the default is the same pinned
    image the Slurm benchmarks use (``CLUSTERMAX_CONTAINER_IMAGE``, set by the
    harness). ``CLUSTERMAX_PYXIS_CHECK_IMAGE`` overrides it for a site whose
    campaign image is too large to pull inside an audit window.
    """
    for name in ("CLUSTERMAX_PYXIS_CHECK_IMAGE", "CLUSTERMAX_CONTAINER_IMAGE"):
        value = (env.get(name) or "").strip()
        if value:
            return value
    return PINNED_CHECK_IMAGE


OPTION_REJECTED_MARKERS = ("unrecognized option", "invalid option", "unknown option")


def stderr_says_no_pyxis(stderr: str) -> bool:
    """Whether the launcher rejected ``--container-image`` as an unknown option.

    That rejection is the only thing in stderr that establishes the plugin is
    not loaded, and the distinction has teeth: ``no_pyxis`` is the one failure
    code excluded from the attestation-required finding, so reading a failed
    check as an absent plugin silences the note the operator needs while cluster
    access is live.

    Two things it must not read as an absent plugin. Pyxis and enroot name
    themselves in their own error output, so a message that mentions either
    proves the plugin ran and something after it failed, whether or not the
    message also echoes the flag back. And an older Slurm that rejects
    ``--overlap`` reports an unrecognized option that says nothing about pyxis,
    so the rejection has to name ``container-image`` on the same line.
    """
    lowered = stderr.lower()
    if "pyxis" in lowered or "enroot" in lowered:
        return False
    return any(
        marker in line and "container-image" in line
        for line in lowered.splitlines()
        for marker in OPTION_REJECTED_MARKERS
    )


def run_container_check(*, harness: str, env: dict[str, str], candidates: list[str], runner=run_command) -> dict[str, Any]:
    """Read NCCL_TOPO_FILE from inside a container started by the same launcher.

    Only slurm/pyxis gives the audit a container that the site's own launcher
    builds. On every other harness the check reports why it has no vantage, and
    the summary degrades to ``unknown`` instead of claiming the mount is absent.
    """
    # The harness is read before the flag. A harness with no launcher has
    # nothing for the flag to disable, and ``check_disabled`` asks the provider
    # for an attestation while ``no_launcher_on_harness`` asks for none, so
    # reading the flag first would let a skip knob invent a vendor-facing
    # finding on a harness this check does not cover.
    if harness != "slurm":
        return {
            "available": False,
            "reason_code": "no_launcher_on_harness",
            "harness": harness or "standalone",
            "reason": f"no container launcher vantage on the {harness or 'standalone'} harness",
        }
    if env.get("CLUSTERMAX_AUDIT_NCCL_CONTAINER_CHECK", "") == "0":
        return {
            "available": False,
            "reason_code": "check_disabled",
            "reason": "container check disabled by CLUSTERMAX_AUDIT_NCCL_CONTAINER_CHECK=0",
        }
    if not env.get("SLURM_JOB_ID"):
        return {
            "available": False,
            "reason_code": "no_allocation",
            "reason": "SLURM_JOB_ID is not set; run the audit inside an allocation",
        }
    if runner is run_command and not shutil.which("srun"):
        return {
            "available": False,
            "reason_code": "no_srun",
            "reason": "srun is not on PATH; pyxis/enroot cannot be exercised from this vantage",
        }

    image = check_container_image(env)
    timeout = as_int(env.get("CLUSTERMAX_PYXIS_CHECK_TIMEOUT_S"), default=600)
    # No --container-mounts and no --mount. The subject of the check is whether
    # the site's own launcher carries the topology file in by itself, so a bind
    # mount added here would manufacture the pass it is looking for.
    command = [
        "srun",
        "--overlap",
        "-N",
        "1",
        "--ntasks=1",
        f"--container-image={image}",
        "--no-container-mount-home",
        "--container-remap-root",
        "--no-container-entrypoint",
        "/bin/sh",
        "-c",
        container_check_script(candidates),
    ]
    attestation = {
        "image": image,
        "container_mounts_added": False,
        # Everything but the script body, so a reader can confirm from the
        # artifact that no mount flag was passed.
        "launcher_argv": command[:-1],
    }
    try:
        proc = runner(command, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        # A busy allocation or a failed image pull left the question open. PR
        # #1357: an attempt that did not run is not a reading of the mount.
        return {
            "available": False,
            "reason_code": "launch_failed",
            "reason": f"pyxis container check did not run ({exc}); the mount is unverified, not absent",
            **attestation,
        }

    parsed = parse_container_check(proc.stdout)
    if not parsed["completed"]:
        stderr = (proc.stderr or "").strip()[:2000]
        if stderr_says_no_pyxis(stderr):
            reason_code = "no_pyxis"
            reason = "pyxis/enroot is not installed on this cluster; the container arm of this check does not apply"
        else:
            reason_code = "check_incomplete"
            reason = f"pyxis container check exited {proc.returncode} without completing"
        return {
            "available": False,
            "reason_code": reason_code,
            "reason": reason,
            "stderr": stderr,
            **attestation,
        }
    return {"available": True, "stdout": (proc.stdout or "").strip()[:8000], **attestation, **parsed}


def vantage_is_local_only(reports: list[dict[str, Any]]) -> bool:
    """Whether every report came from a stand-in host rather than from the fabric.

    When the Slurm fan-out cannot run, or Kubernetes lists no GPU node, the check
    falls back to reading wherever it happens to be and stamps that report
    ``check_scope: local``. That vantage is usually a login or control node, which
    holds no topology file and no RDMA adapter, so letting it answer for the
    cluster would clear the checks from a machine that is not on the fabric. Only
    the fan-out harnesses stamp the flag, so a standalone host, which really is
    the whole cluster, is never local-only.
    """
    return bool(reports) and all(report.get("check_scope") == "local" for report in reports)


def summarize_nccl_topo_file(
    *,
    reports: list[dict[str, Any]],
    container: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    hosts = [report.get("nccl", {}) for report in reports]
    declared = next((host.get("topo_file_declared") for host in hosts if host.get("topo_file_declared")), "")
    host_env = next((host.get("topo_file_env") for host in hosts if host.get("topo_file_env")), "")
    host_files = sorted({path for host in hosts for path in (host.get("topo_files_readable") or [])})
    enroot_hooks = sorted({path for host in hosts for path in (host.get("enroot", {}).get("files_mentioning_topology") or [])})
    host_evidence: dict[str, Any] = {}
    for host in hosts:
        host_evidence.update(host.get("topo_file_evidence") or {})

    detail: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hosts_checked": len(reports),
        "host_topo_file_declared": declared,
        "host_topo_file_env": host_env,
        "host_topo_files_readable": host_files,
        "host_topo_file_evidence": host_evidence,
        "enroot_files_mentioning_topology": enroot_hooks,
        "container": container,
        "warnings": list(errors),
        "failures": [],
    }

    if not reports:
        # Every host check failing looks exactly like a clean read that found no
        # topology file. This is the only check that can hard-fail, so an empty
        # read must never clear it.
        detail.update(
            status="unknown",
            message="no host was checked; whether a NCCL topology file is present is not known",
        )
        return detail

    if not host_files:
        # A declaration is not a file. A stale NCCL_TOPO_FILE or nccl.conf entry
        # pointing at a path that holds nothing leaves nothing to mount, so the
        # check has no subject and must not hard-fail on a missing mount.
        unreachable = sorted({path for host in hosts for path in (host.get("topo_candidates_unreachable") or [])})
        if unreachable:
            # A path the vantage cannot reach is not a path with no file on it.
            detail["unreachable_topo_candidates"] = unreachable
            detail.update(
                status="unknown",
                message=(
                    "no NCCL topology file was found, but this vantage cannot reach "
                    f"{', '.join(unreachable)}; absence is not established"
                ),
            )
            return detail
        if vantage_is_local_only(reports):
            detail.update(
                status="unknown",
                message=(
                    "no GPU host was checked; the local host holds no NCCL topology file, "
                    "which says nothing about the compute nodes"
                ),
            )
            return detail
        detail.update(
            status="not_applicable",
            message="no NCCL topology file on the hosts; NCCL uses automatic detection",
        )
        return detail

    if not container.get("available"):
        detail.update(
            status="unknown",
            message=(
                f"a NCCL topology file is on the host but the container was not inspected: "
                f"{container.get('reason', 'no container vantage')}"
            ),
        )
        return detail

    container_env = str(container.get("topo_file_env") or "")
    container_conf = str(container.get("topo_file_conf") or "")
    container_files = list(container.get("topo_files_readable") or [])
    container_evidence = container.get("topo_file_evidence") or {}
    target = declared if declared in host_files else host_files[0]
    # NCCL resolves the topology file in three steps: NCCL_TOPO_FILE, then the
    # same name in /etc/nccl.conf, then its built-in default path. A container
    # that carries the file to the default path declares nothing and still
    # resolves it, so all three count.
    container_declared = container_env or container_conf
    if container_declared:
        source = TOPO_SOURCE_ENV if container_env else TOPO_SOURCE_CONF
        resolved = container_declared in container_files
    elif NCCL_DEFAULT_TOPO_FILE in container_files:
        container_declared = NCCL_DEFAULT_TOPO_FILE
        source = TOPO_SOURCE_DEFAULT
        resolved = True
    else:
        source = ""
        resolved = False

    # Which of NCCL's three resolution steps produced the file, and the path it
    # produced, so a consumer does not read the message to learn either.
    detail["container_topo_file"] = container_declared
    detail["container_topo_file_source"] = source

    failures: list[str] = []

    # Propagation is only a question when the host set the variable in the first
    # place. A launcher that drops it silences every NCCL setting the job made,
    # not only this one.
    if host_env and not container_env:
        failures.append(
            f"the host sets NCCL_TOPO_FILE={host_env} but the container environment does not carry it; "
            "the launcher does not propagate the job environment into the container"
        )

    if not resolved:
        if container_declared:
            failures.append(
                f"container declares NCCL topology file {container_declared} in {TOPO_SOURCE_LABELS[source]} but the "
                "file is not readable inside the container; NCCL falls back to automatic detection without a warning"
            )
        else:
            failures.append(
                f"host has NCCL topology file {target} but the container sets NCCL_TOPO_FILE in neither "
                f"the environment nor {NCCL_CONF_PATH}, and has no readable {NCCL_DEFAULT_TOPO_FILE}; "
                "the file is not mounted automatically and NCCL falls back to automatic detection without a warning"
            )
    else:
        # A path that opens is not yet the file NCCL needs. An empty or
        # unparseable file makes NCCL fall back just as silently as a missing
        # one, and a digest that differs from the host's is a stale or shadowed
        # copy rather than the topology this host actually has.
        seen = container_evidence.get(container_declared) or {}
        if seen.get("size") == 0:
            failures.append(f"container resolves {container_declared} but the file is empty")
        if seen.get("xml") == "bad":
            failures.append(f"container resolves {container_declared} but its contents do not parse as XML")
        # A topology file describes the node it was generated for, so two nodes
        # legitimately publish different content at the same path. The container
        # runs on one node of the allocation and these reports cover the
        # allocation, so a digest matching any checked node is the file some node
        # really published, and comparing against a single last-writer-wins host
        # would hard-fail that healthy cluster as a shadowed mount. Only content
        # no checked node published is shadowing, and only when every node
        # published a digest at this path: otherwise the container may have run
        # on the node whose file this vantage never read.
        host_digests: set[str] = set()
        host_missing_digest = False
        for host in hosts:
            digest = ((host.get("topo_file_evidence") or {}).get(container_declared) or {}).get("sha256")
            if digest:
                host_digests.add(digest)
            else:
                host_missing_digest = True
        detail["host_topo_file_digests"] = sorted(host_digests)
        container_digest = seen.get("sha256")
        if container_digest and host_digests and not host_missing_digest and container_digest not in host_digests:
            failures.append(
                f"container resolves {container_declared} but its contents match no checked host's file at that "
                "path; the container sees a stale or shadowed topology file"
            )

    if failures:
        detail["failures"] = [*failures, TOPO_REMEDIATION]
        detail.update(status="fail", message=failures[0])
        return detail

    detail.update(
        status="pass",
        message=f"container resolves NCCL topology file {container_declared} from {TOPO_SOURCE_LABELS[source]}",
    )
    return detail


def classify_fabric_shape(*, fabric_tiers: int, node_count: int, clos_node_threshold: int) -> tuple[bool | None, str]:
    """Whether the fabric has a spine tier, and the evidence that decided it.

    An exact tier count wins. Without one the GPU node count stands in, because
    a fabric wider than one leaf switch has to have a spine. Neither reading
    available returns ``None``: unknown shape, never assumed flat.
    """
    if fabric_tiers >= 2:
        return True, f"topology ({fabric_tiers} tiers)"
    if fabric_tiers == 1:
        return False, "topology (single tier)"
    if node_count > clos_node_threshold:
        return True, f"node count ({node_count} > {clos_node_threshold})"
    if node_count > 0:
        return False, f"node count ({node_count} <= {clos_node_threshold})"
    return None, "no topology or node-count data"


def summarize_nccl_ib_qps(
    *,
    reports: list[dict[str, Any]],
    node_count: int,
    node_count_scope: str,
    fabric_tiers: int,
    clos_node_threshold: int,
    errors: list[str],
) -> dict[str, Any]:
    hosts = [report.get("nccl", {}) for report in reports]
    qps_values = sorted({as_int(host.get("qps_per_connection"), DEFAULT_QPS_PER_CONNECTION) for host in hosts})
    qps = qps_values[0] if qps_values else DEFAULT_QPS_PER_CONNECTION
    source = next((host.get("qps_source") for host in hosts if host.get("qps_source")), "default")
    fabrics = sorted({str(host.get("rdma", {}).get("fabric") or "none") for host in hosts})
    rdma_devices = sorted({device for host in hosts for device in (host.get("rdma", {}).get("devices") or [])})
    # "No host has an RDMA device" is a claim about every host, so one host that
    # could not be read withdraws it. A sibling that read a clean empty class
    # says nothing about the host nobody could read.
    unread_hosts = sum(1 for host in hosts if not host.get("rdma", {}).get("sysfs_read", True))
    multi_tier, basis = classify_fabric_shape(
        fabric_tiers=fabric_tiers,
        node_count=node_count,
        clos_node_threshold=clos_node_threshold,
    )

    detail: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hosts_checked": len(reports),
        "qps_per_connection": qps,
        "qps_source": source,
        "qps_values_seen": qps_values,
        "recommended_qps_per_connection": RECOMMENDED_QPS_PER_CONNECTION,
        "node_count": node_count,
        "node_count_scope": node_count_scope,
        "fabric_tiers": fabric_tiers,
        "clos_node_threshold": clos_node_threshold,
        "multi_tier": multi_tier,
        "fabric_shape_basis": basis,
        "rdma_devices": rdma_devices,
        "rdma_sysfs_unread_hosts": unread_hosts,
        "fabric": fabrics[0] if len(fabrics) == 1 else ("mixed" if fabrics else "none"),
        "warnings": list(errors),
        "failures": [],
    }

    if not reports:
        # Every host check failing reads the same as a clean look that found no
        # adapter. The k8s check can return nothing while GPU nodes exist.
        detail.update(
            status="unknown",
            message="no host was checked; RDMA device presence is not known",
        )
        return detail

    if not rdma_devices:
        if unread_hosts:
            detail.update(
                status="unknown",
                message=(
                    f"/sys/class/infiniband is not readable on {unread_hosts} of {len(hosts)} checked host(s); "
                    "RDMA device presence is unknown"
                ),
            )
            return detail
        if vantage_is_local_only(reports):
            detail.update(
                status="unknown",
                message=(
                    "no GPU host was checked; the local host has no RDMA device, "
                    "which says nothing about the compute nodes"
                ),
            )
            return detail
        detail.update(
            status="not_applicable",
            message="no RDMA device on the checked hosts; NCCL_IB_QPS_PER_CONNECTION has no effect",
        )
        return detail
    if multi_tier is None:
        detail.update(status="unknown", message=f"cannot judge the fabric shape: {basis}")
        return detail

    if not multi_tier and fabric_tiers == 0 and node_count_scope != "cluster":
        # A small allocation is not a small fabric. Reading the shape from the
        # allocation would clear a 512-node Clos from a two-node audit job.
        detail.update(
            status="unknown",
            message=(
                f"NCCL_IB_QPS_PER_CONNECTION={qps} on a {node_count}-node {node_count_scope} with no "
                "topology data; the shape of the whole fabric is not known, so the advisory cannot be judged"
            ),
        )
        return detail

    if not multi_tier:
        # One tier gives ECMP nothing to spread across, so extra queue pairs buy
        # no entropy and the advisory has no subject on this fabric.
        detail.update(
            status="not_applicable",
            message=(
                f"no spine tier by {basis}; extra queue pairs add no ECMP entropy, "
                f"so NCCL_IB_QPS_PER_CONNECTION={qps} is not graded"
            ),
        )
        return detail

    if qps >= RECOMMENDED_QPS_PER_CONNECTION:
        detail.update(
            status="pass",
            message=f"NCCL_IB_QPS_PER_CONNECTION={qps} from {source} on a multi-tier Clos fabric by {basis}",
        )
        return detail

    warning = (
        f"NCCL_IB_QPS_PER_CONNECTION={qps} (the default) on a multi-tier Clos fabric by {basis}; "
        f"one queue pair gives ECMP a single hash input, so parallel flows collide on the same spine uplink. "
        f"Set it to {RECOMMENDED_QPS_PER_CONNECTION} (up to 4) identically on every rank, for example in "
        f"{NCCL_CONF_PATH}. Sweep the value at the message sizes of the real workload before you fix it, "
        "because the best value depends on the fabric and adds CPU cost"
    )
    detail["warnings"].append(warning)
    detail.update(status="warning", message=warning)
    return detail


# --------------------------------------------------------------------------
# Host collection and aggregation
# --------------------------------------------------------------------------


def summary(
    status: str,
    message: str,
    *,
    failures: list[str] | None = None,
    warnings: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One per-host verdict.

    ``evidence`` carries the raw reading the verdict came from. The aggregate
    keeps it per host, so a finding reported to a provider can be checked
    against the values the check actually saw.
    """
    return {
        "status": status,
        "message": message,
        "failures": failures or [],
        "warnings": warnings or [],
        "evidence": evidence or {},
    }


def collect_host(
    *,
    root: Path = Path("/"),
    harness: str = "",
    machine: str | None = None,
    env: dict[str, str] | None = None,
    hostname: str = "",
    runner=run_command,
    include_scale_out: bool = True,
    include_rdma_iommu: bool | None = None,
) -> dict[str, Any]:
    env = dict(os.environ if env is None else env)
    machine = platform.machine() if machine is None else machine
    if include_rdma_iommu is None:
        include_rdma_iommu = include_scale_out

    report: dict[str, Any] = {
        "host": hostname or env.get("NODE_NAME") or socket.gethostname(),
        "harness": harness,
        "machine": machine,
        "virtualization": detect_virtualization(root, runner=runner),
        "iommu": collect_iommu(root, include_rdma=include_rdma_iommu),
        "arm_smmu": collect_arm_smmu(root, machine),
        "nccl": collect_nccl(root, env) if include_scale_out else {},
    }
    report["summaries"] = {
        "vm_iommu": summarize_vm_iommu(report),
        "arm_smmu_virtualization": summarize_arm_smmu(report),
    }
    return report


def aggregate_check(key: str, reports: list[dict[str, Any]], errors: list[str]) -> dict[str, Any]:
    """Fold one per-host summary across hosts.

    ``warning`` beats ``pass``, and a host that reports ``not_applicable`` never
    drags an applicable host down. When no host could judge the check the result
    is ``unknown``, never ``fail``.

    ``unknown`` outranks ``not_applicable`` because ``not_applicable`` asserts
    that no host has a subject for this check, and a host nobody could read
    cannot support that. ``pass`` still outranks ``unknown``: it reports what
    the hosts that were read actually have, and every per-host status stays
    visible under ``hosts``.
    """
    statuses = [str(report.get("summaries", {}).get(key, {}).get("status") or "unknown") for report in reports]
    if "fail" in statuses:
        status = "fail"
    elif "warning" in statuses:
        status = "warning"
    elif "pass" in statuses:
        status = "pass"
    elif "unknown" in statuses:
        status = "unknown"
    elif "not_applicable" in statuses:
        status = "not_applicable"
    else:
        status = "unknown"

    failures = [
        f"{report.get('host', 'unknown')}: {item}"
        for report in reports
        for item in report.get("summaries", {}).get(key, {}).get("failures", [])
    ]
    warnings = [
        f"{report.get('host', 'unknown')}: {item}"
        for report in reports
        for item in report.get("summaries", {}).get(key, {}).get("warnings", [])
    ]
    warnings.extend(errors)

    message = ""
    for report in reports:
        host_summary = report.get("summaries", {}).get(key, {})
        if str(host_summary.get("status")) == status:
            message = f"{report.get('host', 'unknown')}: {host_summary.get('message', '')}"
            break
    if not message:
        message = f"{key} was not evaluated on any host"

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "message": message,
        "failures": failures,
        "warnings": warnings,
        "hosts_checked": len(reports),
        "hosts": {
            str(report.get("host") or f"host-{index}"): report.get("summaries", {}).get(key, {})
            for index, report in enumerate(reports)
        },
    }


def build_payload(
    *,
    reports: list[dict[str, Any]],
    errors: list[str],
    container: dict[str, Any],
    node_count: int,
    node_count_scope: str = "cluster",
    fabric_tiers: int = 0,
    clos_node_threshold: int = DEFAULT_CLOS_NODE_THRESHOLD,
) -> dict[str, Any]:
    payload = {key: aggregate_check(key, reports, errors) for key in CHECK_KEYS}
    if vantage_is_local_only(reports):
        # A stand-in host's platform identity is not the fabric's either. A
        # bare-metal login node in front of a virtualized GB200 fabric would
        # otherwise clear both rows for compute nodes nobody read, and a login
        # node that happens to be a VM with passthrough would clear them the
        # same way. A warning is kept: a stand-in that reads badly still read
        # badly, and the finding names a host that really has the fault.
        for key in CHECK_KEYS:
            if payload[key]["status"] in ("pass", "not_applicable"):
                payload[key].update(
                    status="unknown",
                    message="only a stand-in host was checked; the platform of the compute nodes was not read",
                )
    payload["nccl_topo_file"] = summarize_nccl_topo_file(reports=reports, container=container, errors=errors)
    payload["nccl_ib_qps"] = summarize_nccl_ib_qps(
        reports=reports,
        node_count=node_count,
        node_count_scope=node_count_scope,
        fabric_tiers=fabric_tiers,
        clos_node_threshold=clos_node_threshold,
        errors=errors,
    )
    return payload


# --------------------------------------------------------------------------
# Harness fan-out
# --------------------------------------------------------------------------


def gres_names_gpu(gres: str) -> bool:
    """Whether a Slurm gres field advertises a GPU.

    A gres field is a comma-separated list whose entries lead with the resource
    name, as in ``gpu:h100:8(S:0-1)``. A node with none reads ``(null)``.
    """
    return any(entry.strip().split(":", 1)[0].strip().lower() == "gpu" for entry in gres.split(","))


def parse_sinfo_gpu_nodes(stdout: str) -> tuple[list[str], int]:
    """GPU node names, and the total node count, from ``sinfo -h -N -o '%n %G'``.

    sinfo prints one line per node per partition, so a node in two partitions
    appears twice. The queue-pair advisory is about the RDMA fabric the GPUs
    sit on, so login, storage, and other CPU nodes must not inflate its scale.
    sinfo pads its columns, so the fields are split on whitespace.
    """
    gpu_names: set[str] = set()
    all_names: set[str] = set()
    for line in stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        all_names.add(fields[0])
        if gres_names_gpu(" ".join(fields[1:])):
            gpu_names.add(fields[0])
    return sorted(gpu_names), len(all_names)


def slurm_cluster_node_count() -> tuple[int, list[str]]:
    """GPU node count of the whole Slurm cluster, not of the current allocation.

    The queue-pair advisory is about the fabric, and the documented audit
    allocation is two nodes, so the allocation size cannot stand in for it.
    """
    try:
        proc = run_command(["sinfo", "-h", "-N", "-o", "%n %G"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return 0, [f"sinfo failed; the fabric size is not known: {exc}"]
    if proc.returncode != 0:
        return 0, [f"sinfo exited {proc.returncode}; the fabric size is not known"]
    gpu_nodes, total_nodes = parse_sinfo_gpu_nodes(proc.stdout)
    if gpu_nodes:
        return len(gpu_nodes), []
    if total_nodes:
        # A site that does not configure gres reads exactly like a cluster with
        # no GPUs, so a zero here is not a reading that no GPU fabric exists.
        # Counting the CPU nodes instead would size an RDMA fabric from hardware
        # that is not on it. Report no count, so the caller falls back to the
        # allocation and the advisory grades unknown rather than passing.
        return 0, [
            f"none of the {total_nodes} node(s) sinfo reported advertises GPU gres; "
            "the size of the GPU fabric is not known"
        ]
    return 0, ["sinfo reported no nodes; the fabric size is not known"]


def count_fabric_tiers(text: str) -> int:
    """Tier count of a Slurm fabric topology dump. ``0`` when there is no data.

    ``scontrol show topology`` labels every switch with ``Level=N``, so the tier
    count is ``max(Level) + 1`` and is exact. A raw ``topology.conf`` /
    ``topology.yaml`` carries no levels, so the fallback is deliberately coarse:
    a switch that lists child switches proves at least two tiers, and so do
    several sibling leaves with no parent line, because something has to
    interconnect them. The ``topology/block`` plugin emits exactly that shape -
    repeated ``BlockName=... Nodes=...`` with no ``Level=`` and no
    ``Switches=`` - and it is common on GB200 / GB300 fabrics, so reading it as
    a single tier would quietly exempt the largest Clos fabrics from the check.
    Only a lone switch that lists nodes is a genuine single leaf tier.

    Bracket ranges in child names (``Switches=leaf[0-15]``) make a real graph
    walk unreliable, so two is reported as a minimum rather than a guess at three.
    In ``topology.yaml`` the hierarchy key is ``children:``; ``switches:`` only
    opens the list of switch objects and says nothing about depth.
    """
    max_level = -1
    switch_count = 0
    has_child_switch = False
    has_leaf = False
    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0]
        if not line.strip():
            continue
        level = re.search(r"Level=(\d+)", line)
        if level:
            max_level = max(max_level, int(level.group(1)))
            continue
        if re.search(r"SwitchName=|BlockName=|^\s*-\s*switch:|^\s*-\s*block:", line):
            switch_count += 1
        if re.search(r"Switches=|^\s*children:", line):
            has_child_switch = True
        if re.search(r"Nodes=|^\s*nodes:", line):
            has_leaf = True
    if max_level >= 0:
        return max_level + 1
    if has_child_switch or switch_count > 1:
        return 2
    if switch_count or has_leaf:
        return 1
    return 0


def slurm_fabric_tiers() -> tuple[int, list[str]]:
    """Tier count of the Slurm fabric, from ``scontrol`` or a topology file.

    A cluster with no topology plugin configured is not an error and not a
    single-tier fabric: it reports ``0``, and the queue-pair summary falls back
    to the node-count threshold rather than grading from a shape it never read.
    """
    try:
        proc = run_command(["scontrol", "show", "topology"], timeout=30)
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and proc.returncode == 0:
        tiers = count_fabric_tiers(proc.stdout)
        if tiers:
            return tiers, []

    for path in SLURM_TOPOLOGY_FILES:
        text = read_text(Path(path))
        tiers = count_fabric_tiers(text)
        if tiers:
            return tiers, []
    return 0, ["no Slurm topology data; the fabric tier count is not known"]


def run_slurm_check(
    harness: str,
    *,
    include_scale_out: bool = True,
    include_rdma_iommu: bool = True,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not os.environ.get("SLURM_JOB_ID"):
        report = collect_host(
            root=Path("/"),
            harness=harness,
            include_scale_out=include_scale_out,
            include_rdma_iommu=include_rdma_iommu,
        )
        report["check_scope"] = "local"
        return [report], ["SLURM_JOB_ID is not set; the platform check only checked the local host"]

    node_count = os.environ.get("SLURM_NNODES") or "1"
    command = [
        "srun",
        "--overlap",
        "-N",
        node_count,
        "--ntasks-per-node=1",
        sys.executable,
        str(Path(__file__).resolve()),
        "--collect-host",
        "--harness",
        harness,
    ]
    if not include_scale_out:
        command.append("--skip-scale-out")
    if not include_rdma_iommu:
        command.append("--skip-rdma-iommu")
    try:
        proc = run_command(command, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        report = collect_host(
            root=Path("/"),
            harness=harness,
            include_scale_out=include_scale_out,
            include_rdma_iommu=include_rdma_iommu,
        )
        report["check_scope"] = "local"
        return [report], [f"srun host check failed; local host only: {exc}"]

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    if proc.returncode != 0:
        errors.append(f"srun host check exited {proc.returncode}; parsing any completed host output")
    for value in load_fanout().parse_json_lines(proc.stdout, require_host=True):
        reports.append(value)
    if proc.stderr and (proc.returncode != 0 or not reports):
        errors.append(proc.stderr.strip())
    if not reports:
        report = collect_host(
            root=Path("/"),
            harness=harness,
            include_scale_out=include_scale_out,
            include_rdma_iommu=include_rdma_iommu,
        )
        report["check_scope"] = "local"
        reports.append(report)
        errors.append("srun host check returned no host JSON; local host only")
    return reports, errors


def kubectl(command: list[str], *, timeout: int = 60, input_text: str | None = None):
    return run_command(["kubectl", *command], timeout=timeout, input_text=input_text)


def pod_manifest(namespace: str, node: dict[str, Any], image: str, pod_name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "clustermax-platform-audit"},
        },
        "spec": {
            "restartPolicy": "Never",
            "nodeName": node["name"],
            "hostPID": True,
            "tolerations": [{"operator": "Exists"}],
            "containers": [
                {
                    "name": "check",
                    "image": image,
                    "imagePullPolicy": os.environ.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_PULL_POLICY", "IfNotPresent"),
                    "command": ["sh", "-c", "sleep 600"],
                    "env": [{"name": "NODE_NAME", "value": node["name"]}],
                    "securityContext": {"privileged": True, "runAsUser": 0},
                    "volumeMounts": [
                        {"name": "host-proc", "mountPath": "/host/proc", "readOnly": True},
                        {"name": "host-sys", "mountPath": "/host/sys", "readOnly": True},
                        {"name": "host-etc", "mountPath": "/host/etc", "readOnly": True},
                        # nvidia-topologyd writes the topology file under
                        # /var/run, which is where NCCL looks when nothing
                        # declares one. Without this the check reads an empty
                        # tree and calls the file absent.
                        {"name": "host-var-run", "mountPath": "/host/var/run", "readOnly": True},
                    ],
                }
            ],
            "volumes": [
                {"name": "host-proc", "hostPath": {"path": "/proc"}},
                {"name": "host-sys", "hostPath": {"path": "/sys"}},
                {"name": "host-etc", "hostPath": {"path": "/etc"}},
                {"name": "host-var-run", "hostPath": {"path": "/var/run"}},
            ],
        },
    }


def run_k8s_host_check(
    namespace: str,
    node: dict[str, Any],
    image: str,
    *,
    include_scale_out: bool = True,
    include_rdma_iommu: bool = True,
) -> tuple[dict[str, Any] | None, str | None]:
    pod_name = f"clustermax-platform-{uuid.uuid4().hex[:8]}"
    manifest = json.dumps(pod_manifest(namespace, node, image, pod_name))
    try:
        apply_proc = kubectl(["apply", "-f", "-"], timeout=45, input_text=manifest)
        if apply_proc.returncode != 0:
            return None, f"{node['name']}: failed to create host check pod: {apply_proc.stderr.strip()}"

        wait_proc = kubectl(
            ["wait", f"pod/{pod_name}", "-n", namespace, "--for=condition=Ready", "--timeout=90s"],
            timeout=100,
        )
        if wait_proc.returncode != 0:
            return None, f"{node['name']}: host check pod did not become Ready: {wait_proc.stderr.strip()}"

        check_args = [
            "exec",
            "-i",
            "-n",
            namespace,
            pod_name,
            "--",
            "python3",
            "-",
            "--collect-host",
            "--root",
            "/host",
            "--harness",
            "k8s",
        ]
        if not include_scale_out:
            check_args.append("--skip-scale-out")
        if not include_rdma_iommu:
            check_args.append("--skip-rdma-iommu")
        exec_proc = kubectl(
            check_args,
            timeout=60,
            input_text=Path(__file__).read_text(),
        )
        if exec_proc.returncode != 0:
            return None, f"{node['name']}: host check exec failed: {exec_proc.stderr.strip()}"
        for line in exec_proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                return value, None
        return None, f"{node['name']}: host check returned no JSON"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return None, f"{node['name']}: host check failed: {exc}"
    finally:
        try:
            kubectl(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=false"], timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


def k8s_gpu_node_list() -> tuple[list[dict[str, Any]], list[str]]:
    try:
        nodes_proc = kubectl(["get", "nodes", "-o", "json"], timeout=45)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], [f"kubectl get nodes failed: {exc}"]
    if nodes_proc.returncode != 0:
        return [], [f"kubectl get nodes failed: {nodes_proc.stderr.strip()}"]
    try:
        nodes_json = json.loads(nodes_proc.stdout)
    except json.JSONDecodeError as exc:
        return [], [f"kubectl get nodes returned invalid JSON: {exc}"]
    nodes = load_fanout().k8s_gpu_nodes(nodes_json)
    if not nodes:
        return [], ["no Kubernetes nodes advertise nvidia.com/gpu capacity"]
    return nodes, []


def run_k8s_check(
    nodes: list[dict[str, Any]],
    *,
    include_scale_out: bool = True,
    include_rdma_iommu: bool = True,
) -> tuple[list[dict[str, Any]], list[str]]:
    namespace = os.environ.get("CLUSTERMAX_AUDIT_K8S_NAMESPACE", "default")
    image = os.environ.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE", "python:3.12-alpine")
    max_nodes = as_int(os.environ.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"), default=len(nodes))
    return load_fanout().fan_out_k8s(
        lambda node: run_k8s_host_check(
            namespace,
            node,
            image,
            include_scale_out=include_scale_out,
            include_rdma_iommu=include_rdma_iommu,
        ),
        nodes=nodes,
        max_nodes=max_nodes,
    )


def run_default_check(
    harness: str, requested_keys: set[str] | None = None
) -> dict[str, Any]:
    requested = set(ALL_CHECK_KEYS if requested_keys is None else requested_keys)
    unknown = requested.difference(ALL_CHECK_KEYS)
    if unknown:
        raise ValueError(
            f"unknown platform configuration check(s): {', '.join(sorted(unknown))}"
        )
    include_scale_out = bool(
        requested.intersection({"nccl_topo_file", "nccl_ib_qps"})
    )
    include_rdma_iommu = "vm_iommu" in requested and harness != "standalone"
    errors: list[str] = []
    node_count = 1
    node_count_scope = "cluster"
    # Only Slurm publishes a fabric topology the audit can read. On every other
    # harness the tier count stays 0 and the queue-pair advisory grades from the
    # GPU node count instead.
    fabric_tiers = 0

    if harness == "slurm":
        reports, errors = run_slurm_check(
            harness,
            include_scale_out=include_scale_out,
            include_rdma_iommu=include_rdma_iommu,
        )
        if "nccl_ib_qps" in requested:
            node_count, sinfo_errors = slurm_cluster_node_count()
            if node_count <= 0:
                node_count = as_int(
                    os.environ.get("SLURM_NNODES"),
                    default=len(reports),
                )
                node_count_scope = "allocation"
                errors = [*errors, *sinfo_errors]
            fabric_tiers, topology_errors = slurm_fabric_tiers()
            if not fabric_tiers:
                errors = [*errors, *topology_errors]
    elif harness == "k8s":
        nodes, discovery_errors = k8s_gpu_node_list()
        node_count = len(nodes)
        if nodes:
            reports, errors = run_k8s_check(
                nodes,
                include_scale_out=include_scale_out,
                include_rdma_iommu=include_rdma_iommu,
            )
            errors = [*discovery_errors, *errors]
        else:
            report = collect_host(
                root=Path("/"),
                harness=harness,
                include_scale_out=include_scale_out,
                include_rdma_iommu=include_rdma_iommu,
            )
            report["check_scope"] = "local"
            reports = [report]
            errors = [*discovery_errors, "no GPU node was checked; the local host was checked instead"]
    else:
        reports = [
            collect_host(
                root=Path("/"),
                harness=harness,
                include_scale_out=include_scale_out and harness != "standalone",
                include_rdma_iommu=include_rdma_iommu,
            )
        ]

    # Only a file a host actually holds gives the container arm a subject. A
    # declaration pointing at nothing grades not_applicable whatever the
    # container says, so it must not start one.
    host_topo_files = sorted(
        {
            path
            for report in reports
            for path in (
                report.get("nccl", {}).get("topo_files_readable") or []
            )
        }
    ) if "nccl_topo_file" in requested else []
    topo_candidates = sorted(
        {
            path
            for report in reports
            for path in [*host_topo_files, report.get("nccl", {}).get("topo_file_declared") or ""]
            if path
        }
    )

    if harness == "slurm" and host_topo_files:
        # The default path is checked too even when no host holds the file there,
        # because a mounts.d entry can carry the host file to it.
        container = run_container_check(
            harness=harness,
            env=dict(os.environ),
            candidates=sorted({*topo_candidates, NCCL_DEFAULT_TOPO_FILE}),
        )
    else:
        # Without a host topology file the check is not applicable whatever the
        # container says, and a Pyxis start is a cold image pull that can run to
        # the full check timeout.
        container = {
            "available": False,
            "reason_code": "no_host_topo_file",
            "reason": "no readable NCCL topology file on the checked hosts; the container check was skipped",
        }
    threshold = as_int(os.environ.get("CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD"), default=DEFAULT_CLOS_NODE_THRESHOLD)
    payload = build_payload(
        reports=reports,
        errors=errors,
        container=container,
        node_count=node_count,
        node_count_scope=node_count_scope,
        fabric_tiers=fabric_tiers,
        clos_node_threshold=threshold if threshold > 0 else DEFAULT_CLOS_NODE_THRESHOLD,
    )
    if harness != "slurm":
        payload.pop("nccl_topo_file", None)
    if harness == "standalone":
        payload.pop("nccl_ib_qps", None)
    return {key: payload[key] for key in requested if key in payload}


def run_named_check(check_key: str, harness: str) -> dict[str, Any]:
    """Run one public check and reuse host collection within one audit run."""
    if check_key not in ALL_CHECK_KEYS:
        raise ValueError(f"unknown platform configuration check: {check_key}")

    payload: dict[str, Any] | None = None
    cache_value = os.environ.get(CACHE_PATH_ENV, "")
    cache_path = Path(cache_value) if cache_value else None
    if cache_path is not None:
        try:
            cached = json.loads(cache_path.read_text())
        except (OSError, json.JSONDecodeError):
            cached = None
        if (
            isinstance(cached, dict)
            and cached.get("harness") == harness
            and isinstance(cached.get("payload"), dict)
        ):
            payload = cached["payload"]

    if payload is None:
        requested_value = os.environ.get(REQUESTED_CHECKS_ENV, "")
        requested = {
            key.strip()
            for key in requested_value.split(",")
            if key.strip()
        } or {check_key}
        payload = run_default_check(harness, requested)
        if cache_path is not None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = cache_path.with_suffix(f"{cache_path.suffix}.tmp")
            temporary.write_text(
                json.dumps({"harness": harness, "payload": payload}, sort_keys=True)
            )
            os.replace(temporary, cache_path)

    result = payload.get(check_key)
    return {check_key: result} if isinstance(result, dict) else {}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Shared platform configuration collection")
    parser.add_argument("--collect-host", action="store_true", help="emit one host report instead of aggregate check JSON")
    parser.add_argument("--root", default="/", help="host root path for proc/sys/etc reads")
    parser.add_argument("--harness", default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone"))
    parser.add_argument(
        "--skip-scale-out",
        action="store_true",
        help="omit NCCL and RDMA host collection",
    )
    parser.add_argument(
        "--skip-rdma-iommu",
        action="store_true",
        help="omit RDMA NICs from IOMMU collection",
    )
    args = parser.parse_args(argv)

    if args.collect_host:
        print(
            json.dumps(
                collect_host(
                    root=Path(args.root),
                    harness=args.harness,
                    include_scale_out=not args.skip_scale_out,
                    include_rdma_iommu=not args.skip_rdma_iommu,
                ),
                sort_keys=True,
            )
        )
        return 0

    print(json.dumps(run_default_check(args.harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
