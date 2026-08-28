from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditCategory:
    name: str
    title: str
    description: str
    prefixes: tuple[str, ...] = ()
    keys: frozenset[str] = frozenset()

    def includes(self, key: str) -> bool:
        return key in self.keys or key.startswith(self.prefixes)


AUDIT_CATEGORIES = (
    AuditCategory(
        "versions",
        "Minimum versions",
        "Show component versions and their required minimums.",
        keys=frozenset(
            {
                "securityVersions.nvidiaDriver.status",
                "securityVersions.nvidiaContainerToolkit.status",
                "securityVersions.cudaToolkit.status",
                "securityVersions.runc.status",
                "securityVersions.docker.status",
                "securityVersions.connectxFirmware.status",
                "securityVersions.dcgm.status",
                "securityVersions.dcgmExporter.status",
                "securityVersions.virtioNetBluefield.status",
            }
        ),
    ),
    AuditCategory(
        "isolation",
        "Security isolation",
        "Show kernel, virtualization, and tenant isolation checks.",
        prefixes=("security.",),
        keys=frozenset(
            {
                "bmc-ipmi",
                "nvlink-boundary",
                "pcie-passthrough",
                "ufm-profile",
                "securityVersions.virtioNetBluefield.exposure",
                "securityVersions.dpuHostIsolation.status",
            }
        ),
    ),
    AuditCategory(
        "hardware",
        "Hardware",
        "Show GPU, memory, and input-output virtualization checks.",
        prefixes=(
            "gpus.",
            "gpu_controls.",
            "hbm_memory_exposure.",
            "vm_iommu.",
            "arm_smmu_virtualization.",
        ),
    ),
    AuditCategory(
        "software",
        "Software tools",
        "Show installed GPU development and diagnostic tools.",
        prefixes=("software.",),
    ),
    AuditCategory(
        "containers",
        "Container runtime",
        "Show the container runtime and its GPU integration.",
        keys=frozenset(
            {
                "containers.nvidiaContainerToolkit",
                "containers.enroot",
                "containers.enrootImportWorks",
                "containers.dockerOnWorkers",
                "containers.singularity",
            }
        ),
    ),
    AuditCategory(
        "orchestration",
        "Orchestration",
        "Show checks for Slurm workers, Pyxis, and Kubernetes kubelets.",
        # "slurm." covers scheduler-level checks such as accounting; container
        # runtimes on workers stay in the containers category above.
        prefixes=("kubelet_cpu_manager_policy.", "slurm."),
        keys=frozenset(
            {
                "containers.workerCheckOk",
                "containers.pyxisRuntimeWorks",
            }
        ),
    ),
    AuditCategory(
        "networking",
        "Networking",
        "Show fabric topology, adapter naming, and NCCL configuration.",
        prefixes=("nccl_topo_file.", "nccl_ib_qps.", "networking."),
    ),
    AuditCategory(
        "storage",
        "Storage",
        "Show binary storage installation and configuration checks.",
        prefixes=("storage.",),
    ),
    AuditCategory(
        "health",
        "Health and monitoring",
        "Show node health and GPU telemetry checks.",
        prefixes=("healthChecks.",),
    ),
    AuditCategory(
        "access",
        "Access and identity",
        "Show sudo, user management, SSH reachability, and identity provider checks.",
        prefixes=("access.",),
    ),
)

AUDIT_CATEGORY_NAMES = tuple(category.name for category in AUDIT_CATEGORIES)
AUDIT_CATEGORY_BY_NAME = {category.name: category for category in AUDIT_CATEGORIES}
SECURITY_PROFILE = "security"
AUDIT_PROFILE_NAMES = (SECURITY_PROFILE, *AUDIT_CATEGORY_NAMES)
_SECURITY_CATEGORIES = frozenset({"versions", "isolation"})


def category_for_key(key: str) -> AuditCategory:
    matches = [category for category in AUDIT_CATEGORIES if category.includes(key)]
    if len(matches) != 1:
        names = ", ".join(category.name for category in matches) or "none"
        raise ValueError(f"audit check {key!r} has {len(matches)} categories: {names}")
    return matches[0]


def profile_includes(profile: str | None, key: str) -> bool:
    """Return whether one report profile includes an audit check."""
    if profile is None:
        return True
    if profile not in AUDIT_PROFILE_NAMES:
        raise ValueError(f"unknown audit profile: {profile}")
    category = category_for_key(key).name
    if profile == SECURITY_PROFILE:
        return category in _SECURITY_CATEGORIES
    return category == profile
