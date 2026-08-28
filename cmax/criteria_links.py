"""Stable links from audit checks to the public evaluation criteria."""

from __future__ import annotations


CRITERIA_URL = "https://www.clustermax.ai/criteria"
REFERENCE_LABEL = "ClusterMAX evaluation criteria"

_SECURITY_PATCHING = (
    "security-every-component-patched-to-at-least-the-published-clustermax-"
    "minimum-version-covering-the-gpu-driver-container-runtime-nic-and-dpu-"
    "firmware-and-host-packages"
)
_SECURITY_CONTAINER_TOOLKIT = (
    "security-updated-nvidia-container-toolkit-preventing-cve-2024-0132-and-"
    "related-vulnerabilities"
)
_SECURITY_ESCALATION = (
    "security-protection-against-container-escalation-vulnerabilities"
)
_SECURITY_ISOLATION = (
    "security-strong-isolation-between-tenants-not-namespaces-or-container-"
    "only-isolation-i-e-use-vcluster-private-nodes-instead-of-vcluster-shared-"
    "nodes"
)
_SECURITY_UFM = (
    "security-infiniband-csps-enable-the-ufm-secured-bare-metal-cloud-profile-"
    "providing-a-comprehensive-set-of-security-features-required-for-secure-"
    "multi-tenant-cloud-environments"
)
_LIFECYCLE_GPU_DIRECT = (
    "lifecycle-out-of-the-box-gpudirect-rdma-between-nic-and-gpu-setup"
)
_LIFECYCLE_DRIVERS = (
    "lifecycle-out-of-the-box-ib-rocev2-and-nvidia-drivers-configuration"
)
_ORCHESTRATION_USERS = "orchestration-easy-process-for-adding-new-cluster-users"
_ORCHESTRATION_RBAC = "orchestration-rbac-and-sso-implementation"
_ORCHESTRATION_SSH = "orchestration-no-ssh-key-copying-required"
_ORCHESTRATION_CUDA = (
    "orchestration-cuda-visible-devices-properly-configured"
)
_ORCHESTRATION_TOPOLOGY = (
    "orchestration-out-of-the-box-slurm-topology-configuration"
)
_ORCHESTRATION_MODULES = "orchestration-slurm-modules-availability"
_ORCHESTRATION_PYXIS = "orchestration-pyxis-container-plugin-support"
_STORAGE_RWX = (
    "storage-storage-integration-with-kubernetes-for-pvcs-storage-class-"
    "including-readwritemany-rwx-pvcs"
)
_NETWORKING_TOPOLOGY = "networking-out-of-the-box-slurm-topology-configuration"
_NETWORKING_NCCL_AUTOCONFIG = (
    "networking-nccl-min-nchannels-nccl-proto-nccl-algo-not-set-auto-"
    "configuration"
)
_MONITORING_NCU = "monitoring-ncu-profiling-available-for-all-users"
_MONITORING_HEALTH = "monitoring-automated-active-and-passive-health-checks"
_MONITORING_GRAFANA = "monitoring-out-of-the-box-detailed-managed-grafana"
_MONITORING_DCGM = (
    "monitoring-dcgm-health-checks-plugged-into-the-slurm-healthcheckprogram"
)
_MONITORING_SACCT = (
    "monitoring-sacct-integration-for-job-accounting-and-resource-utilization"
)


# Some release checks are more granular than the public requirements. Those
# checks point to the owning public category instead of claiming that a nearby
# requirement is an exact match.
_CHECK_ANCHORS = {
    "securityVersions.nvidiaDriver.status": _SECURITY_PATCHING,
    "securityVersions.nvidiaContainerToolkit.status": _SECURITY_CONTAINER_TOOLKIT,
    "securityVersions.cudaToolkit.status": _SECURITY_PATCHING,
    "securityVersions.runc.status": _SECURITY_PATCHING,
    "securityVersions.docker.status": _SECURITY_PATCHING,
    "securityVersions.connectxFirmware.status": _SECURITY_PATCHING,
    "securityVersions.dcgm.status": _SECURITY_PATCHING,
    "securityVersions.dcgmExporter.status": _SECURITY_PATCHING,
    "securityVersions.virtioNetBluefield.status": _SECURITY_PATCHING,
    "securityVersions.virtioNetBluefield.exposure": _SECURITY_ISOLATION,
    "securityVersions.dpuHostIsolation.status": _SECURITY_ISOLATION,
    "security.januscape.status": _SECURITY_ESCALATION,
    "security.guestKernel.newerInstalled": _SECURITY_PATCHING,
    "security.fragnesia.status": _SECURITY_PATCHING,
    "containers.nvidiaContainerToolkit": _LIFECYCLE_DRIVERS,
    "containers.workerCheckOk": "orchestration",
    "containers.pyxisRuntimeWorks": _ORCHESTRATION_PYXIS,
    "containers.enroot": "orchestration",
    "containers.enrootImportWorks": "orchestration",
    "containers.dockerOnWorkers": "orchestration",
    "containers.singularity": "orchestration",
    "software.nvhpc.status": _LIFECYCLE_DRIVERS,
    "software.ncu.installed": _MONITORING_NCU,
    "software.ncu.profilingEnabled": _MONITORING_NCU,
    "software.lmod.modulesStatus": _ORCHESTRATION_MODULES,
    "software.cudaVisibleDevicesStatus": _ORCHESTRATION_CUDA,
    "software.nccl.installed": "networking",
    "software.perf.installed": "monitoring",
    "software.perf.perfEventParanoid": "monitoring",
    "software.perf.kptrRestrict": "monitoring",
    "gpus.gdrcopy.installed": _LIFECYCLE_GPU_DIRECT,
    "gpus.gpuDirectRdmaPath": _LIFECYCLE_GPU_DIRECT,
    "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy": _LIFECYCLE_GPU_DIRECT,
    "gpus.pcieAcs.enabled": "lifecycle",
    "gpu_controls.vboost.allowed": "lifecycle",
    "hbm_memory_exposure.status": "lifecycle",
    "kubelet_cpu_manager_policy.status": _SECURITY_ISOLATION,
    "vm_iommu.status": "lifecycle",
    "arm_smmu_virtualization.status": "lifecycle",
    "nccl_topo_file.status": _NETWORKING_TOPOLOGY,
    "nccl_ib_qps.status": "networking",
    "networking.topologyConfigured": _ORCHESTRATION_TOPOLOGY,
    "networking.hcaNamingValid": "networking",
    "networking.ncclAutoConfig": _NETWORKING_NCCL_AUTOCONFIG,
    "storage.rwxStatus": _STORAGE_RWX,
    "healthChecks.nhcInstalled": _MONITORING_HEALTH,
    "healthChecks.monitoringStack.dcgmExporter": _MONITORING_GRAFANA,
    "healthChecks.dcgmInstalled": _MONITORING_DCGM,
    "healthChecks.dcgmSlurm": _MONITORING_DCGM,
    "access.sudoAvailable": "orchestration",
    "access.userManagement": _ORCHESTRATION_USERS,
    "access.sshToComputeNodes": _ORCHESTRATION_SSH,
    "access.externalIdp.detected": _ORCHESTRATION_RBAC,
    "access.slurmCommandsOk": "orchestration",
    "slurm.accounting.sacctAvailable": _MONITORING_SACCT,
    "bmc-ipmi": _SECURITY_ISOLATION,
    "ufm-profile": _SECURITY_UFM,
    "pcie-passthrough": _SECURITY_ISOLATION,
    "nvlink-boundary": _SECURITY_ISOLATION,
}


def audit_check_url(check_key: str) -> str | None:
    """Return the public category or requirement permalink for a CLI check."""
    anchor = _CHECK_ANCHORS.get(check_key)
    return f"{CRITERIA_URL}#{anchor}" if anchor else None
