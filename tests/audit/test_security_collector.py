#!/usr/bin/env python3
"""Executable tests for the focused security collectors."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bashtest  # noqa: E402


AUDIT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
)
COLLECTOR = AUDIT_ROOT / "cluster-audit-slurm-security.sh"
K8S_COLLECTOR = AUDIT_ROOT / "cluster-audit-k8s-security.sh"


class SlurmSecurityCollectorTests(unittest.TestCase):
    def test_collector_runs_only_the_security_worker_steps(self) -> None:
        host_evidence = """\
WORKER_HOSTNAME=amd-worker-01
WORKER_GPU_MODEL=unknown
WORKER_GPU_COUNT=0
WORKER_DRIVER_VERSION=unknown
WORKER_CUDA_VERSION=unknown
WORKER_NVCC_VERSION=not-found
WORKER_AMD_GPU_MODEL=AMD-Instinct-MI300X
WORKER_AMD_GPU_COUNT=8
WORKER_AMD_GPU_MEMORY=196608
WORKER_AMD_DRIVER_VERSION=6.8.5
WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true
WORKER_SECURITY_NVIDIA_GPU_PRESENT=false
WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true
WORKER_RDMA_LINK_LAYERS=Ethernet
WORKER_IB_DEVICES=bnxt_re0
WORKER_GUEST_KERNEL_RUNNING=6.8.0-124-generic
WORKER_GUEST_KERNEL_NEWEST_INSTALLED=6.8.0-138-generic
WORKER_GUEST_KERNEL_NEWER_INSTALLED=true
WORKER_GUEST_REBOOT_REQUIRED=true
WORKER_FRAGNESIA_STATUS=unknown
WORKER_FRAGNESIA_ABI_FLOOR=6.8.0-124.124
WORKER_NESTED_CPU_EXPOSED=true
WORKER_KVM_DEVICE=true
WORKER_NESTED_MODULE=kvm_amd
WORKER_NESTED_ENABLED=true
WORKER_JANUSCAPE_EXPOSED=false
WORKER_JANUSCAPE_STATUS=not-exposed
WORKER_QEMU_CVE_2024_3446_STATUS=not-applicable
WORKER_VMSCAPE_STATUS=not-applicable
WORKER_VIRT_TYPE=none
WORKER_VIRT_GUEST=false
WORKER_VIRTIO_SERIAL=true
WORKER_IOMMU_GROUPS=32
WORKER_NVLINK_EXPOSED=unknown
WORKER_NVLINK_TOPOLOGY_CHECKED=false
WORKER_NVIDIA_MAY_2026_PATCHED=not-applicable
WORKER_IPMITOOL_PATH=
WORKER_IPMI_USER_ACCESS=not-installed
WORKER_IPMI_SUDO_ACCESS=not-installed
"""
        container_evidence = """\
WORKER_CONTAINER_HOSTNAME=amd-worker-01
WORKER_CONTAINER_SECURITY_DOCKER_VERSION=29.5.3
WORKER_CONTAINER_SECURITY_NCT_VERSION=not-installed
WORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.5
"""
        srun_stub = (
            'if [[ "$*" == *"--time=5:00"* ]]; then\n'
            f"  printf '%b' {host_evidence!r}\n"
            "else\n"
            f"  printf '%b' {container_evidence!r}\n"
            "fi\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "raw"
            run = bashtest.run_bash(
                f'bash "{COLLECTOR}" --name amd-cluster --output-dir "{output_dir}"',
                stubs={"srun": srun_stub},
                env={
                    "CLUSTERMAX_AUDIT_HARNESS": "slurm",
                    "CLUSTERMAX_AUDIT_SCOPE": "security",
                    "CLUSTERMAX_GPU_PARTITION": "gpu",
                },
                timeout=30,
            )

            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            output_files = list(output_dir.glob("*.json"))
            self.assertEqual(len(output_files), 1)
            payload = json.loads(output_files[0].read_text())

        self.assertEqual(len(run.calls("srun")), 2)
        self.assertEqual(payload["gpus"]["model"], "AMD-Instinct-MI300X")
        self.assertTrue(payload["gpus"]["amd"]["present"])
        self.assertEqual(payload["securityVersions"]["docker"]["version"], "29.5.3")
        self.assertEqual(payload["securityVersions"]["runc"]["version"], "1.3.5")
        self.assertTrue(payload["security"]["guestKernel"]["newerInstalled"])
        self.assertTrue(payload["security"]["virtualization"]["virtioSerialExposed"])
        self.assertEqual(
            payload["security"]["nvidiaMay2026"]["driverVersion"], "unknown"
        )
        self.assertFalse(
            payload["security"]["nvlinkBoundary"]["nvidiaGpuPresent"]
        )
        self.assertEqual(
            payload["security"]["nvlinkBoundary"]["nvlinkExposed"], "unknown"
        )
        self.assertNotIn("NVIDIA HPC SDK & SOFTWARE STACK", run.stdout)
        self.assertNotIn("STORAGE & FILESYSTEM", run.stdout)
        self.assertNotIn("HEALTH CHECKS & MONITORING", run.stdout)


class KubernetesSecurityCollectorTests(unittest.TestCase):
    def test_collector_uses_one_host_pod_and_only_security_worker_steps(self) -> None:
        nodes = {
            "items": [
                {
                    "metadata": {
                        "name": "gpu-node-01",
                        "labels": {
                            "nvidia.com/gpu.product": "NVIDIA-H100-80GB-HBM3",
                            "nvidia.com/cuda.driver.major": "580",
                            "nvidia.com/cuda.driver.minor": "159",
                            "nvidia.com/cuda.driver.rev": "03",
                            "nvidia.com/cuda.runtime.major": "13",
                            "nvidia.com/cuda.runtime.minor": "1",
                        },
                    },
                    "status": {
                        "capacity": {"nvidia.com/gpu": "8"},
                        "allocatable": {"nvidia.com/gpu": "8"},
                    },
                },
                {
                    "metadata": {"name": "worker-node-02", "labels": {}},
                    "status": {"capacity": {}},
                },
                {
                    "metadata": {"name": "worker-node-03", "labels": {}},
                    "status": {"capacity": {}},
                },
                {
                    "metadata": {
                        "name": "control-plane-01",
                        "labels": {"node-role.kubernetes.io/control-plane": ""},
                    },
                    "status": {"capacity": {}},
                },
            ]
        }
        pods = {
            "items": [
                {
                    "spec": {
                        "containers": [
                            {
                                "name": "dcgm-exporter",
                                "image": "nvcr.io/nvidia/k8s/dcgm-exporter:4.5.3-4.8.2-ubuntu22.04",
                            }
                        ]
                    }
                }
            ]
        }
        host_evidence = """\
WORKER_HOSTNAME=gpu-node-01
WORKER_GPU_MODEL=NVIDIA-H100-80GB-HBM3
WORKER_GPU_COUNT=8
WORKER_GPU_MEMORY=81559
WORKER_DRIVER_VERSION=580.159.03
WORKER_CUDA_VERSION=13.1
WORKER_NVCC_VERSION=13.1
WORKER_AMD_GPU_MODEL=unknown
WORKER_AMD_GPU_COUNT=0
WORKER_AMD_DRIVER_VERSION=unknown
WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true
WORKER_SECURITY_NVIDIA_GPU_PRESENT=true
WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true
WORKER_RDMA_LINK_LAYERS=Ethernet
WORKER_IB_DEVICES=mlx5_0
WORKER_DCGM_VERSION=4.5.3
WORKER_GUEST_KERNEL_RUNNING=6.8.0-138-generic
WORKER_GUEST_KERNEL_NEWEST_INSTALLED=6.8.0-138-generic
WORKER_GUEST_KERNEL_NEWER_INSTALLED=false
WORKER_GUEST_REBOOT_REQUIRED=false
WORKER_FRAGNESIA_STATUS=pass
WORKER_FRAGNESIA_ABI_FLOOR=6.8.0-124.124
WORKER_NESTED_CPU_EXPOSED=false
WORKER_KVM_DEVICE=false
WORKER_NESTED_MODULE=none
WORKER_NESTED_ENABLED=false
WORKER_JANUSCAPE_EXPOSED=false
WORKER_JANUSCAPE_STATUS=not-applicable
WORKER_QEMU_CVE_2024_3446_STATUS=not-applicable
WORKER_VMSCAPE_STATUS=not-applicable
WORKER_VIRT_TYPE=kvm
WORKER_VIRT_GUEST=true
WORKER_VIRTIO_SERIAL=false
WORKER_IOMMU_GROUPS=0
WORKER_NVLINK_EXPOSED=true
WORKER_NVLINK_TOPOLOGY_CHECKED=true
WORKER_NVIDIA_MAY_2026_PATCHED=true
WORKER_IPMITOOL_PATH=
WORKER_IPMI_USER_ACCESS=not-installed
WORKER_IPMI_SUDO_ACCESS=not-installed
"""
        container_evidence = """\
WORKER_CONTAINER_HOSTNAME=gpu-node-01
WORKER_CONTAINER_SECURITY_DOCKER_VERSION=29.8.0
WORKER_CONTAINER_SECURITY_NCT_VERSION=1.19.1
WORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6
"""
        kubectl_stub = (
            'case "$*" in\n'
            f'  "get nodes"*) printf \'%s\\n\' {json.dumps(nodes)!r} ;;\n'
            f'  "get pods --all-namespaces"*) printf \'%s\\n\' {json.dumps(pods)!r} ;;\n'
            '  "apply "*) cat >/dev/null ;;\n'
            '  "wait "*) exit 0 ;;\n'
            '  "exec "*)\n'
            '    payload=$(cat)\n'
            '    if grep -q WORKER_CONTAINER_HOSTNAME <<< "$payload"; then\n'
            f"      printf '%b' {container_evidence!r}\n"
            '    elif grep -q "DEVICE=%s" <<< "$payload"; then\n'
            '      grep -q \'timeout 5 "$path" mc info\' <<< "$payload" || exit 96\n'
            '      grep -q \'timeout 5 "$path" chassis status\' <<< "$payload" || exit 96\n'
            "      printf '%s\\n' 'DEVICE=true' 'PATH=/usr/bin/ipmitool' "
            "'INSTALLED=true' 'MC=allowed' 'CHASSIS=allowed'\n"
            '    else\n'
            f"      printf '%b' {host_evidence!r}\n"
            '    fi\n'
            '    ;;\n'
            '  "delete "*) exit 0 ;;\n'
            '  *) echo "unexpected kubectl call: $*" >&2; exit 97 ;;\n'
            'esac\n'
        )

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "raw"
            run = bashtest.run_bash(
                f'bash "{K8S_COLLECTOR}" --name k8s-cluster --output-dir "{output_dir}"',
                stubs={"kubectl": kubectl_stub},
                env={
                    "CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT": "2",
                    "CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED": "true",
                },
                timeout=30,
            )

            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            output_files = list(output_dir.glob("*.json"))
            self.assertEqual(len(output_files), 1)
            payload = json.loads(output_files[0].read_text())

        self.assertEqual(payload["audit"]["type"], "k8s")
        self.assertEqual(payload["nodes"]["total"], 3)
        self.assertEqual(payload["gpus"]["total"], 8)
        self.assertEqual(
            payload["securityVersions"]["nvidiaDriver"]["version"],
            "580.159.03",
        )
        self.assertEqual(
            payload["securityVersions"]["dcgmExporter"]["version"], "4.8.2"
        )
        self.assertEqual(
            payload["security"]["nvlinkBoundary"],
            {
                "nvlinkExposed": True,
                "topologyChecked": True,
                "topologyCoverageComplete": True,
                "nvidiaGpuPresent": True,
                "targetIsVm": True,
                "domainExclusive": True,
            },
        )
        exec_calls = [call for call in run.calls("kubectl") if call[0] == "exec"]
        self.assertEqual(len(exec_calls), 4)
        for call in exec_calls:
            self.assertIn("CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host", call)
            self.assertTrue(
                any(
                    argument.startswith("CLUSTERMAX_FRAGNESIA_ABI_MINIMUM=")
                    and not argument.endswith("=unknown")
                    for argument in call
                )
            )
        self.assertTrue(payload["security"]["bmcIpmi"]["exposed"])
        self.assertEqual(payload["security"]["bmcIpmi"]["nodesChecked"], 2)
        self.assertEqual(
            payload["security"]["bmcIpmi"]["exposedNodes"],
            ["gpu-node-01", "worker-node-02"],
        )
        self.assertEqual(payload["security"]["bmcIpmi"]["nodesTotal"], 3)
        self.assertFalse(payload["security"]["bmcIpmi"]["nodeCoverageComplete"])
        self.assertEqual(
            payload["security"]["bmcIpmi"]["unassessedNodes"],
            ["worker-node-03"],
        )
        self.assertNotIn(
            "control-plane-01",
            [host["node"] for host in payload["security"]["bmcIpmi"]["hosts"]],
        )
        self.assertTrue(payload["security"]["bmcIpmi"]["hosts"][0]["devicePresent"])
        self.assertEqual(
            payload["security"]["bmcIpmi"]["hosts"][0]["chassisStatusAccess"],
            "allowed",
        )
        self.assertEqual(
            payload["security"]["bmcIpmi"]["accessMode"],
            "administrative-privileged-host-root-pod",
        )
        self.assertFalse(
            payload["security"]["bmcIpmi"]["ordinaryPodExposureTested"]
        )
        self.assertEqual(run.calls("srun"), [])
        self.assertNotIn("STORAGE & FILESYSTEM", run.stdout)
        self.assertNotIn("HEALTH CHECKS & MONITORING", run.stdout)


if __name__ == "__main__":
    unittest.main()
