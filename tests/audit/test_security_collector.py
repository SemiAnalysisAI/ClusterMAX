#!/usr/bin/env python3
"""Executable tests for the fleet security stage that every collector runs."""

from __future__ import annotations

import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bashtest  # noqa: E402


AUDIT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
)
FLEET = AUDIT_ROOT / "security-fleet.sh"
SAMPLED_JSON = {
    "securityVersions": {},
    "security": {
        "pciePassthrough": {"guestIommuGroupCount": 3, "hostVerificationRequired": True}
    },
}


def merge_script(
    harness: str, sampled: str, container: str, output: Path, sampled_json: dict | None = None
) -> str:
    """Source the shared stage and fold the fleet into a sampled JSON."""
    host_file = output.with_suffix(".host")
    container_file = output.with_suffix(".container")
    json_file = output.with_suffix(".sampled.json")
    host_file.write_text(sampled)
    container_file.write_text(container)
    json_file.write_text(json.dumps(SAMPLED_JSON if sampled_json is None else sampled_json))
    return f"""
set -o pipefail
WORKLOAD_DIR={shlex.quote(str(AUDIT_ROOT))}
. "$WORKLOAD_DIR/audit-common.sh"
. "$WORKLOAD_DIR/security-fleet.sh"
trap cleanup_k8s_security_pod EXIT
JSON_OUTPUT=$(cat {shlex.quote(str(json_file))})
SAMPLED=$(cat {shlex.quote(str(host_file))})
CONTAINER_CHECK_OUTPUT=$(cat {shlex.quote(str(container_file))})
WORKER_HOSTNAME=$(sed -n 's/^WORKER_HOSTNAME=//p' <<< "$SAMPLED" | head -1)
merge_security_fleet {harness} "$SAMPLED"
printf '%s\\n' "$JSON_OUTPUT" > {shlex.quote(str(output))}
"""


@pytest.mark.parametrize(
    ("kfd_access", "render_access", "expected"),
    (
        ("allowed", "allowed", "allowed"),
        ("denied", "allowed", "denied"),
        ("allowed", "denied", "denied"),
        ("absent", "allowed", "denied"),
        ("allowed", "absent", "denied"),
        ("unknown", "allowed", "untested"),
    ),
)
def test_rocm_counter_access_state(
    kfd_access: str, render_access: str, expected: str
) -> None:
    run = bashtest.run_bash(
        ROCM_COUNTER_ACCESS_STATE
        + f"\nrocm_counter_access_state {kfd_access} {render_access}"
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected


ROCM_COUNTER_ACCESS_STATE = bashtest.extract_function(
    AUDIT_ROOT / "audit-common.sh", "rocm_counter_access_state"
)


SLURM_HOST = """\
WORKER_HOSTNAME={node}
WORKER_GPU_MODEL=NVIDIA-H100-80GB-HBM3
WORKER_GPU_COUNT=8
WORKER_DRIVER_VERSION=580.159.03
WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true
WORKER_SECURITY_NVIDIA_GPU_PRESENT=true
WORKER_OS_ID=ubuntu
WORKER_OS_VERSION_ID=24.04
WORKER_GUEST_KERNEL_RUNNING=6.8.0-138-generic
WORKER_PCIE_SCAN_COMPLETE=true
WORKER_PCIE_VFIO_DEVICES=0
WORKER_PCIE_UNSAFE_GROUPS=0
"""
SLURM_CONTAINER = """\
WORKER_CONTAINER_HOSTNAME={node}
WORKER_CONTAINER_SECURITY_DOCKER_VERSION={docker}
WORKER_CONTAINER_SECURITY_NCT_VERSION=1.19.1
WORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6
"""


class SlurmSecurityFleetTests(unittest.TestCase):
    def test_fleet_json_larger_than_one_argument_is_merged(self) -> None:
        # Linux limits one argument to 128 KiB. The published minimum table
        # can make the sampled security JSON larger than that, and jq then
        # failed and emptied the audit JSON.
        padding = "x" * 300_000
        sampled_json = {
            "securityVersions": {"docker": {"status": "pass", "note": padding}},
            "security": {"pciePassthrough": {}, "note": padding},
        }
        payload, _ = self.run_slurm_merge(sampled_json)
        self.assertEqual(payload["security"]["note"], padding)
        self.assertEqual(payload["security"]["pwnescape"]["scope"], "fleet")
        self.assertEqual(payload["securityVersions"]["docker"]["fleet"]["hostsChecked"], 2)

    def test_full_collector_stage_reads_every_gpu_and_control_host(self) -> None:
        payload, run = self.run_slurm_merge()
        self.check_fleet(payload, run)

    def run_slurm_merge(self, sampled_json: dict | None = None):
        srun_stub = (
            'node=unknown; prev=""\n'
            'for arg in "$@"; do [[ "$prev" == "-w" ]] && node="$arg"; prev="$arg"; done\n'
            'payload=$(cat)\n'
            'if grep -q WORKER_CONTAINER_SECURITY_DOCKER_VERSION <<< "$payload"; then\n'
            "  printf 'WORKER_CONTAINER_HOSTNAME=%s\\nWORKER_CONTAINER_SECURITY_DOCKER_VERSION=29.0.0\\n"
            "WORKER_CONTAINER_SECURITY_NCT_VERSION=1.19.1\\nWORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6\\n' \"$node\"\n"
            'else\n'
            "  printf 'WORKER_HOSTNAME=%s\\nWORKER_OS_ID=ubuntu\\nWORKER_OS_VERSION_ID=24.04\\n"
            "WORKER_GUEST_KERNEL_RUNNING=6.8.0-138-generic\\nWORKER_DRIVER_VERSION=580.159.03\\n' \"$node\"\n"
            'fi\n'
        )
        sinfo_stub = (
            'case "$*" in\n'
            "  *'%N|%P|%G'*) printf 'gpu-a|gpu|gpu:8\\ngpu-b|gpu|gpu:8\\n' ;;\n"
            "  *) printf 'gpu-a|gpu\\ngpu-b|gpu\\n' ;;\n"
            'esac\n'
        )
        scontrol_stub = (
            'case "$*" in\n'
            "  'show config') echo 'SlurmctldHost[0] = ctl-0(10.0.0.1)' ;;\n"
            'esac\n'
        )
        ssh_stub = (
            "printf 'WORKER_HOSTNAME=ctl-0\\nWORKER_GUEST_KERNEL_RUNNING=6.8.0-138-generic\\n'\n"
        )
        sampled = SLURM_HOST.format(node="gpu-a")
        container = SLURM_CONTAINER.format(node="gpu-a", docker="29.5.3")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            run = bashtest.run_bash(
                merge_script("slurm", sampled, container, output, sampled_json),
                stubs={
                    "srun": srun_stub,
                    "sinfo": sinfo_stub,
                    "scontrol": scontrol_stub,
                    "ssh": ssh_stub,
                },
                env={"SLURM_JOB_ID": "", "SLURM_JOB_NODELIST": ""},
                timeout=60,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertNotIn("Argument list too long", run.stdout + run.stderr)
            payload = json.loads(output.read_text())
        return payload, run

    def check_fleet(self, payload: dict, run) -> None:
        pwnescape = payload["security"]["pwnescape"]
        self.assertEqual(pwnescape["scope"], "fleet")
        roles = {(host["node"], host["role"]) for host in pwnescape["hosts"]}
        self.assertIn(("gpu-a", "worker"), roles)
        self.assertIn(("gpu-b", "worker"), roles)
        self.assertIn(("ctl-0", "control-plane"), roles)
        self.assertEqual(payload["security"]["kvmSvm"]["scope"], "fleet")
        self.assertEqual(payload["security"]["januscape"]["scope"], "fleet")
        docker = payload["securityVersions"]["docker"]
        self.assertEqual(docker["fleet"]["hostsChecked"], 2)
        self.assertEqual(
            {host["node"] for host in docker["fleet"]["hosts"]}, {"gpu-a", "gpu-b"}
        )
        self.assertEqual(
            payload["security"]["pciePassthrough"],
            {
                "guestIommuGroupCount": 3,
                "hostVerificationRequired": True,
                "inventoryComplete": True,
                "vfioDevices": 0,
                "unsafeGroups": 0,
                "scope": "sampled-worker-host",
            },
        )
        # One host check and one container check on the second GPU node, and
        # one PwnEscape read on each compute node.
        self.assertEqual(len(run.calls("srun")), 4)


class StandaloneSecurityFleetTests(unittest.TestCase):
    def test_standalone_adds_pcie_inventory_and_reads_no_other_host(self) -> None:
        sampled = SLURM_HOST.format(node="box")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            run = bashtest.run_bash(
                merge_script("standalone", sampled, "", output),
                stubs={"srun": "exit 99\n", "kubectl": "exit 99\n", "sinfo": "exit 99\n"},
                timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            payload = json.loads(output.read_text())
        self.assertEqual(payload["securityVersions"], {})
        self.assertNotIn("pwnescape", payload["security"])
        self.assertTrue(payload["security"]["pciePassthrough"]["inventoryComplete"])
        self.assertEqual(run.calls("srun"), [])
        self.assertEqual(run.calls("kubectl"), [])


class KubernetesSecurityFleetTests(unittest.TestCase):
    def test_full_collector_stage_visits_every_node_once(self) -> None:
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
            '  "get pods -A"*) printf \'{"items": []}\\n\' ;;\n'
            '  "apply "*) cat >/dev/null ;;\n'
            '  "wait "*) exit 0 ;;\n'
            '  "exec "*)\n'
            '    payload=$(cat)\n'
            '    if grep -q WORKER_CONTAINER_HOSTNAME <<< "$payload"; then\n'
            f"      printf '%b' {container_evidence!r}\n"
            '    elif grep -q "PATH=%s" <<< "$payload"; then\n'
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
            output = Path(tmp) / "audit.json"
            run = bashtest.run_bash(
                merge_script("k8s", host_evidence, "", output),
                stubs={"kubectl": kubectl_stub},
                env={
                    "CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT": "2",
                },
                timeout=30,
            )

            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            payload = json.loads(output.read_text())

        self.assertEqual(
            payload["securityVersions"]["nvidiaDriver"]["fleet"]["hostsChecked"], 1
        )
        self.assertEqual(
            payload["runtimeSoftware"]["cudaToolkit"]["node"], "gpu-node-01"
        )
        exec_calls = [call for call in run.calls("kubectl") if call[0] == "exec"]
        # Host check, container check, two BMC probes within the limit, and
        # one PwnEscape read on each of the four nodes.
        self.assertEqual(len(exec_calls), 8)
        pwnescape = payload["security"]["pwnescape"]
        self.assertEqual(pwnescape["scope"], "fleet")
        self.assertEqual(
            {(host["node"], host["role"], host["checked"]) for host in pwnescape["hosts"]},
            {
                ("gpu-node-01", "worker", True),
                ("worker-node-02", "worker", True),
                ("worker-node-03", "worker", True),
                ("control-plane-01", "control-plane", True),
            },
        )
        self.assertTrue(pwnescape["controlPlane"]["coverageComplete"])
        self.assertTrue(pwnescape["coverageComplete"])
        # The host evidence reports a KVM guest, so the hidden host still needs evidence.
        self.assertEqual(pwnescape["status"], "host-version-required")
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


class SampledFailureSurvivesFleetMissTests(unittest.TestCase):
    def test_kubectl_failure_keeps_a_sampled_host_failure(self) -> None:
        sampled_json = {
            "securityVersions": {},
            "security": {
                "pwnescape": {
                    "status": "fail",
                    "reason": "below minimum",
                    "runningKernel": "6.8.0-100-generic",
                },
                "sctpSendall": {"status": "pass", "reason": "meets minimum"},
                "januscape": {
                    "status": "fail",
                    "exposed": True,
                    "reason": "nested virtualization is exposed",
                },
                "pciePassthrough": {},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "audit.json"
            run = bashtest.run_bash(
                merge_script("k8s", "WORKER_HOSTNAME=gpu-a\n", "", output, sampled_json),
                stubs={"kubectl": "echo 'kubectl failed' >&2; exit 1\n"},
                timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            payload = json.loads(output.read_text())
        security = payload["security"]
        self.assertEqual(security["pwnescape"]["status"], "fail")
        self.assertEqual(security["pwnescape"]["reason"], "below minimum")
        self.assertEqual(security["sctpSendall"]["status"], "coverage-incomplete")
        self.assertIs(security["januscape"]["exposed"], True)
        self.assertEqual(security["januscape"]["status"], "fail")
        self.assertEqual(security["januscape"]["reason"], "nested virtualization is exposed")

    def test_passing_fleet_read_keeps_a_sampled_host_failure(self) -> None:
        sampled = {
            "pwnescape": {"status": "fail", "reason": "below minimum"},
            "sctpSendall": {"status": "pass", "reason": "meets minimum"},
            "kvmSvm": {"status": "not_applicable"},
            "fragnesia": {"status": "pass"},
            "januscape": {"status": "fail", "exposed": True, "reason": "nested virtualization is exposed"},
        }
        fleet = {
            "pwnescape": {"status": "pass", "reason": "every host meets minimum", "scope": "fleet"},
            "sctpSendall": {"status": "pass", "reason": "every host meets minimum", "scope": "fleet"},
            "kvmSvm": {"status": "not_applicable", "scope": "fleet"},
            "fragnesia": {"status": "pass", "reason": "ok"},
            "januscape": {"status": "pass", "exposed": False, "reason": "not exposed"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            workload = Path(tmp)
            (workload / "host_fleet.py").write_text(
                "import sys\nsys.stdin.read()\nprint(" + repr(json.dumps(fleet)) + ")\n"
            )
            script = f"""
set -o pipefail
. {shlex.quote(str(FLEET))}
WORKLOAD_DIR={shlex.quote(str(workload))}
minimum_version() {{ echo 0; }}
minimum_version_grace() {{ echo false; }}
PWNESCAPE_HOST_RECORDS='{{}}'
PWNESCAPE_CONTROL_PLANE_JSON='[]'
SECURITY_ADVISORY_JSON={shlex.quote(json.dumps(sampled))}
apply_host_fleet
printf '%s\\n' "$SECURITY_ADVISORY_JSON"
"""
            run = bashtest.run_bash(script, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        merged = json.loads(run.stdout)
        self.assertEqual(merged["pwnescape"]["status"], "fail")
        self.assertEqual(merged["pwnescape"]["reason"], "below minimum")
        self.assertEqual(merged["pwnescape"]["scope"], "fleet")
        self.assertEqual(merged["sctpSendall"]["status"], "pass")
        self.assertEqual(merged["januscape"]["status"], "fail")
        self.assertIs(merged["januscape"]["exposed"], True)


if __name__ == "__main__":
    unittest.main()
