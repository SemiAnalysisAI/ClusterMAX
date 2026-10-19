"""Unit tests with generated topology matrices and synthetic collector records."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any
import pytest

CHECK_PATH = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
    / "fabric"
    / "nic-topology-check.py"
)

def load_check_module():
    spec = importlib.util.spec_from_file_location("nic_topology_check_under_test", CHECK_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

nic = load_check_module()

@pytest.fixture(params=["nic", "vboost"])
def fanout_check(request):
    if request.param == "nic":
        return nic
    path = CHECK_PATH.parents[1] / "gpu" / "vboost.py"
    spec = importlib.util.spec_from_file_location("vboost_fanout_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@pytest.mark.parametrize(
    "env,available,expected",
    [
        ({"CLUSTERMAX_AUDIT_K8S_NAMESPACE": "default"}, {"gpu-operator"}, "gpu-operator"),
        ({}, {"nvidia", "gpu"}, "nvidia"),
        ({"CLUSTERMAX_GPU_OPERATOR_NAMESPACE": "custom-ns"}, set(), "custom-ns"),
    ],
    ids=["audit-namespace-independent", "nvidia-before-generic", "explicit-override"],
)
def test_shared_gpu_namespace_policy(fanout_check, env, available, expected):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return completed(command, returncode=0 if command[-1] in available else 1)

    assert fanout_check.k8s_gpu_namespace(env=env, runner=runner) == expected
    if "CLUSTERMAX_GPU_OPERATOR_NAMESPACE" in env:
        assert calls == []
    elif expected == "gpu-operator":
        assert calls[0][-1] == "gpu-operator"

@pytest.mark.parametrize("driver_present", [False, True], ids=["discovery-fallback", "driver-preferred"])
def test_shared_driver_pod_preference(fanout_check, driver_present):
    names = ["gpu-feature-discovery-abcde", "nvidia-dcgm-exporter-abcde"]
    if driver_present:
        names.append("nvidia-driver-abcde")
    pods = {"items": [
        {"metadata": {"name": name}, "status": {"phase": "Running"}}
        for name in names
    ]}

    def runner(command, **kwargs):
        return completed(command, stdout=json.dumps(pods))

    selected = fanout_check.k8s_driver_pod("gpu-operator", "gpu-1", runner=runner)
    expected = "nvidia-driver-abcde" if driver_present else "gpu-feature-discovery-abcde"
    if fanout_check is nic:
        assert selected == {"name": expected, "container": None, "hostRoot": False}
    else:
        assert selected == expected

def completed(command: list[str], *, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)

def k8s_collector_output() -> str:
    topo = "\n".join(
        [
            "\tGPU0\tNIC0\tCPU Affinity",
            "GPU0\t X \tPIX\t0-55",
            "NIC0\tPIX\t X ",
            "",
            "NIC Legend:",
            "",
            "  NIC0: mlx5_0",
        ]
    )
    return "\n".join(
        [
            "@@TOPO_BEGIN@@",
            topo,
            "@@TOPO_END@@",
            "@@HCA@@\tmlx5_0\t400 Gb/sec (4X NDR)\tEthernet\t4: ACTIVE",
        ]
    ) + "\n"

class HelperTests(unittest.TestCase):
    def test_aggregate_keys_by_host(self) -> None:
        records = [
            {"host": "gpu-a", "nics": [{"name": "mlx5_0", "role": "fabric"}]},
            {"host": "gpu-b", "nics": []},
            {"host": "", "nics": [{"name": "ignored"}]},
        ]
        self.assertEqual(
            nic.aggregate(records),
            {"gpu-a": [{"name": "mlx5_0", "role": "fabric"}], "gpu-b": []},
        )

    def test_parse_topo_strips_ansi_formatting_from_header(self) -> None:
        topo = "\n".join(
            [
                "\x1b[4mGPU0\tNIC0\tNIC1\x1b[0m",
                "GPU0\t X \tPIX\tSYS",
                "NIC0\tPIX\t X \tSYS",
                "NIC1\tSYS\tSYS\t X ",
                "NIC Legend:",
                "  NIC0: mlx5_5",
                "  NIC1: mlx5_0",
            ]
        )

        affinity, names = nic.parse_topo(topo)

        self.assertEqual(affinity["NIC0"], "close")
        self.assertEqual(affinity["NIC1"], "far")
        self.assertEqual(names["NIC0"], "mlx5_5")

    def test_phb_affinity_marks_hgx_compute_hca_as_fabric(self) -> None:
        topo = "\n".join(
            [
                "\tGPU0\tGPU1\tNIC0\tNIC1",
                "GPU0\t X \tNV18\tNODE\tPHB",
                "GPU1\tNV18\t X \tSYS\tPHB",
                "NIC0\tNODE\tSYS\t X \tSYS",
                "NIC1\tPHB\tPHB\tSYS\t X ",
                "NIC Legend:",
                "  NIC0: mlx5_0",
                "  NIC1: mlx5_5",
            ]
        )

        classified = nic.classify_nics(
            topo,
            [
                ("mlx5_0", 100.0, "InfiniBand", "ACTIVE"),
                ("mlx5_5", 800.0, "InfiniBand", "ACTIVE"),
            ],
            [],
        )

        self.assertEqual(classified[0]["role"], "storage")
        self.assertEqual(classified[1]["role"], "fabric")
        self.assertIn("PHB", classified[1]["reason"])

class TopoCollectionFailureTests(unittest.TestCase):

    def test_collect_topo_executes_nvidia_smi_without_a_shell(self) -> None:
        calls = []

        def runner(command: Any, **kwargs: Any) -> subprocess.CompletedProcess:
            calls.append((command, kwargs))
            return completed(command, stdout="topology\n")

        self.assertEqual(nic.collect_topo(runner=runner), ("topology\n", None))
        self.assertEqual(calls[0][0], ["nvidia-smi", "topo", "-m"])
        self.assertEqual(calls[0][1]["stderr"], subprocess.DEVNULL)
        self.assertNotIn("shell", calls[0][1])

    def test_gather_flags_topo_timeout_and_still_classifies(self) -> None:
        def runner(command: Any, **_: Any) -> subprocess.CompletedProcess:
            raise subprocess.TimeoutExpired(cmd=command, timeout=10)

        record = nic.gather(runner=runner)

        self.assertIs(record["topo_collected"], False)
        self.assertEqual(record["topo_error"], "timeout")

        self.assertIsInstance(record["nics"], list)

    def test_gather_healthy_host_records_topo_collected_true(self) -> None:
        def runner(command: Any, **_: Any) -> subprocess.CompletedProcess:
            return completed([str(command)], stdout="\tGPU0\tNIC0\nGPU0\t X \tPIX\nNIC0\tPIX\t X \n")

        record = nic.gather(runner=runner)

        self.assertIs(record["topo_collected"], True)
        self.assertNotIn("topo_error", record)

    def test_collect_topo_records_exception_class(self) -> None:
        def runner(command: Any, **_: Any) -> subprocess.CompletedProcess:
            raise OSError("nvidia-smi exploded")

        self.assertEqual(nic.collect_topo(runner=runner), ("", "OSError"))

    def test_collect_topo_records_empty_output_with_exit_code(self) -> None:
        def runner(command: Any, **_: Any) -> subprocess.CompletedProcess:
            return completed([str(command)], returncode=127, stdout="")

        self.assertEqual(nic.collect_topo(runner=runner), ("", "no output (exit 127)"))

    def test_empty_topo_classifies_rdma_hca_via_storage_fallback(self) -> None:

        classified = nic.classify_nics("", [("mlx5_0", 400.0, "InfiniBand", "ACTIVE")], [])

        self.assertEqual(classified[0]["role"], "storage")
        self.assertEqual(classified[0]["reason"], "high-rate RDMA, no close-GPU affinity")

class SlurmDispatchTests(unittest.TestCase):
    def test_slurm_aggregates_per_node_lines(self) -> None:
        env = {"SLURM_JOB_ID": "42", "SLURM_NNODES": "2"}

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            self.assertIn("srun", command)
            self.assertIn("--collect-host", command)
            stdout = "\n".join(
                [
                    '{"host":"gpu-a","nics":[{"name":"mlx5_0","role":"fabric"}]}',
                    "srun: diagnostic noise",
                    '{"host":"gpu-b","nics":[{"name":"mlx5_1","role":"storage"}]}',
                ]
            )
            return completed(command, stdout=stdout)

        payload = nic.build_check_payload(harness="slurm", env=env, runner=runner)
        topo = payload["nic_topology"]
        self.assertEqual(set(topo), {"gpu-a", "gpu-b"})
        self.assertEqual(topo["gpu-a"][0]["role"], "fabric")

    def test_slurm_topo_failure_surfaces_per_host_status(self) -> None:
        env = {"SLURM_JOB_ID": "42", "SLURM_NNODES": "2"}

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            stdout = "\n".join(
                [
                    '{"host":"gpu-a","nics":[{"name":"mlx5_0","role":"storage"}],"topo_collected":false,"topo_error":"timeout"}',
                    '{"host":"gpu-b","nics":[{"name":"mlx5_0","role":"fabric"}],"topo_collected":true}',
                ]
            )
            return completed(command, stdout=stdout)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            payload = nic.build_check_payload(harness="slurm", env=env, runner=runner)

        self.assertEqual(payload["nic_topology"]["gpu-a"][0]["role"], "storage")

        self.assertEqual(
            payload["nic_topology_status"],
            {"gpu-a": {"topo_collected": False, "topo_error": "timeout"}},
        )
        self.assertIn("gpu-a (timeout)", stderr.getvalue())

    def test_slurm_healthy_hosts_omit_status_key(self) -> None:
        env = {"SLURM_JOB_ID": "42", "SLURM_NNODES": "1"}

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            return completed(
                command,
                stdout='{"host":"gpu-a","nics":[{"name":"mlx5_0","role":"fabric"}],"topo_collected":true}',
            )

        payload = nic.build_check_payload(harness="slurm", env=env, runner=runner)

        self.assertNotIn("nic_topology_status", payload)

    def test_slurm_without_job_id_does_not_substitute_local_evidence(self) -> None:
        def runner(_command: list[str], **_: Any) -> subprocess.CompletedProcess:
            raise AssertionError("srun should not run without SLURM_JOB_ID")

        payload = nic.build_check_payload(harness="slurm", env={}, runner=runner)
        self.assertEqual(payload["nic_topology"], {})

        self.assertEqual(len(payload["nic_topology"]), 1)

class K8sDispatchTests(unittest.TestCase):
    def _fake_kubectl(self, exec_host: str = "driver-pod-xyz") -> Any:
        nodes_json = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "gpu-1"}, "status": {"capacity": {"nvidia.com/gpu": "8"}}},
                    {"metadata": {"name": "gpu-2"}, "status": {"capacity": {"nvidia.com/gpu": "8"}}},
                    {"metadata": {"name": "cpu-1"}, "status": {"capacity": {}}},
                ]
            }
        )
        pods_json = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "nvidia-driver-daemonset-abcde"}, "status": {"phase": "Running"}},
                ]
            }
        )

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            self.assertEqual(command[0], "kubectl")
            args = command[1:]
            if args[:2] == ["get", "nodes"]:
                return completed(command, stdout=nodes_json)
            if args[:2] == ["get", "namespaces"]:
                return completed(command, returncode=1)
            if args[:2] == ["get", "namespace"]:
                return completed(command, returncode=0 if args[2] == "gpu-operator" else 1)
            if args[:2] == ["get", "pods"]:
                return completed(command, stdout=pods_json)
            if args[0] == "exec":

                self.assertIn("sh", args)
                return completed(command, stdout=k8s_collector_output())
            raise AssertionError(f"unexpected kubectl call: {args}")

        return runner

    def test_k8s_checks_each_gpu_node_via_driver_pod(self) -> None:
        payload = nic.build_check_payload(harness="k8s", env={}, runner=self._fake_kubectl())
        topo = payload["nic_topology"]

        self.assertEqual(set(topo), {"gpu-1", "gpu-2"})
        self.assertEqual(topo["gpu-1"][0]["role"], "fabric")

    def test_k8s_empty_topo_block_flags_host_and_keeps_fallback_roles(self) -> None:

        no_topo = "\n".join(
            [
                "@@TOPO_BEGIN@@",
                "@@TOPO_END@@",
                "@@HCA@@\tmlx5_0\t400 Gb/sec (4X NDR)\tInfiniBand\t4: ACTIVE",
            ]
        ) + "\n"

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            args = command[1:]
            if args[:2] == ["get", "nodes"]:
                return completed(command, stdout=json.dumps({"items": [{"metadata": {"name": "gpu-1"}, "status": {"capacity": {"nvidia.com/gpu": "8"}}}]}))
            if args[:2] == ["get", "namespaces"]:
                return completed(command, returncode=1)
            if args[:2] == ["get", "namespace"]:
                return completed(command, returncode=0 if args[2] == "gpu-operator" else 1)
            if args[:2] == ["get", "pods"]:
                return completed(command, stdout=json.dumps({"items": [{"metadata": {"name": "nvidia-driver-x"}, "status": {"phase": "Running"}}]}))
            if args[0] == "exec":
                return completed(command, stdout=no_topo)
            raise AssertionError(f"unexpected kubectl call: {args}")

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            payload = nic.build_check_payload(harness="k8s", env={}, runner=runner)

        self.assertEqual(payload["nic_topology"]["gpu-1"][0]["role"], "storage")
        self.assertEqual(
            payload["nic_topology_status"],
            {"gpu-1": {"topo_collected": False, "topo_error": "no output"}},
        )
        self.assertIn("gpu-1 (no output)", stderr.getvalue())

    def test_k8s_healthy_topo_omits_status_key(self) -> None:
        payload = nic.build_check_payload(harness="k8s", env={}, runner=self._fake_kubectl())

        self.assertNotIn("nic_topology_status", payload)

    def test_k8s_uses_privileged_device_plugin_with_host_root(self) -> None:
        pods = {
            "items": [
                {
                    "metadata": {"name": "nvidia-device-plugin-daemonset-abcde"},
                    "status": {"phase": "Running"},
                    "spec": {
                        "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                        "containers": [
                            {
                                "name": "nvidia-device-plugin",
                                "securityContext": {"privileged": True},
                                "volumeMounts": [
                                    {"name": "host-root", "mountPath": "/host"}
                                ],
                            }
                        ],
                    },
                }
            ]
        }
        commands: list[list[str]] = []

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            commands.append(command)
            if command[1:3] == ["get", "pods"]:
                return completed(command, stdout=json.dumps(pods))
            return completed(command, stdout=k8s_collector_output())

        record, error = nic.run_k8s_node_check(
            "example-nvidia-gpu-operator", "gpu-1", runner=runner
        )

        self.assertIsNone(error)
        self.assertEqual(record["host"], "gpu-1")
        exec_command = commands[-1]
        self.assertIn("nvidia-device-plugin", exec_command)
        self.assertEqual(exec_command[-5:-2], ["chroot", "/host", "sh"])

    def test_k8s_no_gpu_nodes_is_empty(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            if command[1:3] == ["get", "nodes"]:
                return completed(command, stdout=json.dumps({"items": []}))
            raise AssertionError("should not check without GPU nodes")

        payload = nic.build_check_payload(harness="k8s", env={}, runner=runner)
        self.assertEqual(payload["nic_topology"], {})

    def test_k8s_namespace_override_skips_autodetect(self) -> None:
        env = {"CLUSTERMAX_GPU_OPERATOR_NAMESPACE": "custom-ns"}

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            args = command[1:]
            self.assertNotEqual(args[:2], ["get", "namespace"], "override must skip namespace autodetect")
            if args[:2] == ["get", "nodes"]:
                return completed(command, stdout=json.dumps({"items": [{"metadata": {"name": "gpu-1"}, "status": {"capacity": {"nvidia.com/gpu": "8"}}}]}))
            if args[:2] == ["get", "pods"]:
                self.assertIn("custom-ns", args)
                return completed(command, stdout=json.dumps({"items": [{"metadata": {"name": "nvidia-driver-x"}, "status": {"phase": "Running"}}]}))
            if args[0] == "exec":
                self.assertIn("custom-ns", args)
                return completed(command, stdout=k8s_collector_output())
            raise AssertionError(f"unexpected call: {args}")

        payload = nic.build_check_payload(harness="k8s", env=env, runner=runner)
        self.assertEqual(set(payload["nic_topology"]), {"gpu-1"})

    def test_k8s_gpu_operator_namespace_is_independent_of_audit_check_namespace(self) -> None:
        env = {"CLUSTERMAX_AUDIT_K8S_NAMESPACE": "default"}
        payload = nic.build_check_payload(harness="k8s", env=env, runner=self._fake_kubectl())
        self.assertEqual(set(payload["nic_topology"]), {"gpu-1", "gpu-2"})

    def test_k8s_gpu_operator_namespace_accepts_nvidia(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            namespace = command[-1]
            return completed(command, returncode=0 if namespace == "nvidia" else 1)

        self.assertEqual(
            nic.k8s_gpu_namespace(env={}, runner=runner),
            "nvidia",
        )

    def test_k8s_gpu_operator_namespace_prefers_nvidia_over_generic_gpu(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            namespace = command[-1]
            return completed(
                command,
                returncode=0 if namespace in {"nvidia", "gpu"} else 1,
            )

        self.assertEqual(
            nic.k8s_gpu_namespace(env={}, runner=runner),
            "nvidia",
        )


SYNTHETIC_TOPO_LABELS = ["GPU0", "GPU1", "NIC0", "NIC1", "NIC2"]
SYNTHETIC_NODE_TOPO = "\n".join(
    ["\t" + "\t".join(SYNTHETIC_TOPO_LABELS)]
    + [
        row + "\t" + "\t".join("X" if row == col else "SYS" for col in SYNTHETIC_TOPO_LABELS)
        for row in SYNTHETIC_TOPO_LABELS
    ]
    + ["NIC Legend:"]
    + [f"  NIC{i}: mlx5_{i}" for i in range(3)]
)

class FabricAffinityFallbackTests(unittest.TestCase):
    """Synthetic no-affinity matrices exercise independent role rules."""

    def roles(self, classified: list) -> dict:
        return {n["name"]: n["role"] for n in classified}

    def test_synthetic_ib_promotes_top_rate_group(self) -> None:
        classified = nic.classify_nics(
            SYNTHETIC_NODE_TOPO,
            [
                ("mlx5_0", 200.0, "InfiniBand", "ACTIVE"),
                ("mlx5_1", 200.0, "InfiniBand", "ACTIVE"),
                ("mlx5_2", 200.0, "InfiniBand", "ACTIVE"),
                ("mlx5_bond_0", 100.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(
            {roles[f"mlx5_{i}"] for i in range(3)}, {"fabric"}
        )
        self.assertEqual(roles["mlx5_bond_0"], "storage")
        by_name = {n["name"]: n for n in classified}
        self.assertIn("no GPU-affinity signal", by_name["mlx5_0"]["reason"])
        self.assertIn("200 Gb/s", by_name["mlx5_0"]["reason"])

    def test_rail_named_roce_vfs_promote_and_storage_stays(self) -> None:
        classified = nic.classify_nics(
            SYNTHETIC_NODE_TOPO,
            [
                ("synthetic_rail0", 200.0, "Ethernet", "ACTIVE"),
                ("synthetic_rail1", 200.0, "Ethernet", "ACTIVE"),
                ("mlx5_8", 200.0, "Ethernet", "ACTIVE"),
                ("mlx5_bond_0", 200.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(
            {roles[f"synthetic_rail{i}"] for i in range(2)}, {"fabric"}
        )
        self.assertEqual(roles["mlx5_8"], "storage")
        self.assertEqual(roles["mlx5_bond_0"], "storage")

    def test_down_rail_pfs_stay_unpromoted_behind_active_vfs(self) -> None:
        classified = nic.classify_nics(
            SYNTHETIC_NODE_TOPO,
            [
                ("synthetic_rail0", 100.0, "Ethernet", "DOWN"),
                ("synthetic_vf_rail0", 100.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(roles["synthetic_vf_rail0"], "fabric")
        self.assertEqual(roles["synthetic_rail0"], "storage")

    def test_single_ib_hca_never_promotes(self) -> None:

        classified = nic.classify_nics(
            SYNTHETIC_NODE_TOPO,
            [("mlx5_0", 400.0, "InfiniBand", "ACTIVE")],
            [],
        )
        self.assertEqual(classified[0]["role"], "storage")

    def test_low_rate_rdma_ethernet_never_promotes(self) -> None:
        classified = nic.classify_nics(
            SYNTHETIC_NODE_TOPO,
            [
                ("synthetic_eth0", 100.0, "Ethernet", "ACTIVE"),
                ("synthetic_eth1", 100.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )
        self.assertEqual({n["role"] for n in classified}, {"storage"})

    def test_hgx_close_affinity_disables_fallback(self) -> None:

        topo = "\n".join(
            [
                "\tGPU0\tNIC0\tNIC1",
                "GPU0\t X \tPIX\tSYS",
                "NIC0\tPIX\t X \tSYS",
                "NIC1\tSYS\tSYS\t X ",
                "NIC Legend:",
                "  NIC0: mlx5_0",
                "  NIC1: mlx5_9",
            ]
        )
        classified = nic.classify_nics(
            topo,
            [
                ("mlx5_0", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_9", 800.0, "InfiniBand", "ACTIVE"),
            ],
            [],
        )
        roles = self.roles(classified)
        self.assertEqual(roles["mlx5_0"], "fabric")
        self.assertEqual(roles["mlx5_9"], "storage")
        by_name = {n["name"]: n for n in classified}
        self.assertEqual(by_name["mlx5_0"]["reason"], "PIX, PXB, or PHB to >=1 GPU")

    def test_topo_failure_still_recovers_fabric_roles(self) -> None:

        classified = nic.classify_nics(
            "",
            [
                ("mlx5_0", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_1", 800.0, "InfiniBand", "ACTIVE"),
            ],
            [],
        )
        self.assertEqual({n["role"] for n in classified}, {"fabric"})

if __name__ == "__main__":
    unittest.main()
