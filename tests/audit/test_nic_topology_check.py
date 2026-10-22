"""Unit tests for the NIC topology audit check fan-out."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
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

class PeerRecoveryTests(unittest.TestCase):
    def test_down_infiniBand_rail_keeps_fabric_role_from_peer_workers(self) -> None:
        active = {"name": "mlx5_8", "layer": "InfiniBand", "state": "ACTIVE", "role": "fabric"}
        down = {"name": "mlx5_8", "layer": "InfiniBand", "state": "DOWN", "role": "frontend", "rate_gbps": 10}
        records = [
            {"host": "p1", "nics": [down]},
            {"host": "p2", "nics": [active]},
            {"host": "p3", "nics": [active]},
            {"host": "p4", "nics": [active]},
        ]

        result = nic.aggregate(records)

        self.assertEqual(result["p1"][0]["role"], "fabric")
        self.assertEqual(result["p1"][0]["state"], "DOWN")
        self.assertIn("3 peer GPU workers", result["p1"][0]["reason"])
        self.assertEqual(down["role"], "frontend")

    def test_down_hca_needs_two_matching_active_fabric_peers(self) -> None:
        down = {"name": "mlx5_8", "layer": "InfiniBand", "state": "DOWN", "role": "frontend"}
        active = {"name": "mlx5_8", "layer": "InfiniBand", "state": "ACTIVE", "role": "fabric"}
        ethernet = {"name": "mlx5_8", "layer": "Ethernet", "state": "DOWN", "role": "frontend"}
        records = [
            {"host": "p1", "nics": [down, ethernet]},
            {"host": "p2", "nics": [active]},
        ]

        result = nic.aggregate(records)

        self.assertEqual([item["role"] for item in result["p1"]], ["frontend", "frontend"])

def test_slurm_ships_source_without_requiring_the_controller_path():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        assert "--input=all" in command
        assert str(Path(nic.__file__).resolve()) not in command
        assert kwargs["input"] == CHECK_PATH.read_text()
        return completed(command, stdout='{"host":"gpu-a","nics":[]}\n')

    nic.slurm_records(env={"SLURM_JOB_ID": "1"}, runner=runner)
    assert len(calls) == 1


class K8sAmdInventoryTests(unittest.TestCase):
    def test_k8s_uses_amd_device_plugin_for_ionic_inventory(self) -> None:
        nodes = {
            "items": [
                {
                    "metadata": {
                        "name": "mi355-worker",
                        "labels": {
                            "amd.com/gpu.product-name": "AMD_Instinct_MI355_OAM"
                        },
                    },
                    "status": {"capacity": {"amd.com/gpu": "8"}},
                }
            ]
        }
        pods = {
            "items": [
                {
                    "metadata": {"name": "amd-device-plugin-abcde"},
                    "spec": {"containers": [{"name": "device-plugin", "securityContext": {"privileged": True}}]},
                    "status": {"phase": "Running"},
                }
            ]
        }
        collector = "\n".join(
            [
                "@@TOPO_BEGIN@@",
                "@@TOPO_END@@",
                "@@HCA@@\trdma0\t400 Gb/sec (4X NDR)\tEthernet\t4: ACTIVE",
            ]
        )

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            args = command[1:]
            if args[:2] == ["get", "nodes"]:
                return completed(command, stdout=json.dumps(nodes))
            if args[:2] == ["get", "namespaces"]:
                return completed(command, returncode=1)
            if args[:2] == ["get", "namespace"]:
                return completed(
                    command, returncode=0 if args[2] == "kube-amd-gpu" else 1
                )
            if args[:2] == ["get", "pods"]:
                return completed(command, stdout=json.dumps(pods))
            if args[0] == "exec":
                self.assertIn("kube-amd-gpu", args)
                self.assertIn("amd-device-plugin-abcde", args)
                return completed(command, stdout=collector)
            raise AssertionError(f"unexpected kubectl call: {args}")

        payload = nic.build_check_payload(harness="k8s", env={}, runner=runner)

        self.assertEqual(payload["nic_topology"]["mi355-worker"][0]["name"], "rdma0")
        self.assertEqual(payload["nic_topology"]["mi355-worker"][0]["role"], "storage")


def vendor_completed(command, *, data=None, code=0, text=""):
    return subprocess.CompletedProcess(
        command, code, stdout=json.dumps(data) if data is not None else text, stderr=""
    )

@pytest.mark.parametrize("namespace", ["amd-gpu-operator", "synthetic-gpu-operator", "synthetic-nvidia-gpu"])
def test_namespace_discovery_reaches_standard_and_custom_operator_names(namespace):
    calls = []

    def runner(command, **kwargs):
        calls.append(command[1:])
        if command[1:3] == ["get", "namespaces"]:
            return vendor_completed(command, data={"items": [
                {"metadata": {"name": "unrelated"}},
                {"metadata": {"name": namespace}},
            ]})
        return vendor_completed(command, code=0 if command[-1] == namespace else 1)

    assert nic.k8s_gpu_namespace(env={}, runner=runner) == namespace
    if namespace.startswith("synthetic-"):
        assert ["get", "namespaces", "-o", "json"] in calls

@pytest.mark.parametrize("reply", ["not-json", "[]", '{"items":null}', '{"items":[null,{}]}'])
def test_unusable_namespace_inventory_retains_generic_fallback(reply):
    def runner(command, **kwargs):
        if command[1:3] == ["get", "namespaces"]:
            return vendor_completed(command, text=reply)
        return vendor_completed(command, code=0 if command[-1] == "gpu" else 1)

    assert nic.k8s_gpu_namespace(env={}, runner=runner) == "gpu"

@pytest.mark.parametrize("vendor", ["amd", "nvidia"])
def test_shipped_collector_only_runs_nvidia_topology_for_nvidia(tmp_path, vendor):
    marker = tmp_path / "called"
    binary = tmp_path / "nvidia-smi"
    binary.write_text('#!/bin/sh\nprintf called > "$MARKER"\nprintf "synthetic topology\\n"\n')
    binary.chmod(0o755)
    section = nic.K8S_COLLECTOR_SH.split("for d in /sys/class/infiniband/", 1)[0]
    result = subprocess.run(
        ["/bin/sh", "-c", f"CLUSTERMAX_GPU_VENDOR={vendor}\n{section}"],
        env={**os.environ, "PATH": str(tmp_path), "MARKER": str(marker)},
        capture_output=True, text=True, check=True,
    )
    assert marker.exists() == (vendor == "nvidia")
    assert ("synthetic topology" in result.stdout) == (vendor == "nvidia")

@pytest.mark.parametrize("vendors", [("amd",), ("nvidia", "amd")])
def test_amd_inventory_does_not_become_a_topology_failure_or_nvlink_proof(vendors, capsys):
    nodes = [{"metadata": {"name": f"synthetic-{vendor}"}, "status": {
        "capacity": {f"{vendor}.com/gpu": "1"},
    }} for vendor in vendors]

    def runner(command, **kwargs):
        args = command[1:]
        if args[:2] == ["get", "nodes"]:
            return vendor_completed(command, data={"items": nodes})
        if args[:2] == ["get", "pods"]:
            vendor = args[args.index("--field-selector") + 1].rsplit("-", 1)[1]
            return vendor_completed(command, data={"items": [{
                "metadata": {"name": f"{vendor}-device-plugin-synthetic"},
                "spec": {"containers": [{
                    "name": "synthetic-plugin", "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                }], "volumes": [{"name": "host", "hostPath": {"path": "/"}}]},
                "status": {"phase": "Running"},
            }]})
        if args[0] == "exec":
            vendor = "amd" if "amd-device-plugin-synthetic" in args else "nvidia"
            assert args[-1].startswith(f"CLUSTERMAX_GPU_VENDOR={vendor}\n")
            topo = "\tGPU0\tGPU1\nGPU0\tX\tNV2\nGPU1\tNV2\tX" if vendor == "nvidia" else ""
            return vendor_completed(command, text=(
                f"@@TOPO_BEGIN@@\n{topo}\n@@TOPO_END@@\n"
                "@@HCA@@\tsynthetic_rdma\t100 Gb/sec\tEthernet\t4: ACTIVE\n"
            ))
        raise AssertionError(args)

    payload = nic.build_check_payload(
        harness="k8s", env={"CLUSTERMAX_GPU_OPERATOR_NAMESPACE": "synthetic-gpu-operator"},
        runner=runner,
    )
    assert "nic_topology_status" not in payload
    assert "nvidia-smi topo -m failed" not in capsys.readouterr().err
    assert payload["nic_topology"]["synthetic-amd"][0]["name"] == "synthetic_rdma"
    assert payload["nvlink_topology"]["hosts"]["synthetic-amd"] == {
        "checked": False, "exposed": None, "applicable": False,
    }
    assert payload["nvlink_topology"]["coverageComplete"] == ("nvidia" in vendors)
    if "nvidia" in vendors:
        assert payload["nvlink_topology"]["hosts"]["synthetic-nvidia"] == {
            "checked": True, "exposed": True,
        }

@pytest.mark.parametrize(
    "nvidia_namespace,amd_namespace,list_allowed",
    [
        ("gpu-operator", "amd-gpu-operator", True),
        ("gpu-operator", "kube-amd-gpu", True),
        ("synthetic-nvidia-gpu", "synthetic-amd-gpu-operator", True),
        ("gpu-operator", "kube-amd-gpu", False),
    ],
)
@pytest.mark.parametrize("amd_available", [True, False])
def test_mixed_vendor_namespace_selection_without_a_shared_override(
    nvidia_namespace, amd_namespace, list_allowed, amd_available,
):
    namespaces = {"nvidia": nvidia_namespace, "amd": amd_namespace}
    calls = []

    def runner(command, **kwargs):
        args = command[1:]
        calls.append(args)
        if args[:2] == ["get", "nodes"]:
            return vendor_completed(command, data={"items": [{
                "metadata": {"name": f"synthetic-{vendor}"},
                "status": {"capacity": {f"{vendor}.com/gpu": "1"}},
            } for vendor in ("nvidia", "amd")]})
        if args[:2] == ["get", "namespaces"]:
            return vendor_completed(command, code=0 if list_allowed else 1, data={"items": [
                {"metadata": {"name": name}} for name in reversed(list(namespaces.values()))
            ]})
        if args[:2] == ["get", "namespace"]:
            return vendor_completed(command, code=0 if args[-1] in namespaces.values() else 1)
        if args[:2] == ["get", "pods"]:
            namespace = args[args.index("-n") + 1]
            vendor = args[args.index("--field-selector") + 1].rsplit("-", 1)[1]
            if namespace != namespaces[vendor] or (vendor == "amd" and not amd_available):
                return vendor_completed(command, data={"items": []})
            return vendor_completed(command, data={"items": [{
                "metadata": {"name": f"{vendor}-device-plugin-synthetic"},
                "spec": {
                    "containers": [{
                        "name": "synthetic-plugin", "securityContext": {"privileged": True},
                        "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                    }],
                    "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                },
                "status": {"phase": "Running"},
            }]})
        if args[0] == "exec":
            vendor = "amd" if "amd-device-plugin-synthetic" in args else "nvidia"
            assert args[args.index("-n") + 1] == namespaces[vendor]
            topo = "GPU0 X" if vendor == "nvidia" else ""
            return vendor_completed(command, text=(
                f"@@TOPO_BEGIN@@\n{topo}\n@@TOPO_END@@\n"
                "@@HCA@@\tsynthetic_rdma\t100 Gb/sec\tEthernet\t4: ACTIVE\n"
            ))
        raise AssertionError(args)

    records, errors = nic.k8s_records(env={}, runner=runner)
    assert {record["host"] for record in records} == (
        {"synthetic-nvidia", "synthetic-amd"} if amd_available else {"synthetic-nvidia"}
    )
    assert len([args for args in calls if args[:2] == ["get", "namespaces"]]) == 1
    if amd_available:
        assert errors == []
        amd, = [record for record in records if record["gpu_vendor"] == "amd"]
        assert amd["topo_applicable"] is False
    else:
        assert len(errors) == 1
        assert "synthetic-amd: no running amd" in errors[0]

@pytest.mark.parametrize(
    "vendor,pod",
    [
        ("amd", "nvidia-driver-synthetic"),
        ("amd", "gpu-feature-discovery-synthetic"),
        ("nvidia", "amd-device-plugin-synthetic"),
    ],
)
def test_pods_for_a_different_gpu_vendor_cannot_satisfy_the_check(vendor, pod):
    def runner(command, **kwargs):
        assert command[1:3] == ["get", "pods"]
        return vendor_completed(command, data={"items": [{
            "metadata": {"name": pod},
            "spec": {"containers": [{
                "name": "synthetic-plugin", "securityContext": {"privileged": True},
            }]},
            "status": {"phase": "Running"},
        }]})

    record, error = nic.run_k8s_node_check(
        "synthetic-shared", "synthetic-node", runner=runner, gpu_vendor=vendor,
    )
    assert record is None
    assert "no running GPU Operator system pod" in error


if __name__ == "__main__":
    unittest.main()


def _fake_pci(root, devices):
    for name, (vendor, pci_class) in devices.items():
        d = root / name
        d.mkdir()
        (d / "vendor").write_text(vendor + "\n")
        (d / "class").write_text(pci_class + "\n")


TOPO_ONE_GPU = "\tGPU0\tCPU Affinity\tNUMA Affinity\nGPU0\t X \t0-47\t0\n"


def test_host_gpu_visibility_flags_a_container_that_sees_one_of_four(tmp_path):
    # Four GPUs on the host (one 3D controller), their audio functions, and an
    # NVSwitch bridge that is not a GPU.
    _fake_pci(tmp_path, {
        "0000:aa:00.0": ("0x10de", "0x030000"), "0000:aa:00.1": ("0x10de", "0x040300"),
        "0000:ab:00.0": ("0x10de", "0x030000"), "0000:ac:00.0": ("0x10de", "0x030200"),
        "0000:ad:00.0": ("0x10de", "0x030000"), "0000:ae:00.0": ("0x10de", "0x068000"),
        "0000:af:00.0": ("0x15b3", "0x020700"),
    })
    assert nic.host_gpu_visibility(TOPO_ONE_GPU, str(tmp_path)) == {
        "hostGpuCount": 4, "visibleGpuCount": 1, "allHostGpusVisible": False,
    }


def test_host_gpu_visibility_whole_host_and_unreadable_sysfs(tmp_path):
    _fake_pci(tmp_path, {"0000:aa:00.0": ("0x10de", "0x030200")})
    assert nic.host_gpu_visibility(TOPO_ONE_GPU, str(tmp_path))["allHostGpusVisible"] is True
    assert nic.host_gpu_visibility(TOPO_ONE_GPU, str(tmp_path / "missing")) == {}
    assert nic.host_gpu_visibility("", str(tmp_path)) == {}
