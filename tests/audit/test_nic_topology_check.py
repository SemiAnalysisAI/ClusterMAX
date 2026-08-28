#!/usr/bin/env python3
"""Unit tests for the NIC topology audit check fan-out."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any


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


def completed(command: list[str], *, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def k8s_collector_output() -> str:
    """Mimic K8S_COLLECTOR_SH stdout (POSIX-sh, no python3 in the pod): topo
    block + tab-delimited per-HCA lines. mlx5_0 has PIX affinity -> fabric."""
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
    """A failed `nvidia-smi topo -m` must degrade visibly, never silently."""

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
        # Classification still ran via the no-affinity fallback path.
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
        # The graceful fallback the flag makes visible: with no topo output an
        # RDMA HCA loses its GPU affinity and lands on the storage heuristic.
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

        # The degraded host keeps its fallback classification...
        self.assertEqual(payload["nic_topology"]["gpu-a"][0]["role"], "storage")
        # ...and the degradation is recorded, per host, in the payload.
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

    def test_slurm_without_job_id_falls_back_to_local(self) -> None:
        def runner(_command: list[str], **_: Any) -> subprocess.CompletedProcess:
            raise AssertionError("srun should not run without SLURM_JOB_ID")

        payload = nic.build_check_payload(harness="slurm", env={}, runner=runner)
        # Local gather still produces exactly one host entry.
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
            if args[:2] == ["get", "namespace"]:
                return completed(command, returncode=0 if args[2] == "gpu-operator" else 1)
            if args[:2] == ["get", "pods"]:
                return completed(command, stdout=pods_json)
            if args[0] == "exec":
                # New k8s contract: exec `sh -c <collector>` (the driver pod has
                # no python3), parsed + classified on the orchestrator.
                self.assertIn("sh", args)
                return completed(command, stdout=k8s_collector_output())
            raise AssertionError(f"unexpected kubectl call: {args}")

        return runner

    def test_k8s_checks_each_gpu_node_via_driver_pod(self) -> None:
        payload = nic.build_check_payload(harness="k8s", env={}, runner=self._fake_kubectl())
        topo = payload["nic_topology"]
        # Keyed by node name (not the daemonset pod hostname), one entry per GPU node.
        self.assertEqual(set(topo), {"gpu-1", "gpu-2"})
        self.assertEqual(topo["gpu-1"][0]["role"], "fabric")

    def test_k8s_empty_topo_block_flags_host_and_keeps_fallback_roles(self) -> None:
        # nvidia-smi produced nothing inside the driver pod: the HCA lines are
        # still classified (storage fallback), and the payload records why.
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

    def test_k8s_falls_back_to_gpu_feature_discovery_when_driver_is_host_installed(self) -> None:
        pods = {
            "items": [
                {"metadata": {"name": "gpu-feature-discovery-abcde"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "nvidia-dcgm-exporter-abcde"}, "status": {"phase": "Running"}},
            ]
        }

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess:
            return completed(command, stdout=json.dumps(pods))

        self.assertEqual(
            nic.k8s_driver_pod("gpu-operator", "gpu-1", runner=runner),
            {
                "name": "gpu-feature-discovery-abcde",
                "container": None,
                "hostRoot": False,
            },
        )

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
            "cw-nvidia-gpu-operator", "gpu-1", runner=runner
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


GB300_NODE_TOPO = "\n".join(
    [
        # Grace superchip: GPUs reach NICs over C2C, so every GPU<->NIC cell
        # is NODE/SYS and the close-affinity rule can never fire.
        "\tGPU0\tGPU1\tNIC0\tNIC1\tNIC2\tNIC3",
        "GPU0\t X \tNV18\tNODE\tNODE\tSYS\tSYS",
        "GPU1\tNV18\t X \tSYS\tSYS\tNODE\tNODE",
        "NIC0\tNODE\tSYS\t X \tSYS\tSYS\tSYS",
        "NIC1\tNODE\tSYS\tSYS\t X \tSYS\tSYS",
        "NIC2\tSYS\tNODE\tSYS\tSYS\t X \tSYS",
        "NIC3\tSYS\tNODE\tSYS\tSYS\tSYS\t X ",
        "NIC Legend:",
        "  NIC0: mlx5_0",
        "  NIC1: mlx5_1",
        "  NIC2: mlx5_2",
        "  NIC3: mlx5_3",
    ]
)


class FabricAffinityFallbackTests(unittest.TestCase):
    """NVL72 superchips report no close-GPU affinity; roles must recover.

    Shapes below mirror committed audit artifacts: GMI/Azure/Nebius planarized
    4x800G XDR, Firmus mlx5_rail* RoCE VFs, OCI rdma_vf_rail* with DOWN PFs.
    """

    def roles(self, classified: list) -> dict:
        return {n["name"]: n["role"] for n in classified}

    def test_planarized_ib_gb300_promotes_top_rate_ib_group(self) -> None:
        # GMI/Nebius GB300 shape: 4x 800G IB scale-out + 400G Ethernet storage.
        classified = nic.classify_nics(
            GB300_NODE_TOPO,
            [
                ("mlx5_0", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_1", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_2", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_3", 800.0, "InfiniBand", "ACTIVE"),
                ("mlx5_bond_0", 400.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(
            {roles[f"mlx5_{i}"] for i in range(4)}, {"fabric"}
        )
        self.assertEqual(roles["mlx5_bond_0"], "storage")
        by_name = {n["name"]: n for n in classified}
        self.assertIn("no GPU-affinity signal", by_name["mlx5_0"]["reason"])
        self.assertIn("800 Gb/s", by_name["mlx5_0"]["reason"])

    def test_rail_named_roce_vfs_promote_and_storage_stays(self) -> None:
        # Firmus GB300 shape: rail-named 400G RoCE VFs + same-rate storage NICs.
        classified = nic.classify_nics(
            GB300_NODE_TOPO,
            [
                ("mlx5_rail0", 400.0, "Ethernet", "ACTIVE"),
                ("mlx5_rail1", 400.0, "Ethernet", "ACTIVE"),
                ("mlx5_rail2", 400.0, "Ethernet", "ACTIVE"),
                ("mlx5_rail3", 400.0, "Ethernet", "ACTIVE"),
                ("mlx5_8", 400.0, "Ethernet", "ACTIVE"),
                ("mlx5_bond_0", 400.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(
            {roles[f"mlx5_rail{i}"] for i in range(4)}, {"fabric"}
        )
        self.assertEqual(roles["mlx5_8"], "storage")
        self.assertEqual(roles["mlx5_bond_0"], "storage")

    def test_down_rail_pfs_stay_unpromoted_behind_active_vfs(self) -> None:
        # OCI GB300 shape: quad-plane 200G VFs ACTIVE, parent PFs DOWN.
        classified = nic.classify_nics(
            GB300_NODE_TOPO,
            [
                ("rdma_rail0", 200.0, "Ethernet", "DOWN"),
                ("rdma_rail1", 200.0, "Ethernet", "DOWN"),
                ("rdma_vf_rail0", 200.0, "Ethernet", "ACTIVE"),
                ("rdma_vf_rail1", 200.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )

        roles = self.roles(classified)
        self.assertEqual(roles["rdma_vf_rail0"], "fabric")
        self.assertEqual(roles["rdma_vf_rail1"], "fabric")
        self.assertEqual(roles["rdma_rail0"], "storage")
        self.assertEqual(roles["rdma_rail1"], "storage")

    def test_single_ib_hca_never_promotes(self) -> None:
        # One high-rate IB HCA is as likely a storage NIC; require >= 2.
        classified = nic.classify_nics(
            GB300_NODE_TOPO,
            [("mlx5_0", 400.0, "InfiniBand", "ACTIVE")],
            [],
        )
        self.assertEqual(classified[0]["role"], "storage")

    def test_low_rate_rdma_ethernet_never_promotes(self) -> None:
        # Azure mana 100G Ethernet must not ride the IB promotion.
        classified = nic.classify_nics(
            GB300_NODE_TOPO,
            [
                ("mana_0", 100.0, "Ethernet", "ACTIVE"),
                ("manae_0", 100.0, "Ethernet", "ACTIVE"),
            ],
            [],
        )
        self.assertEqual({n["role"] for n in classified}, {"storage"})

    def test_hgx_close_affinity_disables_fallback(self) -> None:
        # When PIX/PHB resolves (HGX), the first pass wins and nothing else
        # is promoted -- storage HCAs must not become fabric.
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
        # nvidia-smi absent/failed: empty topo, fallback still classifies.
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
