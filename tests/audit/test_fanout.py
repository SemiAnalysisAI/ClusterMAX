#!/usr/bin/env python3
"""Unit tests for the shared check fan-out helper (checks/_fanout.py)."""

from __future__ import annotations

import importlib.util
import threading
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
    / "_fanout.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("_fanout_under_test", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fanout = load_module()


class ParseJsonLinesTests(unittest.TestCase):
    def test_skips_noise_and_keeps_dicts(self) -> None:
        stdout = "\n".join(
            [
                "srun: job step diagnostic",
                '{"host":"gpu-a","nics":[]}',
                "not json",
                "[1,2,3]",
                '{"host":"gpu-b","nics":[{"name":"mlx5_0"}]}',
            ]
        )
        records = fanout.parse_json_lines(stdout)
        self.assertEqual([r["host"] for r in records], ["gpu-a", "gpu-b"])

    def test_require_host_filters_hostless_objects(self) -> None:
        stdout = '{"no_host":true}\n{"host":"gpu-a"}'
        self.assertEqual(fanout.parse_json_lines(stdout, require_host=False), [{"no_host": True}, {"host": "gpu-a"}])
        self.assertEqual(fanout.parse_json_lines(stdout, require_host=True), [{"host": "gpu-a"}])


class K8sGpuNodesTests(unittest.TestCase):
    def test_vendor_filter_keeps_mixed_cluster_checks_scoped(self) -> None:
        nodes = {"items": [
            {"metadata": {"name": "nvidia-worker"}, "status": {"capacity": {"nvidia.com/gpu": "8"}}},
            {"metadata": {"name": "amd-worker"}, "status": {"capacity": {"amd.com/gpu": "8"}}},
        ]}
        self.assertEqual(
            [n["name"] for n in fanout.k8s_gpu_nodes(nodes, gpu_vendor="nvidia")],
            ["nvidia-worker"],
        )
        self.assertEqual(len(fanout.k8s_gpu_nodes(nodes)), 2)
    def test_returns_rich_dicts_for_gpu_nodes(self) -> None:
        nodes_json = {
            "items": [
                {
                    "metadata": {"name": "gpu-1", "labels": {"nvidia.com/gpu.product": "NVIDIA-B300", "nvidia.com/gpu.memory": "196608"}},
                    "status": {"capacity": {"nvidia.com/gpu": "8"}},
                },
                {"metadata": {"name": "cpu-1"}, "status": {"capacity": {}}},
                {"metadata": {"name": "gpu-2"}, "status": {"capacity": {"nvidia.com/gpu": "4"}}},
                {"metadata": {"name": ""}, "status": {"capacity": {"nvidia.com/gpu": "8"}}},
            ]
        }
        nodes = fanout.k8s_gpu_nodes(nodes_json)
        self.assertEqual([n["name"] for n in nodes], ["gpu-1", "gpu-2"])
        self.assertEqual(nodes[0], {"name": "gpu-1", "gpu_count": 8, "gpu_vendor": "nvidia", "gpu_model": "NVIDIA-B300", "gpu_memory_mb": 196608})
        self.assertEqual(nodes[1], {"name": "gpu-2", "gpu_count": 4, "gpu_vendor": "nvidia", "gpu_model": "", "gpu_memory_mb": 0})

    def test_uses_gpu_count_label_for_dra_nodes(self) -> None:
        nodes_json = {
            "items": [
                {
                    "metadata": {
                        "name": "dra-gpu-1",
                        "labels": {
                            "nvidia.com/gpu.count": "4",
                            "nvidia.com/gpu.product": "NVIDIA-GB300",
                        },
                    },
                    "status": {"capacity": {}},
                }
            ]
        }
        self.assertEqual(fanout.k8s_gpu_nodes(nodes_json)[0]["gpu_count"], 4)

    def test_returns_amd_operator_gpu_metadata(self) -> None:
        nodes_json = {
            "items": [
                {
                    "metadata": {
                        "name": "mi355-worker",
                        "labels": {
                            "amd.com/gpu.product-name": "AMD_Instinct_MI355_OAM",
                            "amd.com/gpu.vram": "288G",
                        },
                    },
                    "status": {"capacity": {"amd.com/gpu": "8"}},
                }
            ]
        }

        self.assertEqual(
            fanout.k8s_gpu_nodes(nodes_json),
            [
                {
                    "name": "mi355-worker",
                    "gpu_count": 8,
                    "gpu_vendor": "amd",
                    "gpu_model": "AMD_Instinct_MI355_OAM",
                    "gpu_memory_mb": 294912,
                }
            ],
        )

    def test_uses_beta_amd_labels_when_stable_labels_are_absent(self) -> None:
        nodes_json = {
            "items": [
                {
                    "metadata": {
                        "name": "mi300-worker",
                        "labels": {
                            "beta.amd.com/gpu.product-name": "AMD_Instinct_MI300X_OAM",
                            "beta.amd.com/gpu.vram": "192Gi",
                        },
                    },
                    "status": {"capacity": {"amd.com/gpu": "8"}},
                }
            ]
        }

        node = fanout.k8s_gpu_nodes(nodes_json)[0]
        self.assertEqual(node["gpu_model"], "AMD_Instinct_MI300X_OAM")
        self.assertEqual(node["gpu_memory_mb"], 196608)


class FanOutK8sTests(unittest.TestCase):
    def test_runs_independent_nodes_concurrently(self) -> None:
        nodes = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        lock = threading.Lock()
        release = threading.Event()
        started = 0
        peak = 0

        def per_node(node: dict[str, Any]):
            nonlocal started, peak
            with lock:
                started += 1
                peak = max(peak, started)
                if started == len(nodes):
                    release.set()
            self.assertTrue(release.wait(1), "fan-out ran nodes serially")
            return {"host": node["name"]}, None

        records, errors = fanout.fan_out_k8s(
            per_node, nodes=nodes, max_nodes=len(nodes)
        )

        self.assertGreater(peak, 1)
        self.assertEqual([record["host"] for record in records], ["a", "b", "c"])
        self.assertEqual(errors, [])

    def test_applies_per_node_and_collects_records_and_errors(self) -> None:
        nodes = [{"name": "a"}, {"name": "b"}, {"name": "c"}]

        def per_node(node: dict[str, Any]):
            if node["name"] == "b":
                return None, f"{node['name']}: boom"
            return {"host": node["name"]}, None

        records, errors = fanout.fan_out_k8s(per_node, nodes=nodes, max_nodes=len(nodes))
        self.assertEqual([r["host"] for r in records], ["a", "c"])
        self.assertEqual(errors, ["b: boom"])

    def test_cap_truncates_and_appends_message(self) -> None:
        nodes = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        calls: list[str] = []

        def per_node(node: dict[str, Any]):
            calls.append(node["name"])
            return {"host": node["name"]}, None

        records, errors = fanout.fan_out_k8s(per_node, nodes=nodes, max_nodes=1)
        self.assertEqual(calls, ["a"])
        self.assertEqual([r["host"] for r in records], ["a"])
        self.assertEqual(
            errors,
            ["checked 1 of 3 GPU nodes due to CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"],
        )


if __name__ == "__main__":
    unittest.main()


class SlurmPythonCommandTests(unittest.TestCase):
    def test_reads_broadcast_standard_input_instead_of_a_controller_path(self) -> None:
        command = fanout.slurm_python_command(
            node_count="4",
            worker_args=["--collect-host"],
        )
        self.assertEqual(
            command,
            [
                "srun",
                "--overlap",
                "--input=all",
                "-N",
                "4",
                "--ntasks-per-node=1",
                "python3",
                "-",
                "--collect-host",
            ],
        )


class SlurmGpusPerNodeTests(unittest.TestCase):
    @staticmethod
    def runner_for(stdout: str, returncode: int = 0):
        calls: list[list[str]] = []

        def runner(command: list[str], **_: Any):
            import subprocess

            calls.append(command)
            return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")

        return runner, calls

    def test_requests_the_gpus_an_exclusive_allocation_holds(self) -> None:
        # salloc --exclusive holds every GPU, but a step without --gres sees none.
        runner, calls = self.runner_for(
            "   AllocTRES=cpu=128,mem=1980G,node=1,billing=128,gres/gpu=8\n"
            "   JOB_GRES=gpu:h100:8\n"
            "     Nodes=gpu-a CPU_IDs=0-127 Mem=2027520 GRES=gpu:h100:8(IDX:0-7)\n"
        )
        count = fanout.slurm_gpus_per_node({"SLURM_JOB_ID": "7"}, runner)
        self.assertEqual(count, 8)
        self.assertEqual(calls, [["scontrol", "show", "job", "-d", "7"]])
        command = fanout.slurm_python_command(
            node_count="1", worker_args=["--worker"], gpus_per_node=count,
        )
        self.assertEqual(command[:7], [
            "srun", "--overlap", "--input=all", "-N", "1",
            "--ntasks-per-node=1", "--gres=gpu:8",
        ])

    def test_uses_the_smallest_per_node_count_and_untyped_gres(self) -> None:
        runner, _ = self.runner_for(
            "     Nodes=gpu-a CPU_IDs=0-63 Mem=1 GRES=gpu:8(IDX:0-7)\n"
            "     Nodes=gpu-b CPU_IDs=0-63 Mem=1 GRES=gpu:a:2(IDX:0-1),gpu:b:2(IDX:2-3)\n"
        )
        self.assertEqual(fanout.slurm_gpus_per_node({"SLURM_JOB_ID": "7"}, runner), 4)

    def test_no_request_when_gpu_count_is_not_known(self) -> None:
        cases = (
            ({}, "     Nodes=gpu-a GRES=gpu:8(IDX:0-7)\n", 0),            # no job
            ({"SLURM_JOB_ID": "7"}, "", 1),                             # scontrol denied
            ({"SLURM_JOB_ID": "7"}, "     Nodes=cpu-a CPU_IDs=0-63 Mem=1\n", 0),
            ({"SLURM_JOB_ID": "7"},
             "     Nodes=gpu-a GRES=gpu:8(IDX:0-7)\n     Nodes=cpu-a CPU_IDs=0-3 Mem=1\n", 0),
        )
        for env, stdout, rc in cases:
            runner, _ = self.runner_for(stdout, rc)
            self.assertIsNone(fanout.slurm_gpus_per_node(env, runner), stdout)
        self.assertNotIn(
            "--gres=gpu:0",
            " ".join(fanout.slurm_python_command(node_count="1", worker_args=[], gpus_per_node=None)),
        )

    def test_missing_scontrol_is_not_fatal(self) -> None:
        def runner(command: list[str], **_: Any):
            raise FileNotFoundError("scontrol")

        self.assertIsNone(fanout.slurm_gpus_per_node({"SLURM_JOB_ID": "7"}, runner))
