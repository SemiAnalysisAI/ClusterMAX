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
        self.assertEqual(nodes[0], {"name": "gpu-1", "gpu_count": 8, "gpu_model": "NVIDIA-B300", "gpu_memory_mb": 196608})
        self.assertEqual(nodes[1], {"name": "gpu-2", "gpu_count": 4, "gpu_model": "", "gpu_memory_mb": 0})

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
