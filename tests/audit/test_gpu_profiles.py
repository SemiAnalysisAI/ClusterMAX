#!/usr/bin/env python3
"""Unit tests for Kubernetes heterogeneous GPU profile selection."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "gpu_profiles.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("gpu_profiles_under_test", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gpu_profiles = load_module()


def node(name: str, model: str | None, gpus: int, cpu: str, memory: str) -> dict:
    labels = {}
    if model is not None:
        labels["nvidia.com/gpu.product"] = model
        labels["nvidia.com/gpu.memory"] = "183359" if "B200" in model else "23028"
    return {
        "metadata": {"name": name, "labels": labels},
        "status": {
            "capacity": {
                "nvidia.com/gpu": str(gpus),
                "cpu": cpu,
                "memory": memory,
            }
        },
    }


class GpuProfileTests(unittest.TestCase):
    def test_uses_shared_kubernetes_memory_quantity_parser(self) -> None:
        self.assertEqual(gpu_profiles.kubernetes_memory_gib("1024Mi"), 1.0)
        self.assertEqual(gpu_profiles.kubernetes_memory_gib("2Ti"), 2048.0)

    def test_selects_profile_with_most_installed_gpus(self) -> None:
        nodes = [
            *(node(f"b200-{index}", "NVIDIA-B200", 8, "192", "2092988110Ki") for index in range(4)),
            node("inference-a10g", "NVIDIA-A10G", 1, "8", "31887364Ki"),
            node("inference-l4", "NVIDIA-L4", 1, "16", "65118400Ki"),
            node("system", None, 0, "4", "8Gi"),
        ]

        inventory = gpu_profiles.select_gpu_profiles(
            {"items": nodes}, resource_key="nvidia.com/gpu", vendor="nvidia"
        )

        self.assertEqual(inventory["primary"]["model"], "NVIDIA-B200")
        self.assertEqual(inventory["primary"]["perNode"], 8)
        self.assertEqual(inventory["primary"]["nodeCount"], 4)
        self.assertEqual(inventory["primary"]["totalGpus"], 32)
        self.assertEqual(inventory["primary"]["totalCpus"], 768)
        self.assertEqual(inventory["primary"]["memoryMB"], "183359")
        self.assertEqual(len(inventory["profiles"]), 3)

    def test_ties_prefer_more_nodes_then_more_gpus_per_node(self) -> None:
        nodes = [
            node("dense", "NVIDIA-DENSE", 8, "32", "64Gi"),
            node("wide-1", "NVIDIA-WIDE", 4, "16", "32Gi"),
            node("wide-2", "NVIDIA-WIDE", 4, "16", "32Gi"),
        ]

        inventory = gpu_profiles.select_gpu_profiles(
            {"items": nodes}, resource_key="nvidia.com/gpu", vendor="nvidia"
        )

        self.assertEqual(inventory["primary"]["model"], "NVIDIA-WIDE")
        self.assertEqual(inventory["primary"]["nodeCount"], 2)

    def test_returns_no_primary_profile_without_gpu_nodes(self) -> None:
        inventory = gpu_profiles.select_gpu_profiles(
            {"items": [node("system", None, 0, "4", "8Gi")]},
            resource_key="nvidia.com/gpu",
            vendor="nvidia",
        )

        self.assertIsNone(inventory["primary"])
        self.assertEqual(inventory["profiles"], [])

    def test_missing_model_label_stays_unknown_for_host_check_fallback(self) -> None:
        inventory = gpu_profiles.select_gpu_profiles(
            {"items": [node("unlabelled", None, 8, "192", "2Ti")]},
            resource_key="nvidia.com/gpu",
            vendor="nvidia",
        )

        self.assertEqual(inventory["primary"]["model"], "unknown")

    def test_secondary_doks_label_does_not_relabel_dense_unlabelled_profile(self) -> None:
        dense = node("dense", None, 8, "192", "2Ti")
        secondary = node("secondary", None, 1, "8", "32Gi")
        secondary["metadata"]["labels"].update(
            {
                "doks.digitalocean.com/gpu-brand": "nvidia",
                "doks.digitalocean.com/gpu-model": "h100",
            }
        )

        inventory = gpu_profiles.select_gpu_profiles(
            {"items": [dense, secondary]},
            resource_key="nvidia.com/gpu",
            vendor="nvidia",
        )

        self.assertEqual(inventory["primary"]["model"], "unknown")
        self.assertEqual(inventory["profiles"][1]["model"], "NVIDIA H100")

    def test_resolves_missing_primary_facts_from_primary_scoped_check(self) -> None:
        inventory = gpu_profiles.select_gpu_profiles(
            {
                "items": [
                    node("dense", None, 8, "192", "2Ti"),
                    node("secondary", "NVIDIA-L4", 1, "16", "64Gi"),
                ]
            },
            resource_key="nvidia.com/gpu",
            vendor="nvidia",
        )

        resolved = gpu_profiles.resolve_primary_profile(
            inventory,
            model="NVIDIA B200",
            memory_mb="183359",
        )

        self.assertEqual(resolved["primary"]["model"], "NVIDIA B200")
        self.assertEqual(resolved["primary"]["memoryMB"], "183359")
        self.assertEqual(resolved["profiles"][0]["model"], "NVIDIA B200")
        self.assertEqual(resolved["profiles"][0]["memoryMB"], "183359")
        self.assertEqual(resolved["profiles"][1]["model"], "NVIDIA-L4")


if __name__ == "__main__":
    unittest.main()
