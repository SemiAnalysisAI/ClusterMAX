#!/usr/bin/env python3
"""Tests for the individual platform configuration check entry points."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CHECK_ROOT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
)
sys.path.insert(0, str(CHECK_ROOT))
import platform_config


ENTRYPOINTS = {
    "system/vm-iommu-check.py": "vm_iommu",
    "system/arm-smmu-virtualization-check.py": "arm_smmu_virtualization",
    "fabric/nccl-topology-file-check.py": "nccl_topo_file",
    "fabric/nccl-ib-qps-check.py": "nccl_ib_qps",
}


class PlatformCheckEntrypointTests(unittest.TestCase):
    def test_shared_module_loads_fanout_without_an_entrypoint_import(self) -> None:
        script = (
            "import importlib.util\n"
            f"path = {str(CHECK_ROOT / 'platform_config.py')!r}\n"
            "spec = importlib.util.spec_from_file_location('platform_config_isolated', path)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "print(module.load_fanout().__file__)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                cwd=tmp,
            )

        self.assertEqual(
            Path(run.stdout.strip()).resolve(),
            (CHECK_ROOT / "_fanout.py").resolve(),
        )

    def test_each_entrypoint_emits_only_its_check(self) -> None:
        payload = {
            key: {"status": "pass", "message": f"{key} passed"}
            for key in ENTRYPOINTS.values()
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "platform-config.json"
            cache.write_text(
                json.dumps({"harness": "slurm", "payload": payload})
            )
            env = {
                **os.environ,
                "CLUSTERMAX_AUDIT_HARNESS": "slurm",
                platform_config.CACHE_PATH_ENV: str(cache),
            }
            for relative, key in ENTRYPOINTS.items():
                with self.subTest(check=relative):
                    run = subprocess.run(
                        [sys.executable, str(CHECK_ROOT / relative)],
                        check=True,
                        capture_output=True,
                        text=True,
                        env=env,
                    )
                    self.assertEqual(json.loads(run.stdout), {key: payload[key]})

    def test_named_checks_reuse_collection_from_the_audit_cache(self) -> None:
        payload = {
            key: {"status": "pass", "message": f"{key} passed"}
            for key in platform_config.ALL_CHECK_KEYS
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "platform-config.json"
            with mock.patch.dict(
                os.environ,
                {
                    platform_config.CACHE_PATH_ENV: str(cache),
                    platform_config.REQUESTED_CHECKS_ENV: ",".join(payload),
                },
                clear=False,
            ), mock.patch.object(
                platform_config,
                "run_default_check",
                return_value=payload,
            ) as collect:
                first = platform_config.run_named_check("vm_iommu", "slurm")
                second = platform_config.run_named_check("nccl_ib_qps", "slurm")

        self.assertEqual(first, {"vm_iommu": payload["vm_iommu"]})
        self.assertEqual(second, {"nccl_ib_qps": payload["nccl_ib_qps"]})
        collect.assert_called_once_with("slurm", set(payload))

    def test_hardware_check_omits_scale_out_collection(self) -> None:
        report = {
            "host": "node-0",
            "summaries": {
                "vm_iommu": {
                    "status": "pass",
                    "message": "IOMMU uses passthrough",
                },
                "arm_smmu_virtualization": {
                    "status": "not_applicable",
                    "message": "the host is not an Arm guest",
                },
            },
            "nccl": {},
        }
        payload = {
            "vm_iommu": report["summaries"]["vm_iommu"],
            "arm_smmu_virtualization": report["summaries"][
                "arm_smmu_virtualization"
            ],
            "nccl_topo_file": {"status": "not_applicable", "message": "none"},
            "nccl_ib_qps": {"status": "not_applicable", "message": "none"},
        }
        with mock.patch.object(
            platform_config,
            "run_slurm_check",
            return_value=([report], []),
        ) as collect, mock.patch.object(
            platform_config,
            "slurm_cluster_node_count",
            side_effect=AssertionError("hardware check must not count fabric nodes"),
        ), mock.patch.object(
            platform_config,
            "slurm_fabric_tiers",
            side_effect=AssertionError("hardware check must not inspect fabric tiers"),
        ), mock.patch.object(
            platform_config,
            "run_container_check",
            side_effect=AssertionError("hardware check must not start a container"),
        ), mock.patch.object(
            platform_config,
            "build_payload",
            return_value=payload,
        ):
            result = platform_config.run_default_check("slurm", {"vm_iommu"})

        self.assertEqual(result, {"vm_iommu": payload["vm_iommu"]})
        collect.assert_called_once_with(
            "slurm",
            include_scale_out=False,
            include_rdma_iommu=True,
        )


if __name__ == "__main__":
    unittest.main()
