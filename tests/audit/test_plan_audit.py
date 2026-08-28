#!/usr/bin/env python3
"""Unit tests for audit output planning."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PLAN_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "plan_audit.py"
)


def load_plan_module():
    spec = importlib.util.spec_from_file_location("plan_audit_under_test", PLAN_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan_audit = load_plan_module()


class PlanAuditTests(unittest.TestCase):
    def test_kubernetes_runtime_beats_headnode_sbatch_fallback(self) -> None:
        with (
            patch.dict(
                plan_audit.os.environ,
                {"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
                clear=True,
            ),
            patch.object(plan_audit.shutil, "which", return_value="/usr/bin/sbatch"),
        ):
            self.assertEqual(plan_audit.detect_harness(), "k8s")

    def test_infers_slug_from_nested_bench_audit_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            out_dir = repo_root / "runs" / "b300-cluster" / "20260601-010203" / "audit"

            self.assertEqual(
                plan_audit.slug_from_results_dir(repo_root, out_dir),
                "b300-cluster",
            )

    def test_direct_driver_fallback_uses_runs_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # plan_audit resolves the collector relative to its own location
            # The collector is relative to cmax/scripts/1-audit/plan_audit.py, so
            # repo_root only drives slug and OUT_DIR fallback inference.
            repo_root = Path(tmp).resolve()
            plan_path = repo_root / "plan.env"

            with (
                patch.dict(
                    plan_audit.os.environ,
                    {"CLUSTERMAX_AUDIT_HARNESS": "slurm", "CLUSTER_NAME": "direct-cluster"},
                    clear=True,
                ),
                patch.object(plan_audit, "now_ts", lambda: "20260601-010203"),
            ):
                rc = plan_audit.main(["plan_audit.py", str(repo_root), str(plan_path)])

            self.assertEqual(rc, 0)
            plan = dict(
                line.split("=", 1)
                for line in plan_path.read_text().splitlines()
                if line
            )
            self.assertEqual(plan["SLUG"], "direct-cluster")
            self.assertEqual(
                plan["OUT_DIR"],
                str(repo_root / "runs" / "direct-cluster" / "20260601-010203" / "audit"),
            )

    def test_explicit_slug_wins_with_custom_results_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            out_dir = repo_root / "audit" / "20260601-010203"
            plan_path = repo_root / "plan.env"

            with patch.dict(
                plan_audit.os.environ,
                {
                    "CLUSTERMAX_AUDIT_HARNESS": "standalone",
                    "CLUSTER_SLUG": "security-gpu-host",
                    "RUN_RESULTS_DIR": str(out_dir),
                },
                clear=True,
            ):
                rc = plan_audit.main(
                    ["plan_audit.py", str(repo_root), str(plan_path)]
                )

            self.assertEqual(rc, 0)
            plan = dict(
                line.split("=", 1)
                for line in plan_path.read_text().splitlines()
                if line
            )
            self.assertEqual(plan["SLUG"], "security-gpu-host")
            self.assertEqual(plan["OUT_DIR"], str(out_dir))


if __name__ == "__main__":
    unittest.main()
