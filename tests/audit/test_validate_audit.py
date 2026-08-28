#!/usr/bin/env python3
"""Unit tests for audit publish validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


VALIDATE_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "validate_audit.py"
)


def load_validate_module():
    spec = importlib.util.spec_from_file_location("validate_audit_under_test", VALIDATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validate_audit = load_validate_module()


class ValidateAuditTests(unittest.TestCase):
    def test_k8s_gpu_cluster_requires_driver_facts(self) -> None:
        audit = {
            "gpus": {"total": 32, "driverVersion": "unknown"},
            "software": {"workerCheckOk": False},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            Path(tmp.name).write_text("{}")
            self.assertFalse(
                validate_audit.validate_worker_check(audit, "k8s", Path(tmp.name))
            )

    def test_k8s_accepts_host_check_driver_fallback(self) -> None:
        audit = {
            "gpus": {"total": 32, "driverVersion": "unknown"},
            "hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"},
            "software": {"workerCheckOk": True},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertTrue(
                validate_audit.validate_worker_check(audit, "k8s", Path(tmp.name))
            )

    def test_k8s_without_gpus_skips_driver_gate(self) -> None:
        audit = {"gpus": {"total": 0}}
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertTrue(
                validate_audit.validate_worker_check(audit, "k8s", Path(tmp.name))
            )

    def test_k8s_not_found_driver_without_host_check_fails_gate(self) -> None:
        audit = {
            "gpus": {"total": 32, "driverVersion": "not-found"},
            "software": {"workerCheckOk": False},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertFalse(
                validate_audit.validate_worker_check(audit, "k8s", Path(tmp.name))
            )

    def test_k8s_na_host_check_driver_counts_as_missing(self) -> None:
        audit = {
            "gpus": {"total": 32, "driverVersion": "not-found"},
            "hostCheck": {"WORKER_DRIVER_VERSION": "N/A"},
            "software": {"workerCheckOk": False},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertFalse(
                validate_audit.validate_worker_check(audit, "k8s", Path(tmp.name))
            )

    def test_slurm_worker_check_failure_blocks_publish(self) -> None:
        audit = {"software": {"workerCheckOk": False}}
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertFalse(
                validate_audit.validate_worker_check(audit, "slurm", Path(tmp.name))
            )

    def test_slurm_worker_check_success_allows_publish(self) -> None:
        audit = {"software": {"workerCheckOk": True}}
        with tempfile.NamedTemporaryFile("w", suffix=".json") as tmp:
            self.assertTrue(
                validate_audit.validate_worker_check(audit, "slurm", Path(tmp.name))
            )


if __name__ == "__main__":
    unittest.main()
