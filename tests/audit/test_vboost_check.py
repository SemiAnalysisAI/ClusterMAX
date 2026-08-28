#!/usr/bin/env python3
"""Unit tests for the NVIDIA vboost audit check."""

from __future__ import annotations

import importlib.util
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
    / "gpu"
    / "vboost.py"
)


def load_check_module():
    spec = importlib.util.spec_from_file_location("vboost_check_under_test", CHECK_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vboost = load_check_module()


class VboostCheckTests(unittest.TestCase):
    def test_b300_family_is_not_applicable_without_running_vboost(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            raise AssertionError(f"vboost must not run on B300: {command}")

        for model in (
            "NVIDIA B300",
            "NVIDIA-B300-SXM6-AC",
            "NVIDIA GB300",
            "GB300 NVL72",
        ):
            result = vboost.build_check_payload(
                harness="slurm",
                env={"CLUSTERMAX_AUDIT_GPU_MODEL": model},
                runner=runner,
                which=lambda _name: None,
            )["gpu_controls"]["vboost"]

            self.assertFalse(result["checked"])
            self.assertEqual(result["status"], "not_applicable")
            self.assertEqual(result["checked_nodes"], 0)

        self.assertFalse(vboost.is_vboost_unsupported_model("NVIDIA B200"))

    def test_local_check_records_allowed_sudo_change(self) -> None:
        calls: list[list[str]] = []

        def which(name: str) -> str | None:
            return {
                "nvidia-smi": "/usr/bin/nvidia-smi",
                "sudo": "/usr/bin/sudo",
            }.get(name)

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="Updated vboost\n", stderr="")

        result = vboost.local_vboost_result(
            runner=runner,
            which=which,
            euid=lambda: 1000,
            hostname=lambda: "gpu-node-1",
        )

        self.assertEqual(calls, [["/usr/bin/sudo", "-n", "/usr/bin/nvidia-smi", "boost-slider", "--vboost", "2"]])
        self.assertTrue(result["allowed"])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["method"], "sudo")
        self.assertEqual(result["host"], "gpu-node-1")

    def test_local_check_records_provider_denial(self) -> None:
        def which(name: str) -> str | None:
            return {"nvidia-smi": "/usr/bin/nvidia-smi", "sudo": "/usr/bin/sudo"}.get(name)

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="Insufficient Permissions")

        result = vboost.local_vboost_result(
            runner=runner,
            which=which,
            euid=lambda: 1000,
            hostname=lambda: "locked-node",
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("Insufficient Permissions", result["stderr"])

    def test_local_check_skips_when_nvidia_smi_is_missing(self) -> None:
        def runner(_command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            raise AssertionError("runner should not be called")

        result = vboost.local_vboost_result(
            runner=runner,
            which=lambda _name: None,
            hostname=lambda: "cpu-only",
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["status"], "nvidia_smi_missing")
        self.assertIsNone(result["exit_code"])

        payload = vboost.build_check_payload(
            harness="standalone",
            runner=runner,
            which=lambda _name: None,
        )
        self.assertEqual(payload["gpu_controls"]["vboost"]["status"], "unavailable")

    def test_local_check_handles_nvidia_smi_exec_error(self) -> None:
        # nvidia-smi is on PATH but cannot be executed (stub / wrong-arch binary on
        # a non-GPU login node). The runner raises OSError; the check must report a
        # failure rather than letting the exception crash the whole audit.
        def which(name: str) -> str | None:
            return {"nvidia-smi": "/usr/bin/nvidia-smi", "sudo": "/usr/bin/sudo"}.get(name)

        def runner(_command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            raise OSError(8, "Exec format error", "/usr/bin/nvidia-smi")

        result = vboost.local_vboost_result(
            runner=runner,
            which=which,
            euid=lambda: 1000,
            hostname=lambda: "login-1",
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["status"], "nvidia_smi_error")
        self.assertIsNone(result["exit_code"])
        self.assertIn("Exec format error", result["stderr"])

    def test_all_nvidia_smi_error_run_aggregates_to_unavailable(self) -> None:
        # GCore Soperator login node: nvidia-smi is a monitoring stub that
        # raises OSError on every node the check reaches. The control was never
        # exercised, so the aggregate must be "unavailable" (missing data), not
        # "denied" - "denied" grades as a vendor-facing FAIL downstream.
        def which(name: str) -> str | None:
            return {"nvidia-smi": "/usr/bin/nvidia-smi", "sudo": "/usr/bin/sudo"}.get(name)

        def runner(_command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            raise OSError(8, "Exec format error", "/usr/bin/nvidia-smi")

        payload = vboost.build_check_payload(
            harness="standalone",
            runner=runner,
            which=which,
        )
        status = payload["gpu_controls"]["vboost"]

        self.assertEqual(status["status"], "unavailable")
        self.assertNotEqual(status["status"], "denied")
        self.assertTrue(status["checked"])
        self.assertFalse(status["allowed"])

    def test_mixed_check_failures_aggregate_to_unavailable_but_real_denial_wins(self) -> None:
        # Any mix of pure check failures is still "unavailable"; one genuine
        # denial among them means the control was exercised and refused.
        failures = [
            {"allowed": False, "status": "nvidia_smi_error"},
            {"allowed": False, "status": "nvidia_smi_missing"},
            {"allowed": False, "status": "timeout"},
        ]
        self.assertEqual(vboost.aggregate_status(failures), "unavailable")
        self.assertEqual(
            vboost.aggregate_status(failures + [{"allowed": False, "status": "denied"}]),
            "denied",
        )

    def test_slurm_check_aggregates_per_node_results(self) -> None:
        env = {"SLURM_JOB_ID": "123", "SLURM_NNODES": "2"}

        def which(name: str) -> str | None:
            return {"srun": "/usr/bin/srun"}.get(name)

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            stdout = "\n".join(
                [
                    '{"host":"gpu-a","allowed":true,"status":"allowed"}',
                    "srun: job diagnostic line",
                    '{"host":"gpu-b","allowed":false,"status":"denied","stderr":"locked"}',
                ]
            )
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        payload = vboost.build_check_payload(
            harness="slurm",
            env=env,
            runner=runner,
            which=which,
        )
        status = payload["gpu_controls"]["vboost"]

        self.assertEqual(status["mode"], "slurm")
        self.assertEqual(status["status"], "partial")
        self.assertFalse(status["allowed"])
        self.assertEqual(status["checked_nodes"], 2)
        self.assertEqual(status["allowed_nodes"], 1)

    def test_k8s_falls_back_to_gpu_feature_discovery_when_driver_is_host_installed(self) -> None:
        pods = {
            "items": [
                {"metadata": {"name": "gpu-feature-discovery-abcde"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "nvidia-dcgm-exporter-abcde"}, "status": {"phase": "Running"}},
            ]
        }

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(pods), stderr="")

        self.assertEqual(
            vboost.k8s_driver_pod("gpu-operator", "gpu-1", runner=runner),
            "gpu-feature-discovery-abcde",
        )

    def test_k8s_gpu_operator_namespace_is_independent_of_audit_check_namespace(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            namespace = command[-1]
            return subprocess.CompletedProcess(
                command,
                0 if namespace == "gpu-operator" else 1,
                stdout="",
                stderr="",
            )

        namespace = vboost.k8s_gpu_namespace(
            env={"CLUSTERMAX_AUDIT_K8S_NAMESPACE": "default"},
            runner=runner,
        )

        self.assertEqual(namespace, "gpu-operator")
        self.assertEqual(calls[0][-1], "gpu-operator")

    def test_k8s_gpu_operator_namespace_accepts_nvidia(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            namespace = command[-1]
            return subprocess.CompletedProcess(
                command,
                0 if namespace == "nvidia" else 1,
                stdout="",
                stderr="",
            )

        self.assertEqual(
            vboost.k8s_gpu_namespace(env={}, runner=runner),
            "nvidia",
        )

    def test_k8s_gpu_operator_namespace_prefers_nvidia_over_generic_gpu(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            namespace = command[-1]
            return subprocess.CompletedProcess(
                command,
                0 if namespace in {"nvidia", "gpu"} else 1,
                stdout="",
                stderr="",
            )

        self.assertEqual(
            vboost.k8s_gpu_namespace(env={}, runner=runner),
            "nvidia",
        )


if __name__ == "__main__":
    unittest.main()
