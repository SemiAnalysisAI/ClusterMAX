
"""Unit tests for the NVIDIA vboost audit check."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from unittest import mock
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
    def test_missing_worker_results_never_run_local_vboost(self) -> None:
        for harness in ("slurm", "k8s"):
            with self.subTest(harness=harness):
                with mock.patch.object(vboost, "slurm_vboost_results", return_value=([], {"status": "missing"})), \
                        mock.patch.object(vboost, "k8s_vboost_results", return_value=([], ["missing"])), \
                        mock.patch.object(vboost, "local_vboost_result") as local:
                    result = vboost.build_check_payload(harness=harness, env={})["gpu_controls"]["vboost"]
                local.assert_not_called()
                self.assertFalse(result["checked"])
                self.assertEqual(result["checked_nodes"], 0)
                self.assertEqual(result["status"], "not_checked")
                self.assertEqual(result["mode"], harness)

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

    def test_no_visible_gpu_is_not_a_provider_denial(self) -> None:
        # A Slurm step in an allocation without GPUs runs as root but sees no
        # device, so nvidia-smi exits 6 with "No devices were found".
        def which(name: str) -> str | None:
            return {"nvidia-smi": "/usr/bin/nvidia-smi"}.get(name)

        for stdout, stderr in (("No devices were found", ""), ("", "No devices found.")):
            def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(command, 6, stdout=stdout, stderr=stderr)

            result = vboost.local_vboost_result(
                runner=runner, which=which, euid=lambda: 0, hostname=lambda: "gpu-a",
            )
            self.assertFalse(result["allowed"])
            self.assertEqual(result["status"], "no_gpu_visible")
            self.assertEqual(result["method"], "root")
        self.assertEqual(vboost.aggregate_status([result]), "unavailable")
        self.assertEqual(
            vboost.aggregate_status([result, {"allowed": False, "status": "denied"}]),
            "denied",
        )

    def test_k8s_driver_pod_without_visible_gpu_is_not_a_denial(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            if command[:3] == ["kubectl", "get", "pods"]:
                pods = {"items": [{"metadata": {"name": "nvidia-driver-daemonset-a"},
                                   "status": {"phase": "Running"}}]}
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(pods), stderr="")
            return subprocess.CompletedProcess(command, 6, stdout="No devices were found", stderr="")

        result, error = vboost.k8s_vboost_node("gpu-operator", "gpu-a", runner=runner)
        self.assertIsNone(error)
        self.assertEqual(result["status"], "no_gpu_visible")

    def test_k8s_amd_only_cluster_is_not_applicable(self) -> None:
        nodes = {
            "items": [
                {
                    "metadata": {"name": "mi355-worker"},
                    "status": {"capacity": {"amd.com/gpu": "8"}},
                }
            ]
        }

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            if command[1:3] == ["get", "nodes"]:
                return subprocess.CompletedProcess(command, 0, json.dumps(nodes), "")
            raise AssertionError(f"an AMD-only cluster has no vboost to test: {command}")

        status = vboost.build_check_payload(
            harness="k8s", env={}, runner=runner, which=lambda _name: None
        )["gpu_controls"]["vboost"]

        self.assertEqual(status["mode"], "k8s")
        self.assertEqual(status["status"], "not_applicable")
        self.assertFalse(status["checked"])
        self.assertEqual(status["nodes"], [])
        self.assertEqual(status["reason"], vboost.VBOOST_AMD_NOT_APPLICABLE)
        self.assertNotIn("errors", status)

    def test_k8s_cluster_without_gpu_nodes_is_still_an_error(self) -> None:
        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            if command[1:3] == ["get", "nodes"]:
                return subprocess.CompletedProcess(command, 0, json.dumps({"items": []}), "")
            raise AssertionError(f"unexpected command: {command}")

        status = vboost.build_check_payload(
            harness="k8s", env={}, runner=runner, which=lambda _name: None
        )["gpu_controls"]["vboost"]

        self.assertEqual(status["status"], "not_checked")
        self.assertIn("amd.com/gpu", status["errors"][0]["message"])

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
        self.assertTrue(status["checked"])
        self.assertFalse(status["allowed"])

    def test_mixed_check_failures_aggregate_to_unavailable_but_real_denial_wins(self) -> None:

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

    def test_slurm_step_requests_the_allocation_gpus(self) -> None:
        env = {"SLURM_JOB_ID": "123", "SLURM_NNODES": "1"}
        commands: list[list[str]] = []

        def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[0] == "scontrol":
                return subprocess.CompletedProcess(
                    command, 0, stderr="",
                    stdout="     Nodes=gpu-a CPU_IDs=0-127 Mem=1 GRES=gpu:h100:8(IDX:0-7)\n",
                )
            return subprocess.CompletedProcess(
                command, 0, stderr="", stdout='{"host":"gpu-a","allowed":true,"status":"allowed"}',
            )

        payload = vboost.build_check_payload(
            harness="slurm", env=env, runner=runner,
            which=lambda name: {"srun": "/usr/bin/srun"}.get(name),
        )
        srun = next(command for command in commands if command[0] == "srun")
        self.assertIn("--gres=gpu:8", srun)
        self.assertEqual(payload["gpu_controls"]["vboost"]["status"], "allowed")

if __name__ == "__main__":
    unittest.main()
