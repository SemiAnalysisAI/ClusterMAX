#!/usr/bin/env python3
"""Unit tests for HBM exposure and kubelet CPU Manager audit results."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
CHECK_PATH = AUDIT_SCRIPTS / "checks" / "system" / "hbm_memory_exposure.py"
SPEC = importlib.util.spec_from_file_location("hbm_memory_exposure", CHECK_PATH)
assert SPEC and SPEC.loader
hbm_memory_exposure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hbm_memory_exposure)

RUN_CHECKS_PATH = AUDIT_SCRIPTS / "run_checks.py"
RUN_CHECKS_SPEC = importlib.util.spec_from_file_location("run_checks", RUN_CHECKS_PATH)
assert RUN_CHECKS_SPEC and RUN_CHECKS_SPEC.loader
run_checks = importlib.util.module_from_spec(RUN_CHECKS_SPEC)
RUN_CHECKS_SPEC.loader.exec_module(run_checks)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_node(root: Path, node_id: int, mem_kb: int, cpulist: str) -> None:
    node = root / "sys/devices/system/node" / f"node{node_id}"
    write(node / "cpulist", cpulist)
    write(node / "meminfo", f"Node {node_id} MemTotal:       {mem_kb} kB\n")


class HbmMemoryExposureTests(unittest.TestCase):
    def test_detects_gb200_hbm_memory_only_numa_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpu_node_kb = 512 * hbm_memory_exposure.GIB_KB
            hbm_node_kb = 294912 * 1024
            total_kb = (2 * cpu_node_kb) + (4 * hbm_node_kb)

            write(root / "proc/meminfo", f"MemTotal:       {total_kb} kB\n")
            write(root / "proc/sys/kernel/hostname", "gb200-node-0\n")
            write(root / "proc/driver/nvidia/params", 'CoherentGPUMemoryMode: ""\n')
            write(
                root / "var/lib/kubelet/cpu_manager_state",
                json.dumps({"policyName": "none", "defaultCpuSet": ""}),
            )
            write(root / "sys/devices/system/node/online", "0-5\n")
            write_node(root, 0, cpu_node_kb, "0-63")
            write_node(root, 1, cpu_node_kb, "64-127")
            for node_id in range(2, 6):
                write_node(root, node_id, hbm_node_kb, "")

            report = hbm_memory_exposure.collect_host(
                root=root,
                harness="k8s",
                gpu_model_hint="NVIDIA GB200",
                gpu_memory_mb_hint=294912,
                gpu_count_hint=4,
            )

            self.assertEqual(report["summary"]["status"], "fail")
            self.assertEqual(len(report["hbm_like_memory_only_nodes"]), 4)
            self.assertTrue(report["numa"]["meminfo_includes_hbm_like_memory"])
            self.assertNotIn("cpu manager", " ".join(report["summary"]["failures"]).lower())
            self.assertEqual(report["kubelet_cpu_manager_policy"]["status"], "warning")

    def test_b300_hbm_check_is_not_applicable_and_cpu_manager_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpu_node_kb = 768 * hbm_memory_exposure.GIB_KB
            total_kb = 2 * cpu_node_kb

            write(root / "proc/meminfo", f"MemTotal:       {total_kb} kB\n")
            write(root / "proc/sys/kernel/hostname", "b300-node-0\n")
            write(root / "proc/driver/nvidia/params", 'CoherentGPUMemoryMode: ""\n')
            write(
                root / "var/lib/kubelet/cpu_manager_state",
                json.dumps({"policyName": "none", "defaultCpuSet": ""}),
            )
            write(root / "sys/devices/system/node/online", "0-1\n")
            write_node(root, 0, cpu_node_kb, "0-95")
            write_node(root, 1, cpu_node_kb, "96-191")

            report = hbm_memory_exposure.collect_host(
                root=root,
                harness="k8s",
                gpu_model_hint="NVIDIA B300 SXM6 AC",
                gpu_memory_mb_hint=275040,
                gpu_count_hint=8,
            )

            self.assertEqual(report["summary"]["status"], "not_applicable")
            self.assertFalse(report["coherent_gpu_candidate"])
            self.assertEqual(report["hbm_like_memory_only_nodes"], [])
            self.assertEqual(report["kubelet_cpu_manager_policy"]["status"], "warning")
            self.assertIn("static", report["kubelet_cpu_manager_policy"]["message"])

    def test_gpu_without_coherent_metadata_warns_on_hbm_scale_nodes(self) -> None:
        # Managed Kubernetes can omit GPU model and memory labels. HBM-sized NUMA
        # nodes are not sufficient evidence that the platform has CPU-GPU memory
        # coherence, but the audit must keep the suspicious evidence visible.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpu_node_kb = 700 * hbm_memory_exposure.GIB_KB
            hbm_node_kb = 275040 * 1024  # B300 SXM6 HBM per GPU, from nvidia-smi
            total_kb = (2 * cpu_node_kb) + (8 * hbm_node_kb)

            write(root / "proc/meminfo", f"MemTotal:       {total_kb} kB\n")
            write(root / "proc/sys/kernel/hostname", "managed-b300-0\n")
            write(root / "proc/driver/nvidia/params", "CoherentGPUMemoryMode: \n")
            write(root / "sys/devices/system/node/online", "0-9\n")
            write_node(root, 0, cpu_node_kb, "0-111")
            write_node(root, 1, cpu_node_kb, "112-223")
            for node_id in range(2, 10):
                write_node(root, node_id, hbm_node_kb, "")

            report = hbm_memory_exposure.collect_host(
                root=root,
                harness="k8s",
                gpu_model_hint="",       # no nvidia.com/gpu.product label
                gpu_memory_mb_hint=0,    # no nvidia.com/gpu.memory label, no nvidia-smi
                gpu_count_hint=8,        # only the nvidia.com/gpu capacity is known
            )

            self.assertEqual(report["summary"]["status"], "warning")
            self.assertFalse(report["coherent_gpu_candidate"])
            self.assertEqual(report["hbm_like_memory_only_nodes"], [])
            self.assertIn("model evidence", report["summary"]["message"])

    def test_cpu_manager_warning_does_not_change_hbm_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpu_node_kb = 768 * hbm_memory_exposure.GIB_KB
            write(root / "proc/meminfo", f"MemTotal:       {2 * cpu_node_kb} kB\n")
            write(root / "proc/sys/kernel/hostname", "healthy-b300-0\n")
            write(root / "proc/driver/nvidia/params", "CoherentGPUMemoryMode: \n")
            write(
                root / "var/lib/kubelet/cpu_manager_state",
                json.dumps({"policyName": "none", "defaultCpuSet": ""}),
            )
            write(root / "sys/devices/system/node/online", "0-1\n")
            write_node(root, 0, cpu_node_kb, "0-111")
            write_node(root, 1, cpu_node_kb, "112-223")

            report = hbm_memory_exposure.collect_host(
                root=root,
                harness="k8s",
                gpu_model_hint="",
                gpu_memory_mb_hint=0,
                gpu_count_hint=8,
            )

            self.assertEqual(report["summary"]["status"], "not_applicable")
            self.assertEqual(report["hbm_like_memory_only_nodes"], [])
            self.assertEqual(report["summary"]["failures"], [])
            self.assertEqual(report["kubelet_cpu_manager_policy"]["status"], "warning")
            self.assertEqual(report["kubelet_cpu_manager_policy"]["failures"], [])

    def test_cdmm_driver_mode_passes_hbm_with_cpu_manager_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpu_node_kb = 480 * hbm_memory_exposure.GIB_KB

            write(root / "proc/meminfo", f"MemTotal:       {cpu_node_kb} kB\n")
            write(root / "proc/sys/kernel/hostname", "gh200-node-0\n")
            write(root / "proc/driver/nvidia/params", 'CoherentGPUMemoryMode: "driver"\n')
            write(
                root / "var/lib/kubelet/cpu_manager_state",
                json.dumps({"policyName": "none", "defaultCpuSet": ""}),
            )
            write(root / "sys/devices/system/node/online", "0-1\n")
            write_node(root, 0, cpu_node_kb, "0-71")
            write_node(root, 1, 0, "")

            report = hbm_memory_exposure.collect_host(
                root=root,
                harness="k8s",
                gpu_model_hint="NVIDIA GH200",
                gpu_memory_mb_hint=98304,
                gpu_count_hint=1,
            )

            self.assertEqual(report["summary"]["status"], "pass")
            self.assertTrue(report["coherent_gpu_candidate"])
            self.assertEqual(report["nvidia"]["coherent_gpu_memory_mode"], "driver")
            self.assertEqual(report["kubelet_cpu_manager_policy"]["status"], "warning")

    def test_default_check_emits_two_independent_status_lines(self) -> None:
        report = {
            "host": "b300-node-0",
            "summary": {
                "status": "not_applicable",
                "failures": [],
                "warnings": [],
                "message": "GPU platform is not coherent",
            },
            "kubelet_cpu_manager_policy": {
                "status": "warning",
                "failures": [],
                "warnings": ["kubelet CPU Manager policy is none"],
                "message": "kubelet CPU Manager policy is none",
            },
        }
        with mock.patch.object(hbm_memory_exposure, "run_k8s_check", return_value=([report], [])):
            result = hbm_memory_exposure.run_default_check("k8s")

        self.assertEqual(result["hbm_memory_exposure"]["status"], "not_applicable")
        self.assertEqual(result["kubelet_cpu_manager_policy"]["status"], "warning")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            run_checks.print_check_summary(result)
        self.assertIn("hbm_memory_exposure: NOT_APPLICABLE", stdout.getvalue())
        self.assertIn("kubelet_cpu_manager_policy: WARNING", stdout.getvalue())
        self.assertIn("WARNING: kubelet_cpu_manager_policy warning", stderr.getvalue())

    def test_slurm_check_errors_do_not_create_cpu_manager_warning(self) -> None:
        report = {
            "host": "head-0",
            "summary": {
                "status": "pass",
                "failures": [],
                "warnings": [],
                "message": "HBM is not exposed as ordinary system memory",
            },
            "kubelet_cpu_manager_policy": {
                "status": "not_applicable",
                "failures": [],
                "warnings": [],
                "message": "kubelet CPU Manager applies only to Kubernetes",
            },
        }
        errors = ["SLURM_JOB_ID is not set; HBM check only checked the local host"]
        with mock.patch.object(
            hbm_memory_exposure, "run_slurm_check", return_value=([report], errors)
        ):
            result = hbm_memory_exposure.run_default_check("slurm")

        self.assertEqual(result["hbm_memory_exposure"]["status"], "warning")
        self.assertNotIn("kubelet_cpu_manager_policy", result)

    def test_standalone_check_does_not_run_the_kubernetes_check(self) -> None:
        report = {
            "host": "standalone-0",
            "summary": {
                "status": "pass",
                "failures": [],
                "warnings": [],
                "message": "HBM is not exposed as ordinary system memory",
            },
            "kubelet_cpu_manager_policy": {
                "status": "warning",
                "failures": [],
                "warnings": ["policy is none"],
                "message": "kubelet CPU Manager policy is none",
            },
        }
        with mock.patch.object(
            hbm_memory_exposure, "collect_host", return_value=report
        ):
            result = hbm_memory_exposure.run_default_check("standalone")

        self.assertEqual(result["hbm_memory_exposure"]["status"], "pass")
        self.assertNotIn("kubelet_cpu_manager_policy", result)

    def test_standalone_host_collection_does_not_read_kubelet_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            hbm_memory_exposure, "parse_kubelet_cpu_manager"
        ) as parse_cpu_manager:
            report = hbm_memory_exposure.collect_host(
                root=Path(tmp),
                harness="standalone",
            )

        parse_cpu_manager.assert_not_called()
        self.assertNotIn("kubelet_cpu_manager", report)
        self.assertNotIn("kubelet_cpu_manager_policy", report)

    def test_k8s_transport_errors_do_not_create_cpu_manager_warning(self) -> None:
        report = {
            "host": "gpu-node-0",
            "summary": {
                "status": "pass",
                "failures": [],
                "warnings": [],
                "message": "HBM is not exposed as ordinary system memory",
            },
            "kubelet_cpu_manager_policy": {
                "status": "pass",
                "failures": [],
                "warnings": [],
                "message": "kubelet CPU Manager policy is static",
            },
        }
        errors = ["gpu-node-1: host check pod did not become Ready"]
        with mock.patch.object(
            hbm_memory_exposure, "run_k8s_check", return_value=([report], errors)
        ):
            result = hbm_memory_exposure.run_default_check("k8s")

        self.assertEqual(result["hbm_memory_exposure"]["status"], "warning")
        self.assertEqual(result["kubelet_cpu_manager_policy"]["status"], "pass")
        self.assertEqual(result["kubelet_cpu_manager_policy"]["warnings"], [])

    def test_k8s_total_transport_failure_is_unknown_for_cpu_manager(self) -> None:
        errors = ["gpu-node-0: host check pod did not become Ready"]
        with mock.patch.object(
            hbm_memory_exposure, "run_k8s_check", return_value=([], errors)
        ):
            result = hbm_memory_exposure.run_default_check("k8s")

        self.assertEqual(result["hbm_memory_exposure"]["status"], "warning")
        cpu_manager = result["kubelet_cpu_manager_policy"]
        self.assertEqual(cpu_manager["status"], "unknown")
        self.assertEqual(cpu_manager["hosts_checked"], 0)
        self.assertEqual(cpu_manager["warnings"], [])
        self.assertIn("could not be checked", cpu_manager["message"])

    def test_k8s_without_gpu_nodes_is_not_applicable_to_cpu_manager(self) -> None:
        errors = [hbm_memory_exposure.NO_K8S_GPU_NODES]
        with mock.patch.object(
            hbm_memory_exposure, "run_k8s_check", return_value=([], errors)
        ):
            result = hbm_memory_exposure.run_default_check("k8s")

        cpu_manager = result["kubelet_cpu_manager_policy"]
        self.assertEqual(cpu_manager["status"], "not_applicable")
        self.assertEqual(cpu_manager["warnings"], [])
        self.assertIn("no Kubernetes GPU hosts", cpu_manager["message"])


class RunSlurmCheckTests(unittest.TestCase):
    """Stderr policy for the srun fan-out: record it only as failure evidence.

    Matches the sibling nic-topology and vboost checks. srun emits
    informational stderr on healthy clusters (site banners, cgroup notices),
    and aggregate_reports downgrades pass to warning whenever errors is
    non-empty, so blanket stderr recording turned clean Tier-0 passes into
    warnings headlined by raw srun chatter.
    """

    HOST_JSON = json.dumps(
        {"host": "node-0", "summary": {"status": "pass", "failures": [], "warnings": []}}
    )

    def run_check(self, proc: subprocess.CompletedProcess):
        env = {"SLURM_JOB_ID": "42", "SLURM_NNODES": "2"}
        with mock.patch.dict(hbm_memory_exposure.os.environ, env), mock.patch.object(
            hbm_memory_exposure, "run_command", return_value=proc
        ):
            return hbm_memory_exposure.run_slurm_check("slurm")

    def test_benign_stderr_with_clean_exit_keeps_pass(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["srun"],
            returncode=0,
            stdout=self.HOST_JSON + "\n",
            stderr="srun: job 42 has been allocated resources\nWelcome to cluster MOTD\n",
        )
        reports, errors = self.run_check(proc)
        self.assertEqual(errors, [])
        self.assertEqual(len(reports), 1)
        aggregate = hbm_memory_exposure.aggregate_reports(reports, errors)
        self.assertEqual(aggregate["status"], "pass")
        self.assertEqual(aggregate["message"], "HBM exposure check passed")

    def test_nonzero_exit_still_records_stderr(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["srun"],
            returncode=1,
            stdout=self.HOST_JSON + "\n",
            stderr="srun: error: node-1: task 1: Exited with exit code 1\n",
        )
        reports, errors = self.run_check(proc)
        self.assertEqual(len(reports), 1)
        self.assertIn(
            "srun host check exited 1; parsing any completed host output", errors
        )
        self.assertIn("srun: error: node-1: task 1: Exited with exit code 1", errors)

    def test_no_host_json_records_stderr_and_falls_back_to_local(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["srun"],
            returncode=0,
            stdout="",
            stderr="srun: error: fan-out produced nothing\n",
        )
        local = {
            "host": "head-0",
            "summary": {"status": "pass", "failures": [], "warnings": []},
        }
        with mock.patch.object(hbm_memory_exposure, "collect_host", return_value=dict(local)):
            reports, errors = self.run_check(proc)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["check_scope"], "local")
        self.assertIn("srun: error: fan-out produced nothing", errors)
        self.assertIn("srun host check returned no host JSON; local host only", errors)


class AggregateReportsTests(unittest.TestCase):
    def test_check_errors_prevent_overall_pass(self) -> None:
        report = {
            "host": "node-0",
            "summary": {
                "status": "pass",
                "failures": [],
                "warnings": [],
            },
        }

        aggregate = hbm_memory_exposure.aggregate_reports(
            [report],
            ["node-1: host check pod did not become Ready"],
        )

        self.assertEqual(aggregate["status"], "warning")
        self.assertIn("node-1: host check pod did not become Ready", aggregate["warnings"])
        self.assertEqual(aggregate["message"], "node-1: host check pod did not become Ready")

    def test_check_errors_without_reports_are_warning(self) -> None:
        aggregate = hbm_memory_exposure.aggregate_reports(
            [],
            ["srun host check returned no host JSON; local host only"],
        )

        self.assertEqual(aggregate["status"], "warning")
        self.assertEqual(aggregate["hosts_checked"], 0)
        self.assertEqual(aggregate["message"], "srun host check returned no host JSON; local host only")


if __name__ == "__main__":
    unittest.main()
