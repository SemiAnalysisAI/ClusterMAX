"""Synthetic parser and transport cases for cross-node storage checks."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

CHECK_PATH = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit" / "checks" / "system" / "storage_config.py"
)
spec = importlib.util.spec_from_file_location("storage_config_under_test", CHECK_PATH)
assert spec and spec.loader
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

DF = """Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/nvme0n1p1 ext4  100G   50G   50G  50% /
tmpfs          tmpfs  63G     0   63G   0% /dev/shm
10.0.0.5:/home nfs4   10T    9T    1T  {home_pct}% /home
{scratch}"""


def report(host: str, *, home_pct: int = 40, scratch: str = "mgs@tcp:/fs lustre 1P 100T 900T 10% /scratch") -> str:
    return json.dumps({"host": host, "df": storage.parse_df(DF.format(home_pct=home_pct, scratch=scratch)), "error": None})


class StorageConfigTests(unittest.TestCase):
    def assert_error_is_visible_in_finding(self, payload: dict, expected: str) -> None:
        sys.path.insert(0, str(CHECK_PATH.parents[2]))
        import audit_findings

        findings = audit_findings.detect_findings({"audit_data": {"storage_config": payload}})
        finding, = [f for f in findings if f.key == "storage_config.status"]
        self.assertIn(expected, finding.detected)

    def test_nonzero_srun_exit_is_visible_with_or_without_reports(self) -> None:
        for count, code, error, status in [
            (2, 2, "synthetic allocation failed", "warning"),
            (0, 1, "synthetic allocation denied", "unknown"),
        ]:
            with self.subTest(reports=count):
                def runner(command, **kwargs):
                    reports = "\n".join(report(f"synthetic-{i}") for i in range(count))
                    return subprocess.CompletedProcess(command, code, reports, error)

                result = storage.build_check_payload(
                    harness="slurm", env={"SLURM_JOB_ID": "1", "SLURM_NNODES": "2"},
                    runner=runner,
                )["storage_config"]
                self.assertEqual(result["status"], status)
                self.assertIn(error, result["message"])
                self.assert_error_is_visible_in_finding(result, error)
                if count:
                    self.assertEqual(result["nodes_checked"], count)
                    self.assertEqual(result["failures"], [])
                    self.assertIn(f"srun exited {code}", result["errors"][0])

    def test_srun_exceptions_surface_in_the_unknown_message(self) -> None:
        for error in (OSError("synthetic transport unavailable"), subprocess.TimeoutExpired("srun", 1)):
            with self.subTest(error=type(error).__name__):
                def runner(command, **kwargs):
                    raise error

                result = storage.build_check_payload(
                    harness="slurm", env={"SLURM_JOB_ID": "1"}, runner=runner,
                )["storage_config"]
                self.assertEqual(result["status"], "unknown")
                self.assertIn("srun failed:", result["message"])
                self.assert_error_is_visible_in_finding(result, "srun failed:")

    def test_kubernetes_inventory_failure_surfaces_in_the_verdict(self) -> None:
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", "synthetic inventory forbidden")

        result = storage.build_check_payload(harness="k8s", env={}, runner=runner)["storage_config"]
        self.assertEqual(result["status"], "unknown")
        self.assertIn("kubectl get nodes failed", result["message"])
        self.assert_error_is_visible_in_finding(result, "synthetic inventory forbidden")

    def test_kubernetes_host_failure_and_cap_cannot_pass(self) -> None:
        nodes = {"items": [{
            "metadata": {"name": f"synthetic-{index}"},
            "status": {"capacity": {"nvidia.com/gpu": "1"}},
        } for index in range(2)]}
        for fail_host in (True, False):
            with self.subTest(fail_host=fail_host):
                def runner(command, **kwargs):
                    verb = command[1]
                    if verb == "get":
                        return subprocess.CompletedProcess(command, 0, json.dumps(nodes), "")
                    if verb == "apply":
                        return subprocess.CompletedProcess(
                            command, 1 if fail_host else 0, "", "synthetic pod forbidden" if fail_host else "",
                        )
                    if verb in {"wait", "delete"}:
                        return subprocess.CompletedProcess(command, 0, "", "")
                    if verb == "exec":
                        return subprocess.CompletedProcess(
                            command, 0, DF.format(home_pct=40, scratch=""), "",
                        )
                    raise AssertionError(command)

                result = storage.build_check_payload(
                    harness="k8s", env={"CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS": "1"},
                    runner=runner,
                )["storage_config"]
                self.assertEqual(result["status"], "unknown" if fail_host else "warning")
                self.assertTrue(result["errors"])
                self.assertIn("checked 1 of 2 GPU nodes", result["message"])
                self.assert_error_is_visible_in_finding(
                    result, "synthetic pod forbidden" if fail_host else "checked 1 of 2 GPU nodes",
                )

    def test_mount_failure_keeps_priority_over_collection_warning(self) -> None:
        result = storage.aggregate(
            [json.loads(report("synthetic-a")), json.loads(report("synthetic-b", scratch=""))],
            nodes_expected=2, mode="slurm", errors=["synthetic transport warning"],
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["failures"], ["/scratch is missing on synthetic-b"])
        self.assertIn("synthetic transport warning", result["message"])
        self.assert_error_is_visible_in_finding(result, "synthetic transport warning")

    def test_successful_collection_still_passes(self) -> None:
        result = storage.aggregate(
            [json.loads(report("synthetic-a"))], nodes_expected=1, mode="slurm",
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["errors"], [])

    def test_wrapped_shared_device_preserves_mount(self) -> None:
        text = "Filesystem Type Size Used Avail Use% Mounted on\nserver:/a-very-long-lustre-path\n  lustre 100T 20T 80T 20% /shared workspace\n"
        row, = storage.parse_df(text)
        self.assertEqual(row["source"], "server:/a-very-long-lustre-path")
        self.assertEqual(row["fstype"], "lustre")
        self.assertEqual(row["target"], "/shared workspace")

    def test_partial_df_does_not_prove_missing_mounts(self) -> None:
        first = json.loads(report("gpu-a"))
        second = json.loads(report("gpu-b", scratch=""))
        second["error"] = "df: /scratch: Stale file handle"
        result = storage.aggregate([first, second], nodes_expected=2, mode="slurm")
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["failures"], [])
        self.assertIn("Stale file handle", result["message"])

    def test_slurm_fan_out_compares_every_node(self) -> None:
        def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            self.assertEqual(command[0], "srun")
            self.assertEqual(command[command.index("-N") + 1], "5")
            self.assertIn("def worker_report", kwargs["input"])
            out = "\n".join([
                "srun: job 1 has been allocated resources",
                report("n0"),
                report("n1", home_pct=95),
                report("n2", scratch=""),
                json.dumps({"host": "n3", "df": [], "error": "df -hT failed: timeout"}),
            ])
            return subprocess.CompletedProcess(command, 0, out + "\n", "")

        payload = storage.build_check_payload(
            harness="slurm", env={"SLURM_JOB_ID": "1", "SLURM_NNODES": "5"}, runner=runner
        )["storage_config"]

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["nodes_checked"], 4)
        # A failed df on n3 is a warning, never a host missing every mount.
        self.assertEqual(payload["failures"], ["/scratch is missing on n2"])
        self.assertIn("n3: df -hT failed: timeout", payload["warnings"])
        self.assertIn("/home on n1 is 95% used", payload["warnings"])
        self.assertIn("only 4 of 5 allocated node(s) reported", payload["warnings"])
        # tmpfs never enters the comparison.
        self.assertNotIn("/dev/shm", [row["target"] for row in payload["hosts"][0]["df"]])

    def test_k8s_fan_out_runs_df_in_the_host_mount_namespace_of_every_gpu_node(self) -> None:
        nodes = {"items": [
            {"metadata": {"name": n, "labels": {}}, "status": {"capacity": {"nvidia.com/gpu": "8"}}} for n in ("g0", "g1")
        ] + [{"metadata": {"name": "cpu0", "labels": {}}, "status": {"capacity": {}}}]}
        created: list[str] = []
        deleted: list[str] = []
        pod_nodes: dict[str, str] = {}

        def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            verb = command[1]
            if verb == "get":
                return subprocess.CompletedProcess(command, 0, json.dumps(nodes), "")
            if verb == "apply":
                manifest = json.loads(kwargs["input"])
                created.append(manifest["spec"]["nodeName"])
                pod_nodes[manifest["metadata"]["name"]] = manifest["spec"]["nodeName"]
                self.assertTrue(manifest["spec"]["hostPID"])
                return subprocess.CompletedProcess(command, 0, "", "")
            if verb == "wait":
                return subprocess.CompletedProcess(command, 0, "", "")
            if verb == "exec":
                self.assertEqual(command[command.index("--") + 1:], ["nsenter", "-t", "1", "-m", "--", "df", "-hT"])
                node = pod_nodes[command[4]]
                text = DF.format(home_pct=40, scratch="" if node == "g1" else "mgs@tcp:/fs lustre 1P 100T 900T 10% /scratch")
                # Per-pod CSI and container mounts are unique to each node.
                text += f"\n/dev/sdb ext4 100G 1G 99G 1% /var/lib/kubelet/pods/{node}/volumes/pvc"
                text += f"\noverlay overlay 100G 1G 99G 1% /run/containerd/io.containerd.runtime.v2.task/k8s.io/{node}/rootfs"
                return subprocess.CompletedProcess(command, 0, text, "")
            if verb == "delete":
                deleted.append(command[3])
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(command)

        payload = storage.build_check_payload(harness="k8s", env={}, runner=runner)["storage_config"]

        self.assertEqual(sorted(created), ["g0", "g1"])
        self.assertEqual(len(deleted), 2)
        self.assertEqual(payload["mode"], "k8s")
        self.assertEqual(payload["nodes_expected"], 2)
        self.assertEqual(payload["nodes_checked"], 2)
        # One of two nodes is half, so the mount is required on both.
        self.assertEqual(payload["failures"], ["/scratch is missing on g1"])
        self.assertEqual(payload["status"], "fail")

    def test_no_job_is_unknown(self) -> None:
        payload = storage.build_check_payload(harness="slurm", env={})["storage_config"]
        self.assertEqual(payload["status"], "unknown")
        self.assertIn("SLURM_JOB_ID is not set", payload["message"])
        self.assert_error_is_visible_in_finding(payload, "SLURM_JOB_ID is not set")


if __name__ == "__main__":
    unittest.main()
