#!/usr/bin/env python3
"""Unit tests for the cross-node df -hT audit check."""

from __future__ import annotations

import importlib.util
import json
import subprocess
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

        def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            verb = command[1]
            if verb == "get":
                return subprocess.CompletedProcess(command, 0, json.dumps(nodes), "")
            if verb == "apply":
                manifest = json.loads(kwargs["input"])
                created.append(manifest["spec"]["nodeName"])
                self.assertTrue(manifest["spec"]["hostPID"])
                return subprocess.CompletedProcess(command, 0, "", "")
            if verb == "wait":
                return subprocess.CompletedProcess(command, 0, "", "")
            if verb == "exec":
                self.assertEqual(command[command.index("--") + 1:], ["nsenter", "-t", "1", "-m", "--", "df", "-hT"])
                node = created[-1]
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

        self.assertEqual(sorted(created), ["g0", "g1"])  # Concurrent GPU-node fan-out.
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


if __name__ == "__main__":
    unittest.main()
