"""Coverage for the Slinky controller placement check."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
K8S_SCRIPT = WORKLOAD / "cluster-audit-k8s.sh"
FUNCTION = bashtest.extract_function(K8S_SCRIPT, "k8s_audit_slinky_controller_separate")
audit_findings = bashtest.load_python_script(
    WORKLOAD / "audit_findings.py", "audit_findings_slinky_under_test"
)

TITLE = "Slinky Slurm controller is not running on a separate Kubernetes node"


def pod(daemon: str, node: str, *, slinky: bool = True) -> dict:
    labels = {
        "app.kubernetes.io/name": daemon,
        "app.kubernetes.io/instance": "controller",
    }
    if daemon == "slurmd" and slinky:
        labels["slinky.slurm.net/cluster"] = "controller"
    return {
        "metadata": {"namespace": "slurm", "labels": labels},
        "spec": {"nodeName": node},
        "status": {"containerStatuses": [{"name": daemon, "state": {"running": {}}}]},
    }


class SlinkyTopologyTests(unittest.TestCase):
    def check(self, pods: list[dict] | None):
        run = bashtest.run_bash(
            FUNCTION
            + '\nprintf \'%s\\n\' "$PODS_JSON" | k8s_audit_slinky_controller_separate',
            env={"PODS_JSON": json.dumps({} if pods is None else {"items": pods})},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_controller_is_separate_from_workers(self) -> None:
        cases = (
            ([pod("slurmctld", "system-1"), pod("slurmd", "gpu-1")], True),
            ([pod("slurmctld", "gpu-1"), pod("slurmd", "gpu-1")], False),
            # A Slinky worker with no controller in its cluster is a failure.
            ([pod("slurmd", "gpu-1")], False),
            # A slurmd pod without the Slinky cluster label is not Slinky.
            ([pod("slurmctld", "system-1"), pod("slurmd", "gpu-1", slinky=False)], None),
            (None, None),
        )
        for pods, expected in cases:
            with self.subTest(expected=expected):
                self.assertIs(self.check(pods), expected)

    def test_only_a_failed_k8s_check_creates_a_finding(self) -> None:
        for value, harness, expected in (
            (False, "k8s", [TITLE]),
            (True, "k8s", []),
            (None, "k8s", []),
            (False, "slurm", []),
        ):
            with self.subTest(value=value, harness=harness):
                findings = audit_findings.detect_findings(
                    {
                        "cluster": {"orchestrator": harness},
                        "audit_data": {"slurm": {"slinkyControllerSeparate": value}},
                    }
                )
                self.assertEqual(
                    [f.title for f in findings if f.title == TITLE], expected
                )
