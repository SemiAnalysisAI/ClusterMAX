from __future__ import annotations

import bashtest
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"


plan_audit = bashtest.load_python_script(AUDIT_SCRIPTS / "plan_audit.py", "plan_audit_under_test")
run_legacy_audit = bashtest.load_python_script(AUDIT_SCRIPTS / "run_legacy_audit.py", "run_legacy_audit_under_test")
validate_audit = bashtest.load_python_script(AUDIT_SCRIPTS / "validate_audit.py", "validate_audit_under_test")


class PlanAuditTests(unittest.TestCase):
    def test_kubernetes_runtime_beats_headnode_sbatch_fallback(self) -> None:
        with (
            patch.dict(
                plan_audit.os.environ,
                {"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
                clear=True,
            ),
            patch.object(plan_audit.shutil, "which", return_value="/usr/bin/sbatch"),
            patch.object(plan_audit, "command_ok", return_value=False),
        ):
            self.assertEqual(plan_audit.detect_harness(), "k8s")

    def test_slurm_login_pod_on_kubernetes_selects_slurm(self) -> None:
        with (
            patch.dict(
                plan_audit.os.environ,
                {"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
                clear=True,
            ),
            patch.object(plan_audit.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"),
            patch.object(plan_audit, "command_ok", return_value=True) as ping,
        ):
            self.assertEqual(plan_audit.detect_harness(), "slurm")
        ping.assert_called_once_with(["scontrol", "ping"], timeout=5.0)

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


class RunLegacyAuditTests(unittest.TestCase):
    def test_each_harness_has_one_collector(self) -> None:
        # `cmax audit` and `cmax audit security` must read the same evidence.
        # A scope-specific collector, for example cluster-audit-slurm-security.sh,
        # lets the two commands drift apart, so none may exist.
        self.assertEqual(sorted(AUDIT_SCRIPTS.glob("cluster-audit-*-*.sh")), [])
        for harness in ("slurm", "standalone", "k8s"):
            with self.subTest(harness=harness):
                collector = AUDIT_SCRIPTS / f"cluster-audit-{harness}.sh"
                source = collector.read_text()
                self.assertIn('. "$WORKLOAD_DIR/security-fleet.sh"', source)
                self.assertIn(f"merge_security_fleet {harness} ", source)

    def test_collector_runs_without_the_audit_scope(self) -> None:
        # host-check.sh skips facts when CLUSTERMAX_AUDIT_SCOPE=security, and
        # srun passes the environment to the worker. The scope only filters
        # the report, so it must not reach the collector.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            audit_script = root / "cluster-audit-slurm.sh"
            audit_script.write_text(
                "#!/bin/bash\n"
                "out=''\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    --output-dir) out=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "printf '{\"scope\": \"%s\"}\\n' \"${CLUSTERMAX_AUDIT_SCOPE:-unset}\" "
                "> \"$out/audit.json\"\n"
            )
            (root / "cluster-audit-slurm-security.sh").write_text("exit 9\n")
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            audit_json_path = root / "raw.path"
            for scope in ("full", "security", "versions"):
                with self.subTest(scope=scope), patch.dict(
                    run_legacy_audit.os.environ,
                    {
                        "CLUSTERMAX_AUDIT_SCOPE": scope,
                        "CLUSTERMAX_AUDIT_LEGACY_CWD": str(root / "cwd"),
                    },
                    clear=True,
                ):
                    rc = run_legacy_audit.main(
                        [
                            "run_legacy_audit.py",
                            str(root),
                            str(audit_script),
                            "cluster",
                            str(tmpdir),
                            str(audit_json_path),
                        ]
                    )
                    self.assertEqual(rc, 0)
                    self.assertEqual(
                        (tmpdir / "audit.json").read_text().strip(),
                        '{"scope": "unset"}',
                    )

    def test_uses_ephemeral_shared_cwd_for_legacy_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            audit_root = root / "cmax" / "scripts" / "1-audit"
            audit_root.mkdir(parents=True)
            audit_script = audit_root / "00-cluster-audit.sh"
            audit_script.write_text(
                "#!/bin/bash\n"
                "set -euo pipefail\n"
                "out=''\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    --output-dir) out=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "touch nvvs.log\n"
                "printf '{}\\n' > \"$out/audit.json\"\n"
            )
            audit_script.chmod(0o755)
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            legacy_cwd = tmpdir / "legacy-cwd"
            audit_json_path = root / "raw.path"

            with patch.dict(
                run_legacy_audit.os.environ,
                {"CLUSTERMAX_AUDIT_LEGACY_CWD": str(legacy_cwd)},
                clear=True,
            ):
                rc = run_legacy_audit.main(
                    [
                        "run_legacy_audit.py",
                        str(audit_root),
                        str(audit_script),
                        "cluster",
                        str(tmpdir),
                        str(audit_json_path),
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertEqual(audit_json_path.read_text().strip(), str(tmpdir / "audit.json"))
            self.assertTrue((legacy_cwd / "nvvs.log").exists())
            self.assertFalse((root / "runs" / "cluster" / "ts" / "audit" / ".legacy-cwd").exists())
            self.assertFalse((audit_root / "nvvs.log").exists())


@pytest.mark.parametrize(
    "audit",
    [
        {"gpus": {"total": 32, "driverVersion": "unknown"}},
        {"gpus": {"total": 32, "driverVersion": "not-found"}},
        {
            "gpus": {"total": 32, "driverVersion": "not-found"},
            "hostCheck": {"WORKER_DRIVER_VERSION": "N/A"},
        },
    ],
    ids=["unknown-driver", "missing-driver", "missing-host-driver"],
)
def test_k8s_requires_driver_evidence(audit: dict) -> None:
    audit["software"] = {"workerCheckOk": False}
    assert not validate_audit.validate_worker_check(audit, "k8s", Path("unused.json"))


def test_k8s_accepts_host_check_driver_fallback() -> None:
    audit = {
        "gpus": {"total": 32, "driverVersion": "unknown"},
        "hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"},
        "software": {"workerCheckOk": False},
    }
    assert validate_audit.validate_worker_check(audit, "k8s", Path("unused.json"))


@pytest.mark.parametrize(
    ("harness", "audit", "expected"),
    [
        ("k8s", {"gpus": {"total": 0}}, True),
        ("slurm", {"software": {"workerCheckOk": False}}, False),
        ("slurm", {"software": {"workerCheckOk": True}}, True),
    ],
    ids=["no-gpus", "failed-worker-check", "successful-worker-check"],
)
def test_publish_gate(harness: str, audit: dict, expected: bool) -> None:
    assert validate_audit.validate_worker_check(audit, harness, Path("unused.json")) is expected
