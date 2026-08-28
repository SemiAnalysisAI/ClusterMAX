"""Tests for review of saved audit artifacts."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cmax import audit_review, cli, runtime_paths


RUNTIME_ROOT = runtime_paths.package_runtime_root()


def audit_values() -> dict:
    return {
        "audit_data": {
            "securityVersions": {"nvidiaDriver": {"status": "pass"}},
            "containers": {
                "workerCheckOk": True,
                "nvidiaContainerToolkit": False,
            },
            "hbm_memory_exposure": {"status": "warning"},
        }
    }


def write_audit(root: Path, timestamp: str = "20260807-120000") -> Path:
    audit_dir = root / "runs" / "cluster" / timestamp / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "audit.values.json").write_text(json.dumps(audit_values()))
    (audit_dir / "audit.out").write_text("first line\nrunc detail\n")
    return audit_dir


class AuditSourceTests(unittest.TestCase):
    def test_output_log_resolves_its_structured_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            audit_dir = write_audit(Path(temp))
            artifacts = audit_review.resolve_source(audit_dir / "audit.out")

        self.assertEqual(artifacts.values.name, "audit.values.json")
        self.assertEqual(artifacts.raw.name, "audit.out")

    def test_run_directory_resolves_nested_audit_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit_dir = write_audit(root)
            artifacts = audit_review.resolve_source(audit_dir.parent)

        self.assertEqual(artifacts.values, (audit_dir / "audit.values.json").resolve())

    def test_latest_audit_uses_the_newest_run_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_audit(root, "20260807-120000")
            latest = write_audit(root, "20260807-130000")
            artifacts = audit_review.find_latest(
                [root], private_root=root / "private-audits"
            )

        self.assertEqual(artifacts.values, (latest / "audit.values.json").resolve())

    def test_latest_audit_can_select_a_partial_raw_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_audit(root, "20260807-120000")
            partial = write_audit(root, "20260807-130000")
            (partial / "audit.values.json").unlink()
            artifacts = audit_review.find_latest(
                [root], private_root=root / "private-audits"
            )

        self.assertIsNone(artifacts.values)
        self.assertEqual(artifacts.raw, (partial / "audit.out").resolve())

    def test_latest_audit_searches_configured_runs_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            latest = write_audit(root, "20260807-140000")
            with mock.patch.dict(
                "os.environ", {"CLUSTERMAX_RUNS_ROOT": str(root / "runs")}
            ):
                artifacts = audit_review.find_latest(
                    [root / "empty"], private_root=root / "private-audits"
                )

        self.assertEqual(artifacts.values, (latest / "audit.values.json").resolve())

    def test_raw_file_without_values_remains_reviewable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            raw = Path(temp) / "collector.log"
            raw.write_text("collector output\n")
            artifacts = audit_review.resolve_source(raw)

        self.assertIsNone(artifacts.values)
        self.assertEqual(artifacts.raw, raw.resolve())


class AuditCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit_dir = write_audit(Path(self.temp.name))
        self.artifacts = audit_review.resolve_source(self.audit_dir)
        self.checks = audit_review.load_checks(self.artifacts, RUNTIME_ROOT)

    def test_all_numbers_checks_and_show_uses_the_number(self) -> None:
        listing, _ = audit_review.execute_command("all", self.artifacts, self.checks)
        self.assertIn("number  status", listing)
        detail, _ = audit_review.execute_command("show 1", self.artifacts, self.checks)
        self.assertIn("status:", detail)
        self.assertIn("observed:", detail)

    def test_find_searches_keys_titles_and_observed_values(self) -> None:
        result, _ = audit_review.execute_command(
            "find nvidiaContainerToolkit", self.artifacts, self.checks
        )
        self.assertIn("NVIDIA Container Toolkit", result)

    def test_raw_search_prints_matching_line_numbers(self) -> None:
        result, _ = audit_review.execute_command(
            "raw runc", self.artifacts, self.checks
        )
        self.assertEqual(result, "2: runc detail")

    def test_empty_structured_audit_has_an_empty_summary(self) -> None:
        result, _ = audit_review.execute_command(
            "summary", self.artifacts, []
        )

        self.assertIn("No classifiable audit checks were found.", result)

    def test_summary_hint_stays_in_the_saved_review(self) -> None:
        result, _ = audit_review.execute_command(
            "summary", self.artifacts, self.checks
        )

        self.assertIn("run 'cmax audit review -vv'", result)
        self.assertNotIn("run 'cmax audit -vv'", result)

    def test_raw_only_audit_summary_reports_missing_values(self) -> None:
        raw_only = audit_review.AuditArtifacts(None, self.artifacts.raw)
        result, _ = audit_review.execute_command("summary", raw_only, [])

        self.assertEqual(
            result, "Structured audit values are unavailable. Use 'raw'."
        )

    def test_scripted_commands_do_not_start_the_prompt(self) -> None:
        output = io.StringIO()
        rc = audit_review.run(
            self.artifacts,
            RUNTIME_ROOT,
            commands=["find runc", "paths"],
            input_fn=mock.Mock(side_effect=AssertionError("prompted")),
            output=output,
        )
        self.assertEqual(rc, 0)
        self.assertIn("values:", output.getvalue())

    def test_vvv_prints_remediation_without_the_raw_log(self) -> None:
        output = io.StringIO()
        rc = audit_review.run(
            self.artifacts,
            RUNTIME_ROOT,
            verbosity=3,
            interactive=False,
            output=output,
        )

        self.assertEqual(rc, 0)
        self.assertIn("Recommendation:", output.getvalue())
        self.assertNotIn("runc detail", output.getvalue())
        self.assertNotIn("-vvv", output.getvalue())

    def test_vvv_prints_a_raw_only_audit(self) -> None:
        output = io.StringIO()
        raw_only = audit_review.AuditArtifacts(None, self.artifacts.raw)
        rc = audit_review.run(
            raw_only,
            RUNTIME_ROOT,
            verbosity=3,
            interactive=False,
            output=output,
        )

        self.assertEqual(rc, 0)
        self.assertIn("runc detail", output.getvalue())


class AuditReviewCliTests(unittest.TestCase):
    def test_review_keeps_verbosity_on_either_side_of_profile(self) -> None:
        before = cli.build_parser().parse_args(["audit", "-vv", "review"])
        after = cli.build_parser().parse_args(["audit", "review", "-vv"])

        self.assertEqual(before.verbose, 2)
        self.assertEqual(after.verbose, 2)

    def test_review_has_command_specific_help(self) -> None:
        output = io.StringIO()
        with mock.patch("sys.stdout", output), self.assertRaises(SystemExit) as raised:
            cli.main(["audit", "review", "-h"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("usage: cmax audit review", output.getvalue())
        self.assertNotIn("--k8s", output.getvalue())

    def test_review_dispatches_before_live_audit_detection(self) -> None:
        artifacts = audit_review.AuditArtifacts(Path("audit.values.json"), None)
        with (
            mock.patch("cmax.security.find_runtime_root", return_value=RUNTIME_ROOT),
            mock.patch(
                "cmax.audit_review.find_latest", return_value=artifacts
            ) as find_latest,
            mock.patch("cmax.audit_review.run", return_value=0) as run,
        ):
            rc = cli.main(["audit", "review", "--no-interactive"])

        self.assertEqual(rc, 0)
        self.assertIn(RUNTIME_ROOT, find_latest.call_args.args[0])
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["verbosity"], 1)

    def test_review_accepts_an_explicit_output_log(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            audit_dir = write_audit(Path(temp))
            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                rc = cli.main(
                    [
                        "audit",
                        "review",
                        str(audit_dir / "audit.out"),
                        "--command",
                        "paths",
                    ]
                )

        self.assertEqual(rc, 0)
        self.assertIn("audit.values.json", output.getvalue())


if __name__ == "__main__":
    unittest.main()
