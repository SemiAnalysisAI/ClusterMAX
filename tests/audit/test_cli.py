import contextlib
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cmax import audit_profiles, audit_runner, cli, security, target_selection


class PublicCliTests(unittest.TestCase):
    def test_audit_verbosity_has_level_one_as_its_minimum_and_default(self) -> None:
        self.assertEqual(cli._audit_verbosity(0), 1)
        self.assertEqual(cli._audit_verbosity(1), 1)
        self.assertEqual(cli._audit_verbosity(2), 2)
        self.assertEqual(cli._audit_verbosity(3), 3)

    def test_top_level_help_describes_only_public_cli_usage(self) -> None:
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag), self.assertRaises(
                SystemExit
            ) as raised, contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main([flag])

            rendered = out.getvalue()
            self.assertEqual(raised.exception.code, 0)
            self.assertNotIn("usage:", rendered)
            self.assertNotIn("--repo", rendered)
            self.assertNotIn("-h, --help", rendered)
            self.assertNotIn("{audit}", rendered)
            self.assertIn(
                "commands:\n"
                "  audit  Run the full cluster configuration and health audit.",
                rendered,
            )

    def test_missing_command_error_shows_the_command_slot(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(
            SystemExit
        ) as raised:
            cli.main([])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("usage: cmax [-h] [-v] command ...", error.getvalue())

    def test_version_flag_reports_package_version(self) -> None:
        for flag in ("-v", "-V", "--version"):
            with self.subTest(flag=flag), self.assertRaises(
                SystemExit
            ) as raised, contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main([flag])
            self.assertEqual(raised.exception.code, 0)
            self.assertEqual(out.getvalue(), "cmax 0.2.1\n")

    def test_unreleased_commands_are_rejected(self) -> None:
        for command in ("init", "performance", "run"):
            with self.subTest(command=command), contextlib.redirect_stderr(
                io.StringIO()
            ) as stderr, self.assertRaises(SystemExit) as raised:
                cli.main([command])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("invalid choice", stderr.getvalue())

    def test_full_and_security_audits_have_separate_help(self) -> None:
        with self.assertRaises(SystemExit) as full_exit, contextlib.redirect_stdout(
            io.StringIO()
        ) as full_out:
            cli.main(["audit", "--help"])
        with self.assertRaises(
            SystemExit
        ) as security_exit, contextlib.redirect_stdout(io.StringIO()) as security_out:
            cli.main(["audit", "security", "--help"])

        self.assertEqual(full_exit.exception.code, 0)
        self.assertEqual(security_exit.exception.code, 0)
        self.assertIn("full cluster configuration and health audit", full_out.getvalue())
        self.assertNotIn("--exit-zero", full_out.getvalue())
        self.assertIn("focused, read-only security report", security_out.getvalue())
        self.assertIn("--exit-zero", security_out.getvalue())

    def test_security_shared_options_work_before_the_profile(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "audit",
                "--vm",
                "-vv",
                "--show",
                "--yes",
                "--kubeconfig",
                "/tmp/config",
                "security",
            ]
        )
        self.assertEqual(args.profile, "security")
        self.assertEqual(args.target, "vm")
        self.assertEqual(args.verbose, 2)
        self.assertTrue(args.show)
        self.assertTrue(args.assume_yes)
        self.assertEqual(args.kubeconfig, "/tmp/config")

    def test_security_rejects_target_flags_across_the_profile_boundary(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(
            SystemExit
        ) as raised:
            cli.main(["audit", "--vm", "security", "--slurm"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("audit target flags are mutually exclusive", stderr.getvalue())

    def test_audit_show_lists_full_audit_checks_without_running(self) -> None:
        selected = security.SecurityTarget("standalone", "local")
        checks = [
            SimpleNamespace(
                key="gpu.count", title="GPU / Count", category="hardware"
            ),
            SimpleNamespace(
                key="gpu.memory", title="GPU / Memory", category="hardware"
            ),
        ]
        for flag in ("-s", "--show"):
            with self.subTest(flag=flag), mock.patch(
                "cmax.security.find_runtime_root", return_value=Path("/runtime")
            ), mock.patch.object(
                security, "detect_target", return_value=selected
            ), mock.patch(
                "cmax.audit_report.list_check_specs", return_value=checks
            ) as list_checks, mock.patch("cmax.audit_runner.run") as run, (
                contextlib.redirect_stdout(io.StringIO())
            ) as out:
                result = cli.main(["audit", flag])

            self.assertEqual(result, 0)
            self.assertEqual(
                out.getvalue(),
                "[hardware] Hardware (2 checks)\n"
                "  gpu.count: GPU / Count\n"
                "  gpu.memory: GPU / Memory\n",
            )
            list_checks.assert_called_once_with(
                Path("/runtime"), category=None, harness="standalone"
            )
            run.assert_not_called()

    def test_audit_show_uses_the_user_selected_standalone_target(self) -> None:
        selected = security.SecurityTarget("standalone", "container", True)
        with mock.patch.object(
            security, "detect_target", return_value=selected
        ) as detect, mock.patch(
            "cmax.audit_report.list_check_specs", return_value=[]
        ) as list_checks, contextlib.redirect_stdout(io.StringIO()):
            result = cli.main(["audit", "container", "--show"])

        self.assertEqual(result, 0)
        detect.assert_called_once_with("container")
        list_checks.assert_called_once_with(
            mock.ANY, category=None, harness="standalone"
        )

    def test_audit_show_applies_kubeconfig_before_automatic_detection(self) -> None:
        selected = security.SecurityTarget("k8s", "k8s")

        def detect_target(explicit: str | None) -> security.SecurityTarget:
            self.assertIsNone(explicit)
            self.assertEqual(cli.os.environ.get("KUBECONFIG"), "/new/config")
            return selected

        def apply_kubeconfig(_value: str | None) -> None:
            cli.os.environ["KUBECONFIG"] = "/new/config"

        with mock.patch.dict(
            cli.os.environ, {"KUBECONFIG": "/original/config"}
        ), mock.patch.object(
            target_selection, "apply_kubeconfig", side_effect=apply_kubeconfig
        ) as apply, mock.patch.object(
            security, "detect_target", side_effect=detect_target
        ), mock.patch(
            "cmax.audit_report.list_check_specs", return_value=[]
        ) as list_checks, contextlib.redirect_stdout(io.StringIO()):
            result = cli.main(
                ["audit", "--show", "--kubeconfig", "/new/config"]
            )
            self.assertEqual(
                cli.os.environ.get("KUBECONFIG"), "/original/config"
            )

        self.assertEqual(result, 0)
        apply.assert_called_once_with("/new/config")
        list_checks.assert_called_once_with(
            mock.ANY, category=None, harness="k8s"
        )

    def test_category_show_lists_only_the_selected_category(self) -> None:
        target = security.SecurityTarget("standalone", "local")
        with mock.patch.object(
            security,
            "detect_target",
            return_value=target,
        ), mock.patch("cmax.audit_runner.run") as run, contextlib.redirect_stdout(
            io.StringIO()
        ) as out:
            result = cli.main(["audit", "hardware", "-s"])

        self.assertEqual(result, 0)
        self.assertIn("[hardware] Hardware (8 checks)", out.getvalue())
        self.assertNotIn("[versions]", out.getvalue())
        run.assert_not_called()

    def test_audit_delegates_to_the_minimal_runner(self) -> None:
        target = security.SecurityTarget("standalone", "local")
        with mock.patch.object(
            security, "detect_target", return_value=target
        ), mock.patch("cmax.audit_runner.run", return_value=0) as run:
            result = cli.main(["--repo", "/runtime", "audit", "-vv", "--yes"])
        self.assertEqual(result, 0)
        run.assert_called_once_with(
            repo="/runtime",
            verbosity=2,
            category=None,
            resolved_target=target,
        )

    def test_audit_runner_error_is_reported_as_a_cli_error(self) -> None:
        with mock.patch(
            "cmax.audit_runner.run",
            side_effect=audit_runner.AuditError("audit runner failed"),
        ), contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(
            SystemExit
        ) as raised:
            cli.main(["audit", "--yes"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("audit runner failed", stderr.getvalue())

    def test_audit_forwards_each_explicit_target(self) -> None:
        for flag, target in (
            ("--local", security.SecurityTarget("standalone", "local", True)),
            ("--vm", security.SecurityTarget("standalone", "vm", True)),
            ("--container", security.SecurityTarget("standalone", "container", True)),
            ("--standalone", security.SecurityTarget("standalone", "bare-metal", True)),
            ("--slurm", security.SecurityTarget("slurm", "slurm", True)),
            ("--k8s", security.SecurityTarget("k8s", "k8s", True)),
        ):
            with self.subTest(flag=flag), mock.patch.object(
                security, "detect_target", return_value=target
            ), mock.patch.object(
                target_selection, "prepare_audit_target", return_value=target
            ), mock.patch("cmax.audit_runner.run", return_value=0) as run:
                result = cli.main(["audit", flag])
            self.assertEqual(result, 0)
            run.assert_called_once_with(
                repo=None,
                verbosity=1,
                category=None,
                resolved_target=target,
            )

    def test_each_category_profile_filters_the_report(self) -> None:
        selected = security.SecurityTarget("standalone", "local")
        for category in audit_profiles.AUDIT_CATEGORY_NAMES:
            with self.subTest(category=category), mock.patch.object(
                security, "detect_target", return_value=selected
            ), mock.patch.object(
                target_selection, "prepare_audit_target", return_value=selected
            ), mock.patch(
                "cmax.audit_runner.run", return_value=0
            ) as run:
                result = cli.main(["audit", category, "-vv"])
            self.assertEqual(result, 0)
            run.assert_called_once_with(
                repo=None,
                verbosity=2,
                category=category,
                resolved_target=selected,
            )

    def test_category_profile_accepts_a_target(self) -> None:
        selected = security.SecurityTarget("slurm", "slurm", True)
        with mock.patch.object(
            security, "detect_target", return_value=selected
        ), mock.patch.object(
            target_selection, "prepare_audit_target", return_value=selected
        ), mock.patch("cmax.audit_runner.run", return_value=0) as run:
            result = cli.main(["audit", "hardware", "--slurm"])

        self.assertEqual(result, 0)
        run.assert_called_once_with(
            repo=None,
            verbosity=1,
            category="hardware",
            resolved_target=selected,
        )

    def test_each_target_has_a_subcommand_alias(self) -> None:
        selected = security.SecurityTarget("standalone", "local", True)
        for target_name in cli.AUDIT_TARGET_NAMES:
            with self.subTest(target=target_name), mock.patch.object(
                security, "detect_target", return_value=selected
            ) as detect, mock.patch.object(
                target_selection, "prepare_audit_target", return_value=selected
            ), mock.patch(
                "cmax.audit_runner.run", return_value=0
            ) as run:
                result = cli.main(["audit", target_name])
            self.assertEqual(result, 0)
            detect.assert_called_once_with(target_name)
            run.assert_called_once_with(
                repo=None,
                verbosity=1,
                category=None,
                resolved_target=selected,
            )

    def test_target_alias_rejects_a_parent_target(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(
            SystemExit
        ) as raised:
            cli.main(["audit", "--k8s", "slurm"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("audit target flags are mutually exclusive", stderr.getvalue())

    def test_audit_cancel_stops_before_the_runner(self) -> None:
        with mock.patch.object(
            target_selection,
            "prepare_audit_target",
            side_effect=target_selection.TargetSelectionCancelled("audit canceled"),
        ), mock.patch("cmax.audit_runner.run") as run, contextlib.redirect_stderr(
            io.StringIO()
        ) as error:
            result = cli.main(["audit"])
        self.assertEqual(result, cli.AUDIT_CANCEL_EXIT)
        run.assert_not_called()
        self.assertIn("cmax: audit canceled", error.getvalue())

    def test_local_target_restores_the_previous_kubeconfig(self) -> None:
        selected = security.SecurityTarget("standalone", "local", True)

        def apply_kubeconfig(_value: str | None) -> None:
            cli.os.environ["KUBECONFIG"] = "/new/config"

        with mock.patch.dict(
            cli.os.environ, {"KUBECONFIG": "/original/config"}
        ), mock.patch.object(
            target_selection, "apply_kubeconfig", side_effect=apply_kubeconfig
        ), mock.patch.object(
            security, "detect_target", return_value=selected
        ), mock.patch.object(
            target_selection, "prepare_audit_target", return_value=selected
        ), mock.patch(
            "cmax.audit_runner.run", return_value=0
        ):
            result = cli.main(
                ["audit", "--local", "--kubeconfig", "/new/config"]
            )
            self.assertEqual(cli.os.environ["KUBECONFIG"], "/original/config")

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
