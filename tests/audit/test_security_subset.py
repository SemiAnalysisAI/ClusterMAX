#!/usr/bin/env python3
"""The security audit must report a strict subset of the full audit.

`cmax audit security` filters the full report to the security profile
(categories {versions, isolation} plus the security extension checks), so for
one set of collected values every security check must appear in the full audit
with an identical verdict, and the printed report must be graded against the
same harness as the exit code.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cmax import audit_report, audit_runner, runtime_paths, security


RUNTIME_ROOT = runtime_paths.package_runtime_root()
HARNESSES = ("standalone", "slurm", "k8s")
SECURITY_CATEGORIES = frozenset({"versions", "isolation"})


def subset_values(harness: str) -> dict:
    """Representative audit values covering every reportable check state.

    Includes pass / fail / unknown / not-applicable securityVersions records,
    the security.* blocks the extension checks read, container / software /
    networking keys, one guard-suppressed failing value
    (securityVersions.dpuHostIsolation.status is unknown with no BlueField
    observed, and containers.nvidiaContainerToolkit is false while the worker
    check never ran), and one unverified unknown status
    (security.januscape.status).
    """
    return {
        "cluster": {"orchestrator": harness},
        "audit_data": {
            "securityVersions": {
                "nvidiaDriver": {
                    "status": "fail",
                    "version": "580.126.09",
                    "minimum": "580.159.03",
                    "detail": "Below the minimum version",
                },
                "nvidiaContainerToolkit": {
                    "status": "unknown",
                    "version": "unknown",
                    "minimum": "1.19.1",
                },
                "cudaToolkit": {
                    "status": "not_applicable",
                    "version": "not-installed",
                    "minimum": "13.1",
                },
                "runc": {"status": "pass", "version": "1.3.3", "minimum": "1.3.3"},
                "docker": {
                    "status": "pass",
                    "version": "29.4.3",
                    "minimum": "29.4.3",
                },
                "connectxFirmware": {
                    "status": "not_applicable",
                    "minimum": "NVIDIA ConnectX/BlueField only",
                    "devices": [],
                },
                "dcgm": {"status": "pass", "version": "4.6.0", "minimum": "4.5.3"},
                "dcgmExporter": {
                    "status": "pass",
                    "version": "4.9.0",
                    "minimum": "4.8.2",
                },
                # Guard-suppressed: the unknown verdict matches its finding
                # rule, but no BlueField was observed so the guard keeps the
                # rule from firing.
                "dpuHostIsolation": {
                    "status": "unknown",
                    "detail": "mlxconfig usually needs root.",
                },
                "virtioNetBluefield": {
                    "status": "not_applicable",
                    "exposure": "none",
                    "detail": "No BlueField DPU is present.",
                },
            },
            "security": {
                "guestKernel": {
                    "running": "6.8.0-58-generic",
                    "newestInstalled": "6.8.0-136-generic",
                    "newerInstalled": True,
                },
                "fragnesia": {
                    "status": "fail",
                    "ubuntuNoblePackageMinimum": "6.8.0-124.124",
                },
                # Unverified unknown status: reported as a warning.
                "januscape": {"status": "unknown"},
                "bmcIpmi": {"exposed": False},
                "ufmSecuredBareMetalCloud": {
                    "applicable": False,
                    "status": "not-applicable",
                },
                "pciePassthrough": {"hostVerificationRequired": True},
                "nvidiaMay2026": {"nvlinkExposed": False},
            },
            "containers": {
                # Guard-suppressed: the worker check never ran, so the failing
                # toolkit boolean is inconclusive rather than evidence of
                # absence.
                "workerCheckOk": False,
                "nvidiaContainerToolkit": False,
                "pyxisRuntimeWorks": False,
            },
            "software": {
                "nvccInPath": True,
                "nvhpc": {"installed": False},
                "ncu": {"installed": True, "profilingEnabled": True},
            },
            "networking": {"hcaNamingValid": True, "topologyConfigured": False},
            "gpus": {"gdrcopy": {"installed": True}},
            "hbm_memory_exposure": {"status": "warning"},
            "storage": {"rwxStatus": "fail"},
            "kubelet_cpu_manager_policy": {"status": "warning"},
            "healthChecks": {
                "nhcInstalled": False,
                "monitoringStack": {"dcgmExporter": True},
            },
        },
    }


def _verdicts(checks: list) -> dict[str, tuple]:
    return {
        check.key: (check.key, check.status, check.observed, check.assessment)
        for check in checks
    }


class SecuritySubsetTests(unittest.TestCase):
    def test_security_checks_appear_identically_in_the_full_audit(self) -> None:
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                values = subset_values(harness)
                full = _verdicts(
                    audit_report.evaluate(
                        values, RUNTIME_ROOT, category=None, harness=harness
                    )
                )
                subset = _verdicts(
                    audit_report.evaluate(
                        values, RUNTIME_ROOT, category="security", harness=harness
                    )
                )

                self.assertTrue(subset)
                for key, verdict in subset.items():
                    self.assertIn(key, full)
                    self.assertEqual(verdict, full[key])

    def test_security_set_is_the_full_set_filtered_to_security_categories(
        self,
    ) -> None:
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                values = subset_values(harness)
                full = audit_report.evaluate(
                    values, RUNTIME_ROOT, category=None, harness=harness
                )
                subset = audit_report.evaluate(
                    values, RUNTIME_ROOT, category="security", harness=harness
                )

                subset_keys = {check.key for check in subset}
                self.assertEqual(
                    subset_keys,
                    {
                        check.key
                        for check in full
                        if check.category in SECURITY_CATEGORIES
                    },
                )
                self.assertTrue(
                    audit_report._SECURITY_EXTENSION_IDS.issubset(subset_keys)
                )
                self.assertTrue(
                    all(check.category in SECURITY_CATEGORIES for check in subset)
                )

    def test_check_specs_for_security_are_a_subset_for_every_harness(self) -> None:
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                full = {
                    spec.key: spec
                    for spec in audit_report.list_check_specs(
                        RUNTIME_ROOT, category=None, harness=harness
                    )
                }
                subset = audit_report.list_check_specs(
                    RUNTIME_ROOT, category="security", harness=harness
                )

                self.assertTrue(subset)
                for spec in subset:
                    self.assertIn(spec.key, full)
                    self.assertEqual(spec.title, full[spec.key].title)
                    self.assertEqual(spec.category, full[spec.key].category)

    def test_guard_suppressed_checks_stay_visible_in_both_profiles(self) -> None:
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                values = subset_values(harness)
                full = _verdicts(
                    audit_report.evaluate(
                        values, RUNTIME_ROOT, category=None, harness=harness
                    )
                )
                subset = _verdicts(
                    audit_report.evaluate(
                        values, RUNTIME_ROOT, category="security", harness=harness
                    )
                )

                # A guard-suppressed security check renders as SKIPPED instead
                # of vanishing, identically in both profiles.
                key = "securityVersions.dpuHostIsolation.status"
                self.assertIn(key, full)
                self.assertIn(key, subset)
                self.assertEqual(full[key], subset[key])
                self.assertEqual(full[key][1], audit_report.SKIPPED)
                if harness == "standalone":
                    self.assertEqual(full[key][2], "n/a for standalone machines")
                    self.assertEqual(full[key][3], "")
                else:
                    # No BlueField was observed, so the skip explains the check
                    # does not apply instead of demanding verification.
                    self.assertIn("Not applicable", full[key][3])
                    self.assertIn("BlueField", full[key][3])
                # A guard-suppressed non-security check stays visible in the
                # full report and is not counted as a pass: the worker check
                # never ran, so the toolkit value is unverified.
                toolkit = full["containers.nvidiaContainerToolkit"]
                self.assertEqual(toolkit[1], audit_report.SKIPPED)
                self.assertIn("unverified", toolkit[3])
                self.assertNotIn("containers.nvidiaContainerToolkit", subset)
                # The unverified unknown status is a warning in both profiles.
                januscape_full = full["security.januscape.status"]
                self.assertEqual(januscape_full[1], audit_report.WARNING)
                self.assertEqual(januscape_full, subset["security.januscape.status"])

    def test_render_grades_with_the_explicit_harness(self) -> None:
        # The merged values claim a different orchestrator than the operator's
        # confirmed target; render must follow the explicit harness so the
        # printed report matches the exit-code evaluation.
        values = subset_values("standalone")
        values["cluster"]["orchestrator"] = "slurm"
        with tempfile.TemporaryDirectory() as tmp:
            values_path = Path(tmp) / "audit.values.json"
            values_path.write_text(json.dumps(values))

            report = audit_report.render(
                values_path,
                RUNTIME_ROOT,
                rules_root=RUNTIME_ROOT,
                verbosity=1,
                harness="standalone",
            )
            fallback = audit_report.render(
                values_path,
                RUNTIME_ROOT,
                rules_root=RUNTIME_ROOT,
                verbosity=1,
            )

        expected = audit_report.format_report(
            audit_report.evaluate(values, RUNTIME_ROOT, harness="standalone"),
            verbosity=1,
        )
        self.assertEqual(report, expected)
        # Without the pass-through, render falls back to the recorded
        # orchestrator and grades a different check set.
        self.assertNotEqual(report, fallback)
        self.assertIn("Observed: n/a for standalone machines", report)
        self.assertNotIn(
            "This check does not apply to the standalone audit target.", report
        )

    def test_runner_prints_and_exits_from_the_same_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runner = runtime_paths.audit_runner(runtime)
            runner.parent.mkdir(parents=True)
            runner.write_text("#!/bin/sh\n")
            # The collector records a different orchestrator than the
            # operator's confirmed target.
            recorded = json.dumps({"cluster": {"orchestrator": "standalone"}})

            def finish_audit(*args, **kwargs):
                audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
                (audit_dir / "audit.values.json").write_text(recorded)
                return 0, "collector output"

            with (
                mock.patch.object(security, "find_runtime_root", return_value=runtime),
                mock.patch.object(
                    audit_runner, "_audit_dir", return_value=Path(tmp) / "audit"
                ),
                mock.patch.object(
                    audit_runner.progress, "run_with_progress", side_effect=finish_audit
                ),
                mock.patch.object(
                    audit_runner.audit_report, "render", return_value="report"
                ) as render,
                mock.patch.object(
                    audit_runner.audit_report, "evaluate", return_value=[]
                ) as evaluate,
            ):
                result = audit_runner.run(
                    category="security",
                    resolved_target=security.SecurityTarget("slurm", "slurm", True),
                    exit_on_fail=True,
                )

        self.assertEqual(result, 0)
        self.assertEqual(render.call_args.kwargs["harness"], "slurm")
        self.assertEqual(evaluate.call_args.kwargs["harness"], "slurm")
        self.assertEqual(render.call_args.kwargs["environment"], "slurm")
        self.assertEqual(evaluate.call_args.kwargs["environment"], "slurm")
        self.assertEqual(
            render.call_args.kwargs["harness"],
            evaluate.call_args.kwargs["harness"],
        )
        self.assertEqual(
            render.call_args.kwargs["category"],
            evaluate.call_args.kwargs["category"],
        )


if __name__ == "__main__":
    unittest.main()
