"""Tests for the live audit progress display."""

from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cmax import progress, runtime_paths

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent),
)

import bashtest  # noqa: E402


WORKLOAD = runtime_paths.package_runtime_root() / runtime_paths.AUDIT_RELATIVE


class FakeTty(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


class StepClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def header(title: str) -> list[str]:
    rule = "\x1b[1m\x1b[0;34m" + "═" * 63 + "\x1b[0m"
    return [rule, f"\x1b[1m\x1b[0;34m  {title}\x1b[0m", rule, ""]


def section(label: str) -> str:
    return f"\x1b[0;36m─── {label} ───\x1b[0m"


class PlanExtractionTests(unittest.TestCase):
    def test_plan_comes_from_the_real_slurm_collector(self) -> None:
        steps = progress.collector_steps(WORKLOAD / "cluster-audit-slurm.sh")
        groups = [step.group for step in steps]
        self.assertIn("1. SLURM VERSION & CLUSTER IDENTITY", groups)
        self.assertIn("2.5. WORKER NODE CHECK (via srun)", groups)
        self.assertIn("7. NETWORKING & INFINIBAND", groups)
        first_seen = []
        for group in groups:
            if group not in first_seen:
                first_seen.append(group)
        self.assertEqual(groups, sorted(groups, key=first_seen.index))
        self.assertEqual(
            [step.label for step in steps if step.group == "5. MODULE SYSTEM"],
            ["Lmod", "Module Shell Availability"],
        )

    def test_standalone_plan_excludes_scheduler_checks(self) -> None:
        labels = {
            step.label
            for step in progress.collector_steps(
                WORKLOAD / "cluster-audit-standalone.sh"
            )
        }

        self.assertTrue(
            {
                "Host Summary",
                "GPU Inventory (HEAD NODE FALLBACK - check unavailable)",
                "Monitoring Stack",
            }.issubset(labels)
        )
        self.assertTrue(
            {
                "GRES Configuration",
                "SLURM Topology",
                "SLURM Health Check",
                "Prolog/Epilog",
                "Node Health Check (NHC)",
                "Auto-Remediation",
            }.isdisjoint(labels)
        )

    def test_every_harness_collector_yields_a_plan(self) -> None:
        for harness in ("slurm", "standalone", "k8s"):
            with self.subTest(harness=harness):
                steps = progress.audit_plan(WORKLOAD, harness)
                self.assertGreater(len(steps), 20)
                self.assertEqual(steps[0].group, progress.STARTUP_GROUP)
                self.assertEqual(steps[-1].group, progress.FINALIZE_GROUP)

    def test_each_named_profile_drops_the_unfiltered_findings_phase(self) -> None:
        for profile in ("security", "versions", "hardware", "networking"):
            with self.subTest(profile=profile):
                labels = [
                    step.label
                    for step in progress.audit_plan(
                        WORKLOAD, "slurm", scope=profile
                    )
                ]
                self.assertIn("Audit checks", labels)
                self.assertNotIn("Audit findings", labels)
        self.assertIn(
            "Audit findings",
            [step.label for step in progress.audit_plan(WORKLOAD, "slurm")],
        )

    def test_every_security_plan_uses_only_the_focused_collector(self) -> None:
        for harness in ("slurm", "standalone", "k8s"):
            with self.subTest(harness=harness):
                full = progress.audit_plan(WORKLOAD, harness)
                security = progress.audit_plan(
                    WORKLOAD, harness, scope="security"
                )
                security_groups = {step.group for step in security}

                self.assertLess(len(security), len(full) // 2)
                self.assertIn("1. SECURITY WORKER", security_groups)
                self.assertIn("2. SECURITY RUNTIME", security_groups)
                self.assertNotIn(
                    "4. NVIDIA HPC SDK & SOFTWARE STACK", security_groups
                )
                self.assertNotIn("8. STORAGE & FILESYSTEM", security_groups)
                self.assertNotIn(
                    "9. HEALTH CHECKS & MONITORING", security_groups
                )

    def test_run_sh_phase_markers_match_the_plan(self) -> None:
        for scope in ("full", "security", "hardware"):
            with self.subTest(scope=scope):
                markers = self._emitted_phase_markers(scope)
                self.assertTrue(markers, "run.sh emitted no phase markers")
                plan = progress.audit_plan(
                    WORKLOAD, "slurm", **({} if scope == "full" else {"scope": scope})
                )
                patterns = [step.pattern for step in plan if step.pattern is not None]
                for marker in markers:
                    self.assertTrue(
                        any(pattern.match(marker) for pattern in patterns),
                        f"no {scope} plan step matches run.sh marker {marker!r}",
                    )

    def _emitted_phase_markers(self, scope: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "audit"
            stub = (
                'case "$1" in\n'
                '  *plan_audit.py)\n'
                '    cat > "$3" <<PLAN\n'
                f'OUT_DIR={out_dir}\n'
                'SLUG=test-cluster\n'
                'HARNESS=slurm\n'
                f'AUDIT_ROOT={tmp}\n'
                f'AUDIT_SCRIPT={tmp}/cluster-audit-slurm.sh\n'
                'PLAN\n'
                '    ;;\n'
                '  *run_legacy_audit.py) printf "{}" > "$6" ;;\n'
                '  *) : ;;\n'
                'esac\n'
            )
            run = bashtest.run_bash(
                f'bash {WORKLOAD / "run.sh"}',
                stubs={"python3": stub},
                env={
                    "CLUSTERMAX_REPO_ROOT": tmp,
                    "CLUSTERMAX_AUDIT_SCOPE": scope,
                    "RUN_RESULTS_DIR": str(out_dir),
                },
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            markers = re.findall(r"─── (.+?) ───", run.stdout)
            cyan_markers = re.findall(
                r"\x1b\[0;36m─── (.+?) ───\x1b\[0m", run.stdout
            )
            self.assertEqual(cyan_markers, markers)
            return markers

    def test_interpolated_labels_match_the_resolved_output(self) -> None:
        steps = progress.collector_steps(WORKLOAD / "cluster-audit-slurm.sh")
        check = next(
            step for step in steps if step.label.startswith("Checking compute node")
        )
        self.assertIsNotNone(check.pattern)
        self.assertTrue(
            check.pattern.match("Checking compute node via srun (partition: gpu)")
        )
        self.assertFalse(check.pattern.match("Compute Node OS / Image"))
        steps = progress.collector_steps(WORKLOAD / "audit-common.sh")
        self.assertIn(
            'UFM "Secured Bare Metal Cloud" Profile', [step.label for step in steps]
        )
        self.assertIsNone(progress._label_pattern("${SECTION_NAME}"))
        self.assertIsNotNone(progress._label_pattern("GDRCopy"))


class FeedTests(unittest.TestCase):
    def tracker(self, harness: str = "slurm") -> progress.AuditProgress:
        plan = progress.audit_plan(WORKLOAD, harness)
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        return tracker

    def test_a_section_marks_the_matching_step_running(self) -> None:
        tracker = self.tracker()
        for line in header("1. SLURM VERSION & CLUSTER IDENTITY"):
            tracker.feed(line)
        tracker.feed(section("Cluster Identity"))
        running = tracker.running_step()
        self.assertEqual(running.title, "Cluster Identity")
        self.assertEqual(running.group, "1. SLURM VERSION & CLUSTER IDENTITY")
        self.assertEqual(tracker.steps[0].state, progress.DONE)
        version = next(step for step in tracker.steps if step.label == "SLURM Version")
        self.assertEqual(version.state, progress.SKIPPED)

    def test_the_closing_rule_of_a_header_is_not_read_as_a_title(self) -> None:
        tracker = self.tracker("k8s")
        rule = "═" * 63
        for line in (rule, "  1. KUBERNETES VERSION & CLUSTER IDENTITY", rule):
            tracker.feed(line)
        tracker.feed(section("Kubernetes Version"))
        self.assertEqual(tracker.running_step().title, "Kubernetes Version")
        self.assertEqual(
            tracker.current_group, "1. KUBERNETES VERSION & CLUSTER IDENTITY"
        )

    def test_ordinary_output_after_a_header_is_not_read_as_a_title(self) -> None:
        tracker = self.tracker("k8s")
        rule = "═" * 63
        for line in (rule, "  3. NODE INVENTORY", rule):
            tracker.feed(line)
        group = tracker.current_group
        moved = tracker.feed("  \x1b[0;32m✓\x1b[0m Nodes: 12 ready")
        self.assertFalse(moved)
        self.assertEqual(tracker.current_group, group)

    def test_an_unplanned_check_is_counted_in_its_group(self) -> None:
        tracker = self.tracker()
        for line in header("2. NODE INVENTORY"):
            tracker.feed(line)
        before = tracker.total
        tracker.feed(section("Node Summary"))
        tracker.feed(section('UFM "Secured Bare Metal Cloud" Profile'))
        self.assertEqual(tracker.total, before + 1)
        added = tracker.running_step()
        self.assertEqual(added.title, 'UFM "Secured Bare Metal Cloud" Profile')
        self.assertEqual(added.group, "2. NODE INVENTORY")
        planned = next(step for step in tracker.steps if step.label == "Partitions")
        self.assertEqual(planned.state, progress.TODO)
        tracker.feed(section("Partitions"))
        self.assertIs(tracker.running_step(), planned)
        self.assertEqual(tracker.total, before + 1)
        groups = [title for title, _ in tracker.groups()]
        self.assertEqual(len(groups), len(set(groups)), "a group was split in two")

    def test_finish_settles_every_step_and_freezes_the_clock(self) -> None:
        tracker = self.tracker()
        tracker.feed(section("SLURM Version"))
        tracker.finish(ok=True)
        self.assertEqual(tracker.completed, tracker.total)
        self.assertEqual(tracker.fraction, 1.0)
        self.assertNotIn(
            progress.RUNNING, {step.state for step in tracker.steps}
        )
        first = tracker.elapsed()
        self.assertEqual(first, tracker.elapsed())

    def test_a_failed_run_marks_the_running_step_failed(self) -> None:
        tracker = self.tracker()
        tracker.feed(section("SLURM Version"))
        tracker.finish(ok=False)
        states = [step.state for step in tracker.steps]
        self.assertIn(progress.FAILED, states)
        self.assertIn(progress.TODO, states)


class RenderTests(unittest.TestCase):
    def tracker(self) -> progress.AuditProgress:
        plan = progress.audit_plan(WORKLOAD, "slurm")
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        for line in header("3. GPU CONFIGURATION"):
            tracker.feed(line)
        tracker.feed(section("GDRCopy"))
        return tracker

    def test_final_output_lists_every_group_once(self) -> None:
        tracker = self.tracker()
        tracker.finish()
        renderer = progress.ProgressRenderer(progress.Theme(color=False), width=90)
        lines = renderer.final(tracker, 99.0)
        self.assertIn("complete", lines[0])
        for title, _ in tracker.groups():
            self.assertEqual(
                sum(1 for line in lines if title in line), 1, f"group {title}"
            )

        mixed = progress.AuditProgress(
            [
                progress.Step("FAILED GROUP", "pass-1", state=progress.DONE),
                progress.Step("FAILED GROUP", "pass-2", state=progress.DONE),
                progress.Step("FAILED GROUP", "skip", state=progress.SKIPPED),
                progress.Step("FAILED GROUP", "fail-1", state=progress.FAILED),
                progress.Step("FAILED GROUP", "fail-2", state=progress.FAILED),
            ],
            title="campaign",
        )
        mixed.ok = False
        failed_lines = progress.ProgressRenderer(
            progress.Theme(color=True), width=90
        ).final(mixed, 99.0)
        failed_text = "\n".join(failed_lines)
        self.assertIn("FAILED GROUP", progress.strip_ansi(failed_text))
        self.assertIn("2/5 passed", failed_text)
        self.assertIn("1 skipped", failed_text)
        self.assertIn("2 failed", failed_text)


class AsciiTerminalTests(unittest.TestCase):
    def tracker(self) -> progress.AuditProgress:
        plan = progress.audit_plan(WORKLOAD, "slurm", scope="security")
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        for line in header("3. GPU CONFIGURATION"):
            tracker.feed(line)
        tracker.feed(section("GDRCopy"))
        tracker.feed("Running audit check: gpu-persistence-mode")
        return tracker

    def renderer(self, unicode: bool) -> progress.ProgressRenderer:
        return progress.ProgressRenderer(
            progress.Theme(color=False, unicode=unicode), width=60
        )

    def test_every_rendered_line_is_encodable(self) -> None:
        class Latin1Tty(FakeTty):
            encoding = "iso-8859-1"

        tracker = self.tracker()
        display = progress.make_display(tracker, stream=Latin1Tty())
        self.assertFalse(display.renderer.theme.unicode)
        for view in ("live", "final"):
            with self.subTest(view=view):
                lines = (
                    self.renderer(False).live(tracker, 30.0, 0, 12)
                    if view == "live"
                    else self.renderer(False).final(tracker, 30.0)
                )
                self.assertTrue(lines)
                for line in lines:
                    line.encode("latin1")

    def test_a_collector_label_with_a_glyph_is_transliterated(self) -> None:
        plan = [progress.Step(group="G", label="Fabric MTU ≥ 4096")]
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        line = "\n".join(self.renderer(False).live(tracker, 1.0, 0, 12))
        line.encode("ascii")
        self.assertNotIn("≥", line)


class LiveDisplayTests(unittest.TestCase):
    def display(self, columns: str = "100", lines: str = "24") -> progress.LiveDisplay:
        patcher = mock.patch.dict(os.environ, {"COLUMNS": columns, "LINES": lines})
        patcher.start()
        self.addCleanup(patcher.stop)
        plan = progress.audit_plan(WORKLOAD, "slurm", scope="security")
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        return progress.LiveDisplay(
            tracker, stream=FakeTty(), theme=progress.Theme(), clock=StepClock()
        )

    def test_repaint_rewinds_exactly_as_far_as_it_painted(self) -> None:
        display = self.display()
        display.progress.start()
        display._paint()
        first = display.stream.getvalue()
        self.assertNotIn("\x1b[0A", first)
        painted = display._painted
        self.assertEqual(first.count("\x1b[2K"), painted)
        display.stream.seek(0)
        display.stream.truncate()
        display._paint()
        second = display.stream.getvalue()
        self.assertTrue(second.startswith(f"\x1b[{painted}A"))
        self.assertEqual(second.count("\n"), display._painted)

    def test_the_slow_cadence_still_repaints_on_a_state_change(self) -> None:
        display = self.display()
        clock = [0.0]
        display._clock = lambda: clock[0]
        display.progress._clock = lambda: clock[0]
        display.progress.start()
        display.feed(section("SLURM Version"))
        clock[0] = 400.0
        display._paint()
        self.assertEqual(display._next_interval, display.slow_interval)
        display.stream.seek(0)
        display.stream.truncate()
        display.feed(section("Cluster Identity"))
        self.assertIn("Cluster Identity", progress.strip_ansi(display.stream.getvalue()))
        self.assertEqual(display._next_interval, display.interval)
        display.stream.seek(0)
        display.stream.truncate()
        clock[0] = 900.0
        display._paint()
        display.stream.seek(0)
        display.stream.truncate()
        display.feed("  some ordinary detail line")
        self.assertEqual(display.stream.getvalue(), "")

    def test_close_erases_the_region_and_restores_the_cursor(self) -> None:
        display = self.display()
        display.progress.start()
        display._paint()
        painted = display._painted
        display.stream.seek(0)
        display.stream.truncate()
        display.close(ok=False)
        text = display.stream.getvalue()
        self.assertIn(f"\x1b[{painted}A\x1b[J", text)
        self.assertIn("\x1b[?25h", text)
        self.assertIn("failed", progress.strip_ansi(text))
        after_close = display.stream.getvalue()
        display.close(ok=False)
        display.feed(section("GDRCopy"))
        display.update(lambda tracker: tracker.feed(section("GDRCopy")))
        self.assertEqual(display.stream.getvalue(), after_close)
        display.print_above("worker interrupted")
        self.assertTrue(display.stream.getvalue().endswith("worker interrupted\n"))


class EndToEndTests(unittest.TestCase):
    script = "\n".join(
        [
            "#!/bin/bash",
            'echo "Cluster slug: fake"',
            'printf "%s\\n" "$(printf "%.0s═" {1..40})"',
            'echo "  2. NODE INVENTORY"',
            'printf "%s\\n" "$(printf "%.0s═" {1..40})"',
            "",
            'echo "─── Node Summary ───"',
            'echo "  some detail"',
            'echo "─── Audit checks ───"',
            'echo "Running audit check: fabric/nic-topology-check.py"',
            'echo "─── Writing audit values ───"',
            'echo "AUDIT FINDINGS (2)"',
            'echo "  driver not installed"',
            "exit ${FAKE_EXIT:-0}",
        ]
    )

    def run_script(self, exit_code: int = 0, stream=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector.sh"
            path.write_text(self.script)
            plan = progress.audit_plan(WORKLOAD, "slurm")
            tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
            target = stream if stream is not None else io.StringIO()
            code, output = progress.run_with_progress(
                ["bash", str(path)],
                cwd=tmp,
                env={**os.environ, "FAKE_EXIT": str(exit_code)},
                progress=tracker,
                stream=target,
            )
            return code, output, target.getvalue(), tracker

    def test_a_pipe_gets_one_plain_line_per_check(self) -> None:
        code, output, shown, tracker = self.run_script()
        self.assertEqual(code, 0)
        self.assertIn("AUDIT FINDINGS (2)", output)
        self.assertIn("Cluster slug: fake", output)
        self.assertIn("some detail", output)
        self.assertIn("─── Node Summary ───", output)
        self.assertIn("2. NODE INVENTORY / Node Summary", shown)
        self.assertIn("FINALIZE / Audit checks", shown)
        self.assertIn("checks in", shown)
        self.assertNotIn("\x1b[", shown)
        self.assertEqual(tracker.completed, tracker.total)

    def test_a_terminal_gets_a_redrawn_region_and_a_final_checklist(self) -> None:
        code, _output, shown, _tracker = self.run_script(stream=FakeTty())
        self.assertEqual(code, 0)
        self.assertIn("\x1b[2K", shown)
        self.assertIn("\x1b[?25l", shown)
        self.assertIn("\x1b[?25h", shown)
        plain = progress.strip_ansi(shown)
        self.assertIn("2. NODE INVENTORY", plain)
        self.assertIn("audit complete", plain)

    def test_a_failing_collector_reports_a_failed_run(self) -> None:
        code, output, shown, tracker = self.run_script(exit_code=3)
        self.assertEqual(code, 3)
        self.assertIn("failed", shown)
        self.assertFalse(tracker.ok)
        buffer = io.StringIO()
        progress.print_failure_tail(output, stream=buffer)
        self.assertIn("driver not installed", buffer.getvalue())

    def test_print_tail_reprints_the_findings_block(self) -> None:
        output = "─── Node Summary ───\nAUDIT FINDINGS (2)\n  driver not installed\n"
        buffer = io.StringIO()
        self.assertTrue(progress.print_tail(output, "AUDIT FINDINGS", stream=buffer))
        text = buffer.getvalue()
        self.assertTrue(text.startswith("AUDIT FINDINGS (2)"))
        self.assertIn("driver not installed", text)
        self.assertNotIn("Node Summary", text)
        self.assertFalse(progress.print_tail(output, "NO SUCH MARKER", stream=buffer))
        terminal = FakeTty()
        progress.print_tail(
            "AUDIT FINDINGS (1)\nCVEs: CVE-2024-3446\n",
            "AUDIT FINDINGS",
            stream=terminal,
        )
        self.assertIn("\x1b]8;;https://nvd.nist.gov/vuln/detail/CVE-2024-3446", terminal.getvalue())
        self.assertIn("\x1b[4mCVE-2024-3446\x1b[24m", terminal.getvalue())

    def test_interrupt_kills_the_collector_and_closes_the_display(self) -> None:
        process = mock.Mock(stdout=["collector output\n"])
        display = mock.Mock()
        display.feed.side_effect = KeyboardInterrupt
        tracker = progress.AuditProgress([], title="audit")
        with mock.patch.object(progress.subprocess, "Popen", return_value=process), mock.patch.object(
            progress, "make_display", return_value=display
        ), self.assertRaises(KeyboardInterrupt):
            progress.run_with_progress(
                ["collector"], cwd=None, env=None, progress=tracker, stream=FakeTty()
            )
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()
        display.close.assert_called_once_with(ok=False)

    def test_a_non_utf8_byte_does_not_kill_the_collector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector.sh"
            path.write_text(
                "#!/bin/bash\n"
                'echo "─── Node Summary ───"\n'
                r"printf 'dmesg: \xff\xfe bad bytes\n'" + "\n"
                'echo "─── Audit checks ───"\n'
            )
            plan = progress.audit_plan(WORKLOAD, "slurm")
            tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
            code, output = progress.run_with_progress(
                ["bash", str(path)], cwd=tmp, env=dict(os.environ),
                progress=tracker, stream=io.StringIO(),
            )
        self.assertEqual(code, 0)
        self.assertIn("bad bytes", output)
        self.assertIn("�", output)
        self.assertEqual(tracker.completed, tracker.total)


if __name__ == "__main__":
    unittest.main()
