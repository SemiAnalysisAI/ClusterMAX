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
    """A terminal-looking stream, so the live renderer is exercised."""

    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


class StepClock:
    """A clock that advances one second per read, for stable durations."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def header(title: str) -> list[str]:
    """The three lines print_header writes, colors included."""
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
        # Groups stay contiguous and in source order, which is what lets the
        # display mark everything before an arriving check as finished.
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
        """The phases run.sh owns must be recognized, not counted as extras.

        run.sh prints its own phase markers for the work it does around the
        collector. If one is renamed without updating audit_plan, the display
        silently grows a step and the percentage jumps at the end. The script
        is executed with stub interpreters rather than read, so the markers
        asserted here are the ones an operator's terminal actually receives.
        """
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
        """Run run.sh under stub interpreters; return the phase markers it printed.

        Only plan_audit.py and run_legacy_audit.py have to produce anything:
        the first writes the plan the script sources, the second writes the
        file the script reads back. Every other python3 call is a no-op, so
        the run exercises the script's own control flow and its markers.
        """
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

    def test_a_single_quoted_label_is_read(self) -> None:
        # audit-common.sh passes a label containing a double quote, so it is
        # single-quoted at the call site.
        steps = progress.collector_steps(WORKLOAD / "audit-common.sh")
        self.assertIn(
            'UFM "Secured Bare Metal Cloud" Profile', [step.label for step in steps]
        )

    def test_a_label_that_is_only_interpolation_matches_nothing(self) -> None:
        self.assertIsNone(progress._label_pattern("${SECTION_NAME}"))
        self.assertIsNotNone(progress._label_pattern("GDRCopy"))


class FeedTests(unittest.TestCase):
    def tracker(self, harness: str = "slurm") -> progress.AuditProgress:
        plan = progress.audit_plan(WORKLOAD, harness)
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        return tracker

    def test_startup_step_runs_before_any_output_arrives(self) -> None:
        tracker = self.tracker()
        step = tracker.running_step()
        self.assertIsNotNone(step)
        self.assertEqual(step.group, progress.STARTUP_GROUP)

    def test_a_section_marks_the_matching_step_running(self) -> None:
        tracker = self.tracker()
        for line in header("1. SLURM VERSION & CLUSTER IDENTITY"):
            tracker.feed(line)
        tracker.feed(section("Cluster Identity"))
        running = tracker.running_step()
        self.assertEqual(running.title, "Cluster Identity")
        self.assertEqual(running.group, "1. SLURM VERSION & CLUSTER IDENTITY")
        # The startup step finished rather than being reported as skipped: it
        # ran, the collector just never announced its end.
        self.assertEqual(tracker.steps[0].state, progress.DONE)
        # "SLURM Version" was announced by neither, so it did not run.
        version = next(step for step in tracker.steps if step.label == "SLURM Version")
        self.assertEqual(version.state, progress.SKIPPED)

    def test_the_closing_rule_of_a_header_is_not_read_as_a_title(self) -> None:
        tracker = self.tracker("k8s")
        # The k8s collector's print_header writes no blank line after its
        # closing rule, so the next line is real output.
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

    def test_a_check_line_annotates_the_running_step(self) -> None:
        tracker = self.tracker()
        tracker.feed(section("Audit checks"))
        tracker.feed("Running audit check: fabric/nic-topology-check.py")
        step = tracker.running_step()
        self.assertEqual(step.label, "Audit checks")
        self.assertEqual(step.detail, "fabric/nic-topology-check.py")
        # A check is progress inside one step, never a new step.
        self.assertEqual(tracker.total, len(tracker.steps))

    def test_the_first_line_inside_a_check_explains_the_wait(self) -> None:
        tracker = self.tracker()
        tracker.feed(section("Checking compute node via srun (partition: cluster)"))
        tracker.feed(
            "    Running single srun job to gather GPU, IB, and software facts..."
        )
        tracker.feed("  \x1b[0;32m✓\x1b[0m Worker check: SUCCESS (node: node001)")
        step = tracker.running_step()
        # The first line said what the check is waiting on; later lines are
        # results, and replacing the detail with each one only flickers.
        self.assertEqual(
            step.detail, "Running single srun job to gather GPU, IB, and software facts..."
        )

    def test_an_unplanned_check_is_counted_in_its_group(self) -> None:
        """Checks printed from audit-common.sh cannot be placed from source.

        The shared helpers are called from inside the collector, so their
        position in the run is not visible in either file's source order. They
        arrive as unplanned checks instead, and must land in the group that is
        running rather than splitting it or resetting the plan.
        """
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
        # The rest of the group must still be ahead of the cursor. Inserting the
        # unplanned check at the end of the group marked them skipped, and the
        # forward-only match then re-inserted each one as a duplicate when it
        # printed. On a Slurm audit that reported "SLURM Topology" as skipped.
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
        # Nothing is claimed as skipped, because the run did not get that far.
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

    def test_live_output_fits_a_short_terminal(self) -> None:
        """A region taller than the window breaks the repaint's rewind."""
        renderer = progress.ProgressRenderer(progress.Theme(), width=80)
        tracker = self.tracker()
        for height in (8, 12, 20, 40):
            with self.subTest(height=height):
                lines = renderer.live(tracker, 30.0, 3, height)
                self.assertLessEqual(len(lines), max(8, height - 2))
                for line in lines:
                    self.assertLessEqual(len(progress.strip_ansi(line)), 80)

    def test_a_short_terminal_keeps_the_running_check_visible(self) -> None:
        """Trimming drops context, never the line the operator is waiting on."""
        renderer = progress.ProgressRenderer(progress.Theme(color=False), width=80)
        tracker = self.tracker()
        lines = renderer.live(tracker, 30.0, 0, 12)
        text = "\n".join(lines)
        self.assertIn("3. GPU CONFIGURATION", text)
        self.assertIn("GDRCopy", text)
        self.assertRegex(lines[1], r"\d+%")
        # Groups still to run are summarized rather than listed one by one.
        self.assertNotIn("12. GITHUB SOURCE", text)
        self.assertIn("more group(s) to run", text)

    def test_live_output_shows_the_bar_the_current_check_and_a_todo(self) -> None:
        renderer = progress.ProgressRenderer(progress.Theme(color=False), width=90)
        tracker = self.tracker()
        lines = renderer.live(tracker, 30.0, 0, 40)
        text = "\n".join(lines)
        self.assertIn("audit", lines[0])
        self.assertRegex(lines[1], r"\d+%")
        self.assertIn(f"/{len(tracker.steps)} checks", lines[1])
        self.assertIn("3. GPU CONFIGURATION", text)
        self.assertIn("GDRCopy", text)
        self.assertIn("7. NETWORKING & INFINIBAND", text)

    def test_only_checks_that_ran_get_a_line_under_the_current_group(self) -> None:
        """The plan holds conditional checks this cluster may never reach."""
        tracker = self.tracker()
        skipped = [
            step.title
            for step in tracker.steps
            if step.group == "3. GPU CONFIGURATION" and step.state == progress.SKIPPED
        ]
        self.assertIn("GPUDirect RDMA", skipped)
        renderer = progress.ProgressRenderer(progress.Theme(color=False), width=90)
        text = "\n".join(renderer.live(tracker, 30.0, 0, 40))
        indented = [line for line in text.splitlines() if line.startswith("      ")]
        self.assertEqual(len(indented), 1)
        self.assertIn("GDRCopy", indented[0])

    def test_a_long_run_collapses_the_finished_groups(self) -> None:
        """Late in a run the finished groups outnumber the window."""
        plan = progress.audit_plan(WORKLOAD, "slurm")
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        for group in (
            "1. SLURM VERSION & CLUSTER IDENTITY",
            "2. NODE INVENTORY",
            "2.5. WORKER NODE CHECK (via srun)",
            "3. GPU CONFIGURATION",
            "4. NVIDIA HPC SDK & SOFTWARE STACK",
            "5. MODULE SYSTEM",
            "6. CONTAINER SUPPORT",
            "7. NETWORKING & INFINIBAND",
            "8. STORAGE & FILESYSTEM",
            "9. HEALTH CHECKS & MONITORING",
            "10. ACCESS & AUTHENTICATION",
        ):
            for line in header(group):
                tracker.feed(line)
            for step in [s for s in tracker.steps if s.group == group]:
                tracker.feed(section(step.label))
        renderer = progress.ProgressRenderer(progress.Theme(color=False), width=90)
        lines = renderer.live(tracker, 300.0, 0, 14)
        text = "\n".join(lines)
        self.assertLessEqual(len(lines), 12)
        self.assertIn("group(s) complete", text)
        self.assertIn("10. ACCESS & AUTHENTICATION", text)
        self.assertNotIn("2. NODE INVENTORY", text)
        self.assertIn("more group(s) to run", text)

    def test_colors_are_emitted_only_when_asked(self) -> None:
        tracker = self.tracker()
        colored = progress.ProgressRenderer(progress.Theme(color=True), width=90)
        plain = progress.ProgressRenderer(progress.Theme(color=False), width=90)
        self.assertIn("\x1b[", "".join(colored.live(tracker, 30.0, 0, 40)))
        self.assertNotIn("\x1b[", "".join(plain.live(tracker, 30.0, 0, 40)))
        finding_intro = progress.color_status_text(
            "These items were detected as missing / not-OK."
        )
        self.assertIn("\x1b[31mmissing\x1b[0m", finding_intro)
        self.assertIn("not-OK", finding_intro)
        self.assertNotIn("not-\x1b[32mOK", finding_intro)
        linked = progress.linkify_report_text(
            "CVEs: CVE-2024-3446; Advisories: GHSA-9493-h29p-rfm2",
            prompt_toolkit=True,
        )
        self.assertIn("\x01\x1b]8;;https://nvd.nist.gov/vuln/detail/CVE-2024-3446", linked)
        self.assertIn("\x1b[4mCVE-2024-3446\x1b[24m", linked)
        self.assertIn("https://github.com/advisories/GHSA-9493-h29p-rfm2", linked)
        boundary = "\x01\x1b]8;;\x1b\\\x02"
        self.assertTrue(linked.startswith(boundary))
        self.assertTrue(linked.endswith(boundary + " "))

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
        self.assertIn("\x1b[31;1mFAILED GROUP\x1b[0m", failed_text)
        self.assertIn("2/5 passed", failed_text)
        self.assertIn("1 skipped", failed_text)
        self.assertIn("2 failed", failed_text)

    def test_ascii_theme_avoids_box_drawing(self) -> None:
        renderer = progress.ProgressRenderer(
            progress.Theme(color=False, unicode=False), width=90
        )
        text = "\n".join(renderer.live(self.tracker(), 30.0, 0, 40))
        self.assertNotIn("█", text)
        self.assertNotIn("✓", text)
        self.assertIn("#", text)




class AsciiTerminalTests(unittest.TestCase):
    """A terminal that cannot encode the display's glyphs must still get lines."""

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
        """One unencodable code point takes the whole live display down."""
        tracker = self.tracker()
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

    def test_the_detail_arrow_and_the_clip_mark_have_ascii_forms(self) -> None:
        tracker = self.tracker()
        tracker.steps[tracker.cursor].detail = "waiting on srun"
        wide = "\n".join(self.renderer(True).live(tracker, 30.0, 0, 40))
        plain = "\n".join(self.renderer(False).live(tracker, 30.0, 0, 40))
        self.assertIn("→", wide)
        self.assertNotIn("→", plain)
        self.assertIn("->", plain)
        self.assertIn("...", plain)

    def test_a_collector_label_with_a_glyph_is_transliterated(self) -> None:
        """The label is the collector's text, not the display's own."""
        plan = [progress.Step(group="G", label="Fabric MTU ≥ 4096")]
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        tracker.start()
        line = "\n".join(self.renderer(False).live(tracker, 1.0, 0, 12))
        line.encode("ascii")
        self.assertNotIn("≥", line)

    def test_a_clipped_line_never_exceeds_the_width(self) -> None:
        for unicode in (True, False):
            with self.subTest(unicode=unicode):
                renderer = self.renderer(unicode)
                for line in renderer.live(self.tracker(), 30.0, 0, 40):
                    self.assertLessEqual(len(progress.strip_ansi(line)), 60)


class LiveDisplayTests(unittest.TestCase):
    def display(self, columns: str = "100", lines: str = "24") -> progress.LiveDisplay:
        # The size stays patched for the whole test: each repaint re-reads it so
        # the region follows a terminal resize.
        patcher = mock.patch.dict(os.environ, {"COLUMNS": columns, "LINES": lines})
        patcher.start()
        self.addCleanup(patcher.stop)
        plan = progress.audit_plan(WORKLOAD, "slurm", scope="security")
        tracker = progress.AuditProgress(plan, title="audit", clock=StepClock())
        return progress.LiveDisplay(
            tracker, stream=FakeTty(), theme=progress.Theme(), clock=StepClock()
        )

    def test_a_late_update_after_close_does_not_repaint(self) -> None:
        """A --parallel interrupt leaves workers running past teardown.

        The pool is shut down with wait=False, so a heartbeat or a result can
        reach the display after the final checklist is on screen. A repaint
        then rewinds over lines the region never wrote.
        """
        display = self.display()
        display.progress.start()
        display._paint()
        display.close(ok=False)
        after_close = display.stream.getvalue()
        display.update(lambda tracker: tracker.feed(section("GDRCopy")))
        display.feed(section("GDRCopy"))
        self.assertEqual(display.stream.getvalue(), after_close)

    def test_a_second_close_does_not_print_the_checklist_twice(self) -> None:
        display = self.display()
        display.progress.start()
        display.close(ok=True)
        once = display.stream.getvalue()
        display.close(ok=True)
        self.assertEqual(display.stream.getvalue(), once)

    def test_a_late_line_after_close_still_reaches_the_terminal(self) -> None:
        """Losing a worker's output would be worse than losing the region."""
        display = self.display()
        display.progress.start()
        display.close(ok=False)
        display.stream.seek(0)
        display.stream.truncate()
        display.print_above("==> cmax performance: fio: interrupted")
        text = display.stream.getvalue()
        self.assertEqual(text, "==> cmax performance: fio: interrupted\n")
        self.assertNotIn("\x1b[", text)

    def test_a_resize_starts_a_fresh_region(self) -> None:
        display = self.display()
        display.progress.start()
        display._paint()
        self.assertGreater(display._painted, 0)
        os.environ["LINES"] = "14"
        display.stream.seek(0)
        display.stream.truncate()
        display._paint()
        text = display.stream.getvalue()
        # No rewind into a region whose lines the resize just rewrapped.
        self.assertNotIn("A", re.sub(r"\x1b\[2K", "", text.split("\n")[0]))
        self.assertEqual(display.height, 14)
        self.assertLessEqual(display._painted, 12)

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
        # A wrong rewind is what corrupts the scrollback, so pin the exact move.
        self.assertTrue(second.startswith(f"\x1b[{painted}A"))
        self.assertEqual(second.count("\n"), display._painted)

    def test_the_region_never_grows_past_the_window(self) -> None:
        display = self.display()
        heading = section("Node Resources (Sample)")
        display.capture_output(heading, owner="Node Resources (Sample)")
        self.assertNotIn(
            ("separator", "── Node Resources (Sample) ──"), display._timeline
        )
        self.assertEqual(display._timeline, [("output", heading)])
        self.assertEqual(len(display._timeline_rendered), len(display._timeline))
        display.capture_output(
            "  1. KUBERNETES VERSION & CLUSTER IDENTITY\n"
            "═══════════════════════════════════════════════════════════════",
            owner="CAMPAIGN",
        )
        control = progress._TimelineControl(display)
        display._timeline_control = control
        self.assertNotIn(("separator", "── CAMPAIGN ──"), display._timeline)
        self.assertEqual(control.create_content(100, 10).line_count, 3)
        control.move_cursor_up()
        scrolled_cursor = control._cursor_line
        self.assertFalse(control._follow_tail)
        display.capture_output("new output while scrolled", owner="CAMPAIGN")
        self.assertEqual(control._cursor_line, scrolled_cursor)
        self.assertEqual(control.create_content(100, 10).line_count, 4)
        control.jump_to_end()
        self.assertTrue(control._follow_tail)
        display.capture_output("new output at tail", owner="CAMPAIGN")
        control.create_content(100, 10)
        self.assertEqual(control._cursor_line, len(display._timeline) - 1)
        for index in range(20):
            display.capture_output(f"scroll line {index}", owner="CAMPAIGN")
        control.create_content(100, 4)
        tail_top = control.viewport_top
        control.scroll_viewport(-3)
        self.assertEqual(control.viewport_top, tail_top - 3)
        control.scroll_viewport(-3)
        self.assertEqual(control.viewport_top, tail_top - 6)
        self.assertFalse(control._follow_tail)
        visible_before_update = control.create_content(100, 4).line_count
        render_snapshot = control._render_lines
        display._mark_scroll_input()
        display.capture_output("output during scroll", owner="CAMPAIGN")
        display.capture_output("heartbeat one", owner="CAMPAIGN", transient=True)
        display.capture_output("heartbeat two", owner="CAMPAIGN", transient=True)
        self.assertEqual(
            control.create_content(100, 4).line_count,
            visible_before_update,
        )
        display._last_scroll_input_at = 0.0
        self.assertEqual(
            control.create_content(100, 4).line_count,
            visible_before_update + 2,
        )
        self.assertEqual(control._render_lines, display._timeline_rendered)
        self.assertIs(control._render_lines, render_snapshot)
        display._tui_app = mock.Mock()
        display._tui_app.loop = mock.Mock()
        viewport_before_burst = control.viewport_top
        display._queue_tui_scroll("wheel_up")
        display._queue_tui_scroll("wheel_up")
        self.assertEqual(display._pending_wheel_delta, -6)
        display._tui_app.loop.call_soon_threadsafe.assert_called_once()
        schedule_flush = (
            display._tui_app.loop.call_soon_threadsafe.call_args.args[0]
        )
        schedule_flush()
        display._tui_app.loop.call_later.assert_called_once()
        scheduled_flush = display._tui_app.loop.call_later.call_args.args[1]
        scheduled_flush()
        self.assertEqual(control.viewport_top, viewport_before_burst - 6)
        self.assertEqual(display._pending_wheel_delta, 0)
        display._tui_app.loop.call_later.reset_mock()
        display._tui_app.loop.call_soon_threadsafe.reset_mock()
        display._queue_tui_scroll("wheel_down")
        display._queue_tui_scroll("wheel_down")
        display._queue_tui_scroll("wheel_up")
        self.assertEqual(display._pending_wheel_delta, -3)
        display._tui_app.loop.call_soon_threadsafe.assert_called_once()
        schedule_flush = (
            display._tui_app.loop.call_soon_threadsafe.call_args.args[0]
        )
        schedule_flush()
        display._tui_app.loop.call_later.assert_called_once()
        display._flush_tui_scroll()
        self.assertEqual(
            progress._vt100_wheel_action("\x1b[<64;80;24M"),
            "wheel_up",
        )
        self.assertEqual(
            progress._vt100_wheel_action("\x1b[<65;80;24M"),
            "wheel_down",
        )
        self.assertIsNone(progress._vt100_wheel_action("\x1b[<0;80;24M"))
        with (
            mock.patch.object(progress, "Application") as application,
            mock.patch.object(progress, "create_input"),
            mock.patch.object(progress, "create_output"),
        ):
            display._enter_tui()
        options = application.call_args.kwargs
        self.assertFalse(options["full_screen"])
        self.assertTrue(options["erase_when_done"])
        self.assertEqual(options["min_redraw_interval"], 1 / 30)
        self.assertEqual(options["max_render_postpone_time"], 0)
        display._replay_output()
        self.assertEqual(
            progress.strip_ansi(display.stream.getvalue()).count(
                "─── Node Resources (Sample) ───"
            ),
            1,
        )
        self.assertNotIn(
            "KUBERNETES VERSION & CLUSTER IDENTITY", display.stream.getvalue()
        )
        display.progress.start()
        for _ in range(4):
            display._paint()
        self.assertLessEqual(display._painted, display.height - 2)

    def test_the_slow_cadence_still_repaints_on_a_state_change(self) -> None:
        """A long check must not freeze the checks that follow it.

        The audit reaches every state change through feed(), never through
        update(). Once a check passes slow_after_s the painter sleeps for 30
        seconds, so without a repaint here the display kept showing the finished
        check as running while the next checks ran inside that sleep. A live run
        hit the trigger: the srun worker check held one check for 4m52s, and the
        standalone run then finished 63 checks in 15 seconds.
        """
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
        # A fresh check is running, so the cadence returns to fast.
        self.assertEqual(display._next_interval, display.interval)
        # A line that changes nothing must not repaint.
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
        display.close(ok=True)
        text = display.stream.getvalue()
        self.assertIn(f"\x1b[{painted}A\x1b[J", text)
        self.assertIn("\x1b[?25h", text)
        self.assertIn("complete", progress.strip_ansi(text))


class EndToEndTests(unittest.TestCase):
    """Run a real collector-shaped script through the real display."""

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
        _code, output, _shown, _tracker = self.run_script()
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

    def test_a_non_utf8_byte_does_not_kill_the_collector(self) -> None:
        # The collector prints dmesg excerpts and raw vendor tool output. Strict
        # decoding raised inside the read loop and killed a healthy collector.
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

    def test_the_collector_output_is_returned_whole(self) -> None:
        _code, output, _shown, _tracker = self.run_script()
        # audit.out is the committed evidence for a run, so the display must
        # not consume any part of the stream.
        self.assertIn("Cluster slug: fake", output)
        self.assertIn("some detail", output)
        self.assertIn("─── Node Summary ───", output)


class DurationTests(unittest.TestCase):
    def test_durations_read_as_operators_expect(self) -> None:
        self.assertEqual(progress.format_duration(0), "0s")
        self.assertEqual(progress.format_duration(9.7), "9s")
        self.assertEqual(progress.format_duration(75), "1m 15s")
        self.assertEqual(progress.format_duration(3600 + 240), "1h 04m")
        self.assertEqual(progress.format_duration(None), "")


class DisplaySelectionTests(unittest.TestCase):
    def test_a_pipe_gets_the_plain_display(self) -> None:
        tracker = progress.AuditProgress([], title="audit")
        self.assertIsInstance(
            progress.make_display(tracker, stream=io.StringIO()),
            progress.PlainDisplay,
        )

    def test_a_terminal_gets_the_live_display(self) -> None:
        tracker = progress.AuditProgress([], title="audit")
        with mock.patch.dict(os.environ, {"COLUMNS": "100", "LINES": "24"}):
            display = progress.make_display(tracker, stream=FakeTty())
        self.assertIsInstance(display, progress.LiveDisplay)
        self.assertTrue(display.renderer.theme.unicode)

    def test_a_latin1_terminal_loses_the_box_drawing_glyphs(self) -> None:
        class Latin1Tty(FakeTty):
            encoding = "iso-8859-1"

        tracker = progress.AuditProgress([], title="audit")
        with mock.patch.dict(os.environ, {"COLUMNS": "100", "LINES": "24"}):
            display = progress.make_display(tracker, stream=Latin1Tty())
        self.assertFalse(display.renderer.theme.unicode)


if __name__ == "__main__":
    unittest.main()
