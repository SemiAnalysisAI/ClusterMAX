"""Live progress display for the cluster audit collectors.

The audit collectors are long shell scripts that already announce their work:
`print_header` for each group of checks and `print_section` for each check
inside a group. Nothing in the harness read those announcements, so
`cmax audit security` printed one line and then looked hung for minutes while
the collector checked workers over srun.

This module turns that output stream into a plan-backed progress display: a
percentage bar with a real denominator, a checklist of the groups that are
finished, the check that is running right now with a live timer, and the checks
still to come.

The plan is read from the collector script itself, by scanning its
`print_header` / `print_section` call sites in source order. No check list is
duplicated here, so a collector that gains a check gains a plan step with no
edit to this file. Labels that interpolate a shell variable become prefix
patterns, and the observed label replaces the pattern once the step starts.

Only the display changes. The collector's own output still reaches
`audit.out` unchanged, which stays the committed evidence for the run.
"""

from __future__ import annotations

import os
import re
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence, TextIO

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.data_structures import Point
from prompt_toolkit.formatted_text import ANSI, to_formatted_text
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.input.defaults import create_input
from prompt_toolkit.input.vt100_parser import Vt100Parser
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl, UIContent, UIControl
from prompt_toolkit.output.defaults import create_output

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - native Windows uses prompt-toolkit input.
    termios = None
    tty = None


TODO = "todo"
RUNNING = "running"
DONE = "done"
SKIPPED = "skipped"
FAILED = "failed"

# Synthetic first group. The collector needs a few seconds to resolve its plan
# and start, and a display with nothing running looks as stalled as no display
# at all.
STARTUP_GROUP = "STARTUP"
FINALIZE_GROUP = "FINALIZE"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# print_header / print_section call sites in a collector, in source order. Both
# helpers are called at the start of a line, sometimes indented inside a
# conditional branch, and a label that itself contains a double quote is passed
# in single quotes.
_CALL_SITE = re.compile(
    r"""^[ \t]*print_(header|section)[ \t]+(?:"([^"]*)"|'([^']*)')""", re.M
)

# The same two helpers as they appear in the collector's output: print_header
# frames its title between two rules of box characters, print_section wraps its
# label in horizontal rules on a single line.
_RULE_OUT = re.compile(r"^[═=]{3,}$")
_SECTION_OUT = re.compile(r"^─{3,}\s*(.*?)\s*─{3,}$")
_CHECK_OUT = re.compile(r"^Running audit check:\s+(.+)$")

# A shell interpolation inside a label, which becomes a wildcard in the pattern.
_INTERP = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")

# Every glyph the display can put on a line, with the ascii stand-in a
# terminal that cannot encode it gets instead.
_ASCII_FALLBACKS = {
    "…": "...",
    "→": "->",
    "·": "-",
    "─": "-",
    "═": "=",
    "█": "#",
    "░": ".",
    "✓": "+",
    "✗": "x",
    "⊘": "-",
    "○": ".",
}

_SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_ASCII = "|/-\\"

# Operator escape hatch. `-v` turns the display off for the audit commands, but
# the sweep commands have no `-v`, and a terminal that mishandles the cursor
# codes needs a way out of the region on any command.
PROGRESS_ENV = "CLUSTERMAX_PROGRESS"

_UNLABELED_OUTPUT_OWNERS = {
    "CAMPAIGN",
    "Render audit check summary",
}

_STATUS_WORDS = (
    (re.compile(r"(?<!not-)\b(pass|ok)\b", re.I), "32"),
    (re.compile(r"\b(warning|warn|skip|skipped)\b", re.I), "33"),
    (re.compile(r"\b(fail|failed|failure|missing)\b", re.I), "31"),
)

_CVE_LINK = re.compile(r"\b(CVE-\d{4}-\d+)\b", re.I)
_GHSA_LINK = re.compile(r"\b(GHSA-[0-9a-z-]+)\b", re.I)
_NVIDIA_ADVISORY_LINK = re.compile(r"\bNVIDIA advisory (\d+)\b")
_DOCKER_NOTES_LINK = re.compile(r"\bDocker Engine ([0-9A-Za-z._-]+) release notes\b")
_UBUNTU_NOTICES_LINK = re.compile(r"\bUbuntu security notices\b")
_PROMPT_TOOLKIT_LINK_CLOSE = "\x01\x1b]8;;\x1b\\\x02"


def progress_enabled() -> bool:
    return (os.environ.get(PROGRESS_ENV) or "").strip().lower() not in {
        "0",
        "no",
        "off",
        "false",
    }


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def color_status_text(text: str, *, color: bool = True) -> str:
    """Color human status words without changing their fixed-width spelling."""
    if not color or not text:
        return text
    if _ANSI.search(text):
        return text
    rendered = text
    for pattern, code in _STATUS_WORDS:
        rendered = pattern.sub(lambda match: f"\x1b[{code}m{match.group(0)}\x1b[0m", rendered)
    # Findings use a padded seven-character category. Color only the text so
    # `[CONFIG ]` keeps the alignment operators rely on in screenshots.
    rendered = re.sub(
        r"\[(CONFIG)(\s*)\]",
        lambda match: f"[\x1b[33m{match.group(1)}\x1b[0m{match.group(2)}]",
        rendered,
    )
    rendered = re.sub(
        r"\[(MISSING|VERSION)(\s*)\]",
        lambda match: f"[\x1b[31m{match.group(1)}\x1b[0m{match.group(2)}]",
        rendered,
    )
    return rendered


def _terminal_hyperlink(
    text: str, url: str, *, prompt_toolkit: bool = False
) -> str:
    opening = f"\x1b]8;;{url}\x1b\\"
    closing = "\x1b]8;;\x1b\\"
    if prompt_toolkit:
        # ANSI() sends text between SOH/STX as a zero-width terminal escape.
        # This preserves OSC 8 through prompt-toolkit's formatted-text parser.
        opening = f"\x01{opening}\x02"
        closing = f"\x01{closing}\x02"
    return f"{opening}\x1b[4m{text}\x1b[24m{closing}"


def linkify_report_text(text: str, *, prompt_toolkit: bool = False) -> str:
    """Add hidden, underlined OSC 8 targets to report identifiers."""
    if not text:
        return _PROMPT_TOOLKIT_LINK_CLOSE + " " if prompt_toolkit else text
    if "\x1b]8;;" in text:
        if prompt_toolkit:
            return (
                _PROMPT_TOOLKIT_LINK_CLOSE
                + text
                + _PROMPT_TOOLKIT_LINK_CLOSE
                + " "
            )
        return text

    rendered = _CVE_LINK.sub(
        lambda match: _terminal_hyperlink(
            match.group(1).upper(),
            f"https://nvd.nist.gov/vuln/detail/{match.group(1).upper()}",
            prompt_toolkit=prompt_toolkit,
        ),
        text,
    )
    rendered = _GHSA_LINK.sub(
        lambda match: _terminal_hyperlink(
            match.group(1),
            f"https://github.com/advisories/{match.group(1)}",
            prompt_toolkit=prompt_toolkit,
        ),
        rendered,
    )
    rendered = _NVIDIA_ADVISORY_LINK.sub(
        lambda match: _terminal_hyperlink(
            match.group(0),
            f"https://nvidia.custhelp.com/app/answers/detail/a_id/{match.group(1)}/",
            prompt_toolkit=prompt_toolkit,
        ),
        rendered,
    )
    rendered = _DOCKER_NOTES_LINK.sub(
        lambda match: _terminal_hyperlink(
            match.group(0),
            f"https://docs.docker.com/engine/release-notes/{match.group(1)}/",
            prompt_toolkit=prompt_toolkit,
        ),
        rendered,
    )
    rendered = _UBUNTU_NOTICES_LINK.sub(
        lambda match: _terminal_hyperlink(
            match.group(0),
            "https://ubuntu.com/security/notices",
            prompt_toolkit=prompt_toolkit,
        ),
        rendered,
    )
    if prompt_toolkit:
        # prompt-toolkit can omit a zero-width escape at the end of a row
        # because no terminal cell owns it. Put the close before a real space,
        # and close again at column zero so a malformed prior row cannot leak.
        return (
            _PROMPT_TOOLKIT_LINK_CLOSE
            + rendered
            + _PROMPT_TOOLKIT_LINK_CLOSE
            + " "
        )
    return rendered


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m {total % 60:02d}s"
    return f"{total // 3600}h {(total % 3600) // 60:02d}m"


@dataclass
class Step:
    """One check the collector announces, and how to recognize it.

    A sweep reuses this for one test. `ceiling` is the declared `timeout_s` of
    that test, which gives the running line a real upper bound instead of an
    estimate.
    """

    group: str
    label: str
    pattern: re.Pattern[str] | None = None
    state: str = TODO
    started: float | None = None
    ended: float | None = None
    observed: str = ""
    detail: str = ""
    ceiling: float | None = None

    @property
    def title(self) -> str:
        return self.observed or self.label

    def duration(self, now: float) -> float | None:
        if self.started is None:
            return None
        return (self.ended if self.ended is not None else now) - self.started


def _label_pattern(label: str) -> re.Pattern[str] | None:
    """Compile an output matcher for a `print_section` label from source.

    A label with no interpolation matches exactly. `${GPU_PARTITION}` and
    friends become wildcards, because the collector prints the resolved value.
    A label that is nothing but interpolation matches anything, which would
    swallow the next unrelated check, so it gets no pattern at all.
    """
    literal_parts: list[str] = []
    pattern_parts: list[str] = []
    last = 0
    for match in _INTERP.finditer(label):
        chunk = label[last : match.start()]
        literal_parts.append(chunk)
        pattern_parts.append(re.escape(chunk))
        pattern_parts.append(".*")
        last = match.end()
    tail = label[last:]
    literal_parts.append(tail)
    pattern_parts.append(re.escape(tail))
    if not "".join(literal_parts).strip():
        return None
    return re.compile("^" + "".join(pattern_parts) + "$")


def _display_label(label: str) -> str:
    """The label to show before the collector reveals the resolved value."""
    return _INTERP.sub("…", label).replace("(…)", "…").strip()


def collector_steps(script: Path | str) -> list[Step]:
    """Read the ordered check plan out of a collector script's source."""
    script = Path(script)
    text = script.read_text(errors="replace")
    # Standalone and Kubernetes use thin wrappers that select the harness and
    # exec the shared focused security collector. Follow that local target for
    # planning so their progress bars have the same real phases as Slurm.
    wrapper = re.search(
        r'exec\s+bash\s+"\$WORKLOAD_DIR/([^"/]+\.sh)"', text
    )
    if wrapper is not None:
        target = script.parent / wrapper.group(1)
        if target.is_file() and target != script:
            text = target.read_text(errors="replace")
    steps: list[Step] = []
    group = ""
    for match in _CALL_SITE.finditer(text):
        kind = match.group(1)
        label = match.group(2) if match.group(2) is not None else match.group(3)
        if kind == "header":
            group = label
            continue
        steps.append(
            Step(group=group, label=_display_label(label), pattern=_label_pattern(label))
        )
    return steps


def scoped_collector(script_dir: Path, harness: str, scope: str) -> Path:
    """Select the collector that the runner uses for one audit profile."""
    collector = Path(script_dir) / f"cluster-audit-{harness}.sh"
    if scope == "full":
        return collector
    candidate = collector.with_name(f"{collector.stem}-{scope}.sh")
    return candidate if candidate.is_file() else collector


def audit_plan(script_dir: Path, harness: str, scope: str = "full") -> list[Step]:
    """The full expected step list for one `run.sh` invocation.

    The middle is the harness collector's own plan; the ends are the phases
    `run.sh` runs around it. A missing collector yields a plan with only those
    ends, and the display then counts checks as they arrive instead of showing
    a percentage.

    The plan is an expectation, not a contract. A collector's conditional
    branches put checks in it that this cluster may never reach, and the checks
    printed from `audit-common.sh` are not in it at all, because neither file's
    source order says where in the run the shared helper is called. The display
    resolves both as it goes: an unreached check is marked skipped once a later
    one starts, and a check the plan missed is inserted into the group that is
    running. The denominator therefore moves by a few over a run.
    """
    plan = [Step(group=STARTUP_GROUP, label="Resolve audit plan and collector")]
    collector = scoped_collector(Path(script_dir), harness, scope)
    if collector.is_file():
        plan.extend(collector_steps(collector))
    plan.append(
        Step(
            group=FINALIZE_GROUP,
            label="Audit checks",
            pattern=_label_pattern("Audit checks"),
        )
    )
    plan.append(
        Step(
            group=FINALIZE_GROUP,
            label="Writing audit values",
            pattern=_label_pattern("Writing audit values"),
        )
    )
    if scope == "full":
        plan.append(
            Step(
                group=FINALIZE_GROUP,
                label="Audit findings",
                pattern=_label_pattern("Audit findings"),
            )
        )
    return plan


class AuditProgress:
    """Collector output in, step states out.

    Every state change comes from a line the collector printed, so the display
    can never claim progress the collector did not report.
    """

    def __init__(
        self,
        steps: Sequence[Step],
        *,
        title: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.steps: list[Step] = list(steps)
        self.title = title
        self._clock = clock
        self.started: float | None = None
        self.finished: float | None = None
        self.ok = True
        self.cursor = 0
        self.current_group = self.steps[0].group if self.steps else ""
        # 0 idle, 1 saw the opening rule of a header, 2 consumed its title.
        self._header_state = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self.started = self._clock()
        if self.steps:
            self._begin(0)

    def finish(self, ok: bool = True) -> None:
        self.ok = ok
        now = self._clock()
        self.finished = now
        for step in self.steps:
            if step.state == RUNNING:
                step.state = DONE if ok else FAILED
                step.ended = now
            elif step.state == TODO and ok:
                step.state = SKIPPED
        self.cursor = len(self.steps)

    # -- feeding ----------------------------------------------------------

    def feed(self, raw_line: str) -> bool:
        """Consume one output line. True when it moved the display."""
        line = strip_ansi(raw_line).strip()
        if _RULE_OUT.match(line):
            # The closing rule of a header block, or the opening rule of the
            # next one. Distinguishing them keeps the line after a closing rule
            # from being mistaken for a title.
            self._header_state = 0 if self._header_state == 2 else 1
            return False
        section = _SECTION_OUT.match(line)
        if section:
            self._header_state = 0
            self._on_section(section.group(1))
            return True
        check = _CHECK_OUT.match(line)
        if check:
            self._on_detail(check.group(1), sticky=False)
            return True
        if self._header_state == 1 and line:
            self._header_state = 2
            self._on_header(line)
            return True
        if line:
            # The collector's first line inside a check says what it is about to
            # do ("Running single srun job to gather GPU, IB, and software
            # facts..."), which is the whole answer for the check that holds the
            # run longest. Later lines are results, and swapping the detail on
            # every one of them would only flicker.
            self._on_detail(line, sticky=True)
        return False

    def _on_detail(self, detail: str, sticky: bool) -> None:
        for step in self.steps:
            if step.state == RUNNING:
                if sticky and step.detail:
                    return
                step.detail = detail.strip()
                return

    def _on_header(self, title: str) -> None:
        for index in range(self.cursor, len(self.steps)):
            if self.steps[index].group == title:
                self._advance_to(index)
                self.current_group = title
                return
        # A header the plan does not know about: attach whatever checks follow
        # to it rather than to the group that happened to be current.
        self.current_group = title

    def _on_section(self, label: str) -> None:
        index = self._match_forward(label)
        if index is None:
            index = self._insert_unplanned(label)
        self._advance_to(index)
        self._begin(index, observed=label)

    def _match_forward(self, label: str) -> int | None:
        for index in range(self.cursor, len(self.steps)):
            pattern = self.steps[index].pattern
            if pattern is not None and pattern.match(label):
                return index
        return None

    def _insert_unplanned(self, label: str) -> int:
        """Place a check the plan missed directly after the running check.

        Inserting at the end of the group instead would mark every remaining
        planned check in that group as skipped, and the forward-only match could
        never find them again when they print. Group contiguity holds either way,
        because the running check belongs to the current group.
        """
        index = self.cursor
        if index < len(self.steps) and self.steps[index].state == RUNNING:
            index += 1
        self.steps.insert(index, Step(group=self.current_group, label=label))
        return index

    def _advance_to(self, index: int) -> None:
        now = self._clock()
        for step in self.steps[self.cursor : index]:
            if step.state == RUNNING:
                step.state = DONE
                step.ended = now
            elif step.state == TODO:
                step.state = SKIPPED
        self.cursor = index

    def _begin(self, index: int, observed: str = "") -> None:
        step = self.steps[index]
        step.state = RUNNING
        step.started = self._clock()
        step.observed = observed
        self.current_group = step.group

    # -- reporting --------------------------------------------------------

    @property
    def total(self) -> int:
        return len(self.steps)

    @property
    def completed(self) -> int:
        return sum(1 for step in self.steps if step.state in {DONE, SKIPPED, FAILED})

    @property
    def fraction(self) -> float:
        if not self.steps:
            return 0.0
        return self.completed / len(self.steps)

    def elapsed(self, now: float | None = None) -> float:
        if self.started is None:
            return 0.0
        end = self.finished if self.finished is not None else (now or self._clock())
        return end - self.started

    def groups(self) -> list[tuple[str, list[Step]]]:
        ordered: list[tuple[str, list[Step]]] = []
        by_title: dict[str, list[Step]] = {}
        for step in self.steps:
            if step.group not in by_title:
                by_title[step.group] = []
                ordered.append((step.group, by_title[step.group]))
            by_title[step.group].append(step)
        return ordered

    def running_step(self) -> Step | None:
        for step in self.steps:
            if step.state == RUNNING:
                return step
        return None

    def running_steps(self) -> list[Step]:
        """Every step running now. A parallel sweep runs more than one."""
        return [step for step in self.steps if step.state == RUNNING]


@dataclass
class Theme:
    """Colors and glyphs, resolved once from the terminal's capabilities."""

    color: bool = True
    unicode: bool = True

    def paint(self, text: str, *codes: str) -> str:
        if not text or not self.color or not codes:
            return text
        return "\x1b[" + ";".join(codes) + "m" + text + "\x1b[0m"

    @property
    def spinner(self) -> str:
        return _SPINNER_UNICODE if self.unicode else _SPINNER_ASCII

    def spin(self, tick: int) -> str:
        frames = self.spinner
        return frames[tick % len(frames)]

    def bar(self, fraction: float, width: int) -> str:
        filled_char, empty_char = ("█", "░") if self.unicode else ("#", ".")
        filled = int(round(max(0.0, min(1.0, fraction)) * width))
        return self.paint(filled_char * filled, "32") + self.paint(
            empty_char * (width - filled), "90"
        )

    @property
    def ellipsis(self) -> str:
        return "…" if self.unicode else "..."

    @property
    def arrow(self) -> str:
        return "→" if self.unicode else "->"

    @property
    def middot(self) -> str:
        return "·" if self.unicode else "-"

    def encodable(self, text: str) -> str:
        """Text this terminal can encode.

        A latin1 or ascii terminal cannot encode the display's own glyphs, and
        a check label carries whatever the collector wrote. One unencodable
        code point raises UnicodeEncodeError on the write and takes the whole
        display down, so the last step before a line is measured is to bring it
        into the terminal's range.
        """
        if self.unicode:
            return text
        for source, fallback in _ASCII_FALLBACKS.items():
            text = text.replace(source, fallback)
        return text.encode("ascii", "replace").decode("ascii")

    def glyph(self, state: str, tick: int) -> str:
        if state == DONE:
            return self.paint("✓" if self.unicode else "+", "32")
        if state == RUNNING:
            return self.paint(self.spin(tick), "36", "1")
        if state == SKIPPED:
            return self.paint("⊘" if self.unicode else "-", "33")
        if state == FAILED:
            return self.paint("✗" if self.unicode else "x", "31", "1")
        return self.paint("○" if self.unicode else ".", "90")


def _group_state(steps: Sequence[Step], active: bool) -> str:
    states = {step.state for step in steps}
    if FAILED in states:
        return FAILED
    if RUNNING in states or active:
        return RUNNING
    if not states or states <= {SKIPPED}:
        return SKIPPED if states else TODO
    if states <= {DONE, SKIPPED}:
        return DONE
    if states == {TODO}:
        return TODO
    return RUNNING


def _group_duration(steps: Sequence[Step], now: float) -> float | None:
    timed = [step for step in steps if step.started is not None]
    if not timed:
        return None
    end = max((step.ended or now) for step in timed)
    return end - min(step.started for step in timed)  # type: ignore[type-var]


def _clip(text: str, width: int, mark: str = "…") -> str:
    """Trim to a printable width, ignoring the escape codes in the text."""
    if width <= 0:
        return ""
    plain = strip_ansi(text)
    if len(plain) <= width:
        return text
    # Colored text is built from short, known pieces; clip the plain form and
    # drop the color rather than cutting an escape sequence in half.
    return plain[: max(0, width - len(mark))] + mark


def _pad(text: str, width: int) -> str:
    plain = strip_ansi(text)
    return text + " " * max(0, width - len(plain))


def _fit_text(text: str, width: int, mark: str = "…") -> str:
    """Shorten a label so the duration column stays where the eye expects it."""
    if width <= len(mark) or len(text) <= width:
        return text
    return text[: width - len(mark)] + mark


class ProgressRenderer:
    """Turns an `AuditProgress` into the lines shown on screen."""

    def __init__(self, theme: Theme, *, width: int = 80) -> None:
        self.theme = theme
        self.width = max(40, width)

    def live(self, progress: AuditProgress, now: float, tick: int, height: int) -> list[str]:
        head = self._head(progress, now)
        groups = progress.groups()
        # Every group holding a running step is expanded. A parallel sweep runs
        # tests from more than one group at the same time, and an operator who
        # can see only one of them cannot tell what the allocation is doing.
        expanded = {
            title
            for title, steps in groups
            if any(step.state == RUNNING for step in steps)
        }
        if not expanded and progress.current_group:
            expanded = {progress.current_group}
        blocks: list[dict] = []
        seen_expanded = False
        for title, steps in groups:
            state = _group_state(steps, title in expanded)
            group_line = self._group_line(title, steps, state, now, tick)
            if title in expanded:
                seen_expanded = True
                blocks.append(
                    {
                        "kind": "current",
                        "lines": [group_line, *self._sub_lines(steps, now, tick)],
                    }
                )
            else:
                blocks.append(
                    {
                        "kind": "todo" if seen_expanded else "done",
                        "lines": [group_line],
                    }
                )
        lines = self._fit(head, blocks, max(8, height - 2), tick)
        return self._finish(lines)

    def _fit(
        self,
        head: list[str],
        blocks: list[dict],
        budget: int,
        tick: int,
    ) -> list[str]:
        """Fit the region into `budget` lines, least-valuable-first.

        Each step strictly reduces the line count, so a terminal too short for
        the full region converges instead of trimming forever. The region must
        stay inside the window: the repaint moves the cursor up by the number of
        lines it wrote last time, and a region taller than the terminal scrolls
        that anchor off the screen.

        Blocks keep their order while they shrink, so a group never appears to
        move when a parallel sweep expands a second one.
        """
        theme = self.theme

        def total() -> int:
            return len(head) + sum(len(block["lines"]) for block in blocks)

        pending = [
            index
            for index, block in enumerate(blocks)
            if block["kind"] == "todo" and block["lines"]
        ]
        hidden = 0
        # Dropping the first pending group adds the summary line that replaces
        # it, so the first drop must beat budget - 1.
        while pending and total() + (1 if hidden == 0 else 0) > budget:
            index = pending.pop()
            hidden += len(blocks[index]["lines"])
            blocks[index]["lines"] = []
        if hidden:
            # One line always survives here: an operator who cannot see how much
            # is left has lost the only thing the display is for.
            blocks.append(
                {
                    "kind": "note",
                    "lines": [
                        "  "
                        + theme.paint(
                            f"{theme.ellipsis} {hidden} more group(s) to run", "90"
                        )
                    ],
                }
            )
        finished = [
            index
            for index, block in enumerate(blocks)
            if block["kind"] == "done" and block["lines"]
        ]
        if total() > budget and len(finished) > 1:
            for index in finished[1:]:
                blocks[index]["lines"] = []
            blocks[finished[0]]["lines"] = [
                "  "
                + theme.glyph(DONE, tick)
                + " "
                + theme.paint(f"{len(finished)} group(s) complete", "90")
            ]
        for block in blocks:
            if block["kind"] != "current":
                continue
            while total() > budget and len(block["lines"]) > 2:
                # Keep the group line and the last running line; the finished
                # steps above it are the least useful lines on the screen.
                block["lines"].pop(1)
        lines = head + [line for block in blocks for line in block["lines"]]
        return lines[:budget]

    def final(self, progress: AuditProgress, now: float) -> list[str]:
        theme = self.theme
        state_word = "complete" if progress.ok else "failed"
        color = "32" if progress.ok else "31"
        counts = f"{progress.completed}/{progress.total} checks"
        lines = [
            "  "
            + theme.paint(f"{progress.title} {state_word}", color, "1")
            + theme.paint(
                f"  {self.theme.middot}  {format_duration(progress.elapsed(now))}"
                f"  {self.theme.middot}  {counts}",
                "90",
            ),
            "",
        ]
        for title, steps in progress.groups():
            state = _group_state(steps, False)
            lines.append(self._group_line(title, steps, state, now, 0, final=True))
        lines.append("")
        return self._finish(lines)

    def _finish(self, lines: list[str]) -> list[str]:
        """Bring each line into the terminal's range, then into its width.

        A collector's check label reaches the display unchanged, so the
        encoding pass runs on the assembled line rather than on the display's
        own glyphs alone. It runs before the clip, because the clip measures
        the characters that are about to be written.
        """
        theme = self.theme
        return [
            _clip(theme.encodable(line), self.width, theme.ellipsis)
            for line in lines
        ]

    # -- pieces -----------------------------------------------------------

    def _head(self, progress: AuditProgress, now: float) -> list[str]:
        theme = self.theme
        elapsed = format_duration(progress.elapsed(now))
        bar_width = max(16, min(40, self.width - 34))
        percent = f"{progress.fraction * 100:3.0f}%"
        counts = f"{progress.completed}/{progress.total}"
        head = (
            "  "
            + theme.bar(progress.fraction, bar_width)
            + " "
            + theme.paint(percent, "1")
            + theme.paint(f"  {counts} checks  ·  {elapsed}", "90")
        )
        return [
            "  " + theme.paint(progress.title, "1"),
            head,
            "",
        ]

    def _group_line(
        self,
        title: str,
        steps: Sequence[Step],
        state: str,
        now: float,
        tick: int,
        final: bool = False,
    ) -> str:
        theme = self.theme
        passed = sum(1 for step in steps if step.state == DONE)
        skipped = sum(1 for step in steps if step.state == SKIPPED)
        failed = sum(1 for step in steps if step.state == FAILED)
        not_run = sum(1 for step in steps if step.state == TODO)
        total = len(steps)
        label_style = ("90",) if state in {TODO, SKIPPED} else ()
        if state == RUNNING and not final:
            label_style = ("1",)
        elif state == FAILED:
            label_style = ("31", "1")
        if state == SKIPPED:
            tail = theme.paint("skipped", "33")
        elif state == TODO:
            tail = theme.paint(f"0/{total}" if total else "", "90")
        elif state == FAILED:
            parts = [theme.paint(f"{passed}/{total} passed", "90")]
            if skipped:
                parts.append(theme.paint(f"{skipped} skipped", "33"))
            parts.append(theme.paint(f"{failed} failed", "31", "1"))
            if not_run:
                parts.append(theme.paint(f"{not_run} not run", "90"))
            tail = ", ".join(parts)
        elif state == DONE and skipped:
            tail = (
                theme.paint(f"{passed}/{total} passed, ", "90")
                + theme.paint(f"{skipped} skipped", "33")
            )
        else:
            duration = format_duration(_group_duration(steps, now))
            tail = theme.paint(f"{passed}/{total}  {duration}".rstrip(), "90")
        column = max(
            24,
            min(self.width - 22, self.width - len(strip_ansi(tail))),
        )
        label = theme.paint(_fit_text(title, column - 5, theme.ellipsis), *label_style)
        return _pad("  " + theme.glyph(state, tick) + " " + label, column) + tail

    def _sub_lines(self, steps: Sequence[Step], now: float, tick: int) -> list[str]:
        """Every running step in a group, with the two finished before them."""
        theme = self.theme
        running = [index for index, step in enumerate(steps) if step.state == RUNNING]
        first_running = running[0] if running else None
        # Only steps that actually ran are worth a line. A group whose plan holds
        # conditional checks would otherwise fill the window with the branches
        # this cluster never took.
        finished = [
            step
            for step in steps[:first_running]
            if step.state in {DONE, FAILED}
        ]
        visible = finished[-2:] + [steps[index] for index in running]
        lines: list[str] = []
        for step in visible:
            duration = (
                format_duration(step.duration(now)) if step.state == RUNNING else ""
            )
            if step.state == RUNNING and step.ceiling:
                duration = f"{duration} / {format_duration(step.ceiling)}"
            title = step.title
            if step.state == RUNNING and step.detail:
                title = f"{title} {theme.arrow} {step.detail}"
            style = ("36",) if step.state == RUNNING else ("90",)
            column = max(24, self.width - 22)
            title = _fit_text(title, column - 9, theme.ellipsis)
            body = (
                "      " + theme.glyph(step.state, tick) + " " + theme.paint(title, *style)
            )
            lines.append(_pad(body, column) + theme.paint(duration, "90"))
        return lines


class _TimelineControl(UIControl):
    """Expose preformatted log rows through an independently moved viewport."""

    def __init__(self, display: "LiveDisplay") -> None:
        self.display = display
        self._cursor_line = max(0, len(display._timeline) - 1)
        self._follow_tail = True
        self._viewport_top = 0
        self._viewport_height = 1
        self._render_lines = list(display._timeline_rendered)

    def is_focusable(self) -> bool:
        return True

    def create_content(self, width: int, height: int) -> UIContent:
        # Output collection and input handling run on different threads. Never
        # wait for the producer's lock here: retain the last complete snapshot
        # if it is busy, and keep that snapshot stable while the user scrolls.
        if not self.display._scroll_input_active() and self.display._lock.acquire(
            blocking=False
        ):
            try:
                dirty_from = self.display._timeline_dirty_from
                if dirty_from is not None:
                    # The producer can append rows while scrolling, then mark
                    # a later transient row dirty. Rebuild from the first row
                    # missing from this frozen snapshot when that is earlier,
                    # or the appended rows before dirty_from are skipped.
                    sync_from = min(dirty_from, len(self._render_lines))
                    del self._render_lines[sync_from:]
                    self._render_lines.extend(
                        self.display._timeline_rendered[sync_from:]
                    )
                    self.display._timeline_dirty_from = None
                elif len(self._render_lines) < len(
                    self.display._timeline_rendered
                ):
                    start = len(self._render_lines)
                    self._render_lines.extend(
                        self.display._timeline_rendered[start:]
                    )
                elif len(self._render_lines) > len(self.display._timeline_rendered):
                    self._render_lines[:] = self.display._timeline_rendered
            finally:
                self.display._lock.release()
        line_count = len(self._render_lines)
        self._viewport_height = max(1, height)
        self._sync_viewport(line_count)

        def get_line(index: int):
            if not line_count:
                return to_formatted_text(ANSI("(waiting for output)"))
            return self._render_lines[index]

        return UIContent(
            get_line=get_line,
            line_count=max(1, line_count),
            cursor_position=Point(x=0, y=self._cursor_line),
            show_cursor=False,
        )

    def move_cursor_up(self) -> None:
        self.scroll_viewport(-1)

    def move_cursor_down(self) -> None:
        self.scroll_viewport(1)

    def jump_to_start(self) -> None:
        self._follow_tail = False
        self._viewport_top = 0
        self._sync_viewport(len(self._render_lines))

    def jump_to_end(self) -> None:
        self._follow_tail = True
        self._sync_viewport(len(self._render_lines))

    @property
    def viewport_top(self) -> int:
        return self._viewport_top

    def scroll_viewport(self, delta: int) -> None:
        """Apply every input delta to stable state, independent of render timing."""
        line_count = len(self._render_lines)
        max_top = max(0, line_count - self._viewport_height)
        if self._follow_tail:
            self._viewport_top = max_top
        self._viewport_top = min(
            max_top,
            max(0, self._viewport_top + delta),
        )
        if delta < 0:
            self._follow_tail = False
        elif self._viewport_top >= max_top:
            self._follow_tail = True
        self._sync_viewport(line_count)

    def _sync_viewport(self, line_count: int) -> None:
        max_top = max(0, line_count - self._viewport_height)
        if self._follow_tail:
            self._viewport_top = max_top
        else:
            self._viewport_top = min(self._viewport_top, max_top)
        last_line = max(0, line_count - 1)
        viewport_bottom = min(
            last_line,
            self._viewport_top + self._viewport_height - 1,
        )
        if self._follow_tail:
            self._cursor_line = last_line
        else:
            self._cursor_line = min(
                viewport_bottom,
                max(self._viewport_top, self._cursor_line),
            )


def _vt100_wheel_action(data: str) -> str | None:
    """Decode wheel direction without prompt-toolkit's screen-coordinate map."""
    try:
        if data.startswith("\x1b[<"):
            code = int(data[3:].split(";", 1)[0])
        elif data.startswith("\x1b[M") and len(data) >= 4:
            code = ord(data[3]) - 32
        elif data.startswith("\x1b["):
            code = int(data[2:].split(";", 1)[0]) - 32
        else:
            return None
    except (TypeError, ValueError):
        return None
    if not code & 64:
        return None
    return "wheel_down" if code & 1 else "wheel_up"


class LiveDisplay:
    """Repaints the progress region on a timer while the collector runs.

    The timer is the point. An operator watching a check that takes four
    minutes needs the seconds to keep moving, and output-driven repaints stop
    exactly when the collector goes quiet, which is when the run looks hung.
    """

    interval = 0.12
    input_interval = 1 / 30
    log_refresh_interval = 0.25
    wheel_lines = 3
    # A burn-in runs for eight hours. Repainting it eight times a second for
    # that long writes megabytes to the terminal and shows nothing new, so a
    # step that passes slow_after_s drops the repaint to slow_interval. This is
    # the cadence bench used for its heartbeat line before this display existed.
    # A state change repaints at once, through update() for a sweep and through
    # feed() for the audit, so the slow cadence only ever delays the clock.
    slow_interval = 30.0
    slow_after_s = 120.0

    def __init__(
        self,
        progress: AuditProgress,
        *,
        stream: TextIO | None = None,
        theme: Theme | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.progress = progress
        self.stream = stream if stream is not None else sys.stdout
        size = shutil.get_terminal_size((100, 30))
        resolved_theme = theme or Theme()
        if "NO_COLOR" in os.environ:
            resolved_theme = Theme(color=False, unicode=resolved_theme.unicode)
        self.renderer = ProgressRenderer(resolved_theme, width=size.columns - 1)
        self.height = size.lines
        self._clock = clock
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._painted = 0
        self._tick = 0
        self._next_interval = self.interval
        self._started = False
        self._captures: dict[str, list[str]] = {}
        self._capture_order: list[str] = []
        self._timeline: list[tuple[str, str]] = []
        self._timeline_rendered: list[list] = []
        self._timeline_dirty_from: int | None = None
        self._tail_transient_owner: str | None = None
        self._timeline_owner = ""
        self._active_owner = ""
        self._tui_app: Application[None] | None = None
        self._tui_log_window: Window | None = None
        self._timeline_control: _TimelineControl | None = None
        self._tui_ready = threading.Event()
        self._tui_error: BaseException | None = None
        self._pending_wheel_delta = 0
        self._wheel_flush_scheduled = False
        self._wheel_lock = threading.Lock()
        self._last_scroll_input_at = 0.0
        self._tui_progress_cache = ANSI("")
        self._tui_header_cache = ANSI("")
        self._tui_pipe_context = None
        self._tui_input_thread: threading.Thread | None = None
        self._tui_input_stop = threading.Event()
        self._tui_stdin_attrs = None
        terminal = False
        try:
            stream_fd = self.stream.fileno()
            input_fd = sys.stdin.fileno()
            terminal = os.isatty(stream_fd) and os.isatty(input_fd)
        except (AttributeError, OSError, ValueError):
            pass
        self._dedicated_tui_input = (
            terminal
            and os.name == "posix"
            and termios is not None
            and tty is not None
        )
        self._tui = terminal
        # After close() the final checklist owns the screen. A sweep's worker
        # threads are not waited for on the interrupt path, so a late heartbeat
        # or result can still arrive; anything that repaints then would rewind
        # over text the region never wrote.
        self._closed = False

    def __enter__(self) -> "LiveDisplay":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close(ok=exc[0] is None)

    def start(self) -> None:
        self.progress.start()
        self._started = True
        if self._tui:
            self._enter_tui()
            self._thread = threading.Thread(
                target=self._run_tui, name="cmax-progress", daemon=True
            )
            self._thread.start()
            self._tui_ready.wait(timeout=2.0)
            if self._tui_error is not None:
                raise RuntimeError(
                    "prompt-toolkit display failed to start"
                ) from self._tui_error
        else:
            self.stream.write("\x1b[?25l")
            self.stream.flush()
            self._thread = threading.Thread(
                target=self._loop, name="cmax-progress", daemon=True
            )
            self._thread.start()

    def feed(self, line: str) -> None:
        with self._lock:
            if self._closed:
                return
            moved = self.progress.feed(line)
            if self._tui:
                # Fill the live lower pane, or it would sit at "waiting for
                # output" for the whole run. The caller persists the output
                # and decides what to reprint, so keep it out of the final
                # replay (unlike feed_capture).
                self._capture_locked(self._current_owner(), line, replay=False)
                return
            # In the slow cadence the painter sleeps for 30 seconds, so an audit
            # would keep showing a finished check as running while the checks
            # after it start and finish inside that sleep. The audit reaches
            # every state change through here, never through update().
            if moved and self._next_interval != self.interval:
                self._paint()

    def feed_capture(self, line: str) -> None:
        """Feed collector progress and retain its complete human output."""
        with self._lock:
            if self._closed:
                return
            moved = self.progress.feed(line)
            if self._tui:
                self._capture_locked(self._current_owner(), line)
                return
            if moved and self._next_interval != self.interval:
                self._paint()

    def update(self, mutate: Callable[[AuditProgress], None]) -> None:
        """Change the tracked state and repaint at once.

        A sweep runs its tests from more than one thread, so every state change
        goes through this one lock. The immediate repaint is what lets the tick
        fall back to 30 seconds without delaying a result.
        """
        with self._lock:
            if self._closed:
                return
            mutate(self.progress)
            if self._tui:
                self._invalidate_tui()
            else:
                self._paint()

    def print_above(self, text: str) -> None:
        """Scroll text above the region instead of through it.

        A launcher prints a Slurm job identifier and other lines an operator
        needs to keep. Writing them into the region would leave the repaint's
        rewind counting lines it did not write, so the region is erased first
        and drawn again below the new text.
        """
        if text is None:
            return
        with self._lock:
            if self._closed:
                # The region is gone, so the line goes straight to the stream
                # rather than being lost with it.
                self.stream.write(text if text.endswith("\n") else text + "\n")
                self.stream.flush()
                return
            if self._tui and self._started:
                self._capture_locked(self._current_owner(), text)
                self._invalidate_tui()
                return
            self._erase()
            self.stream.write(text if text.endswith("\n") else text + "\n")
            self.stream.flush()
            self._paint()

    def capture_output(
        self, text: str, owner: str | None = None, *, transient: bool = False
    ) -> None:
        """Add terminal output to the lower pane and the final replay.

        A `transient` line (e.g. a heartbeat) is shown live, replacing the
        owner's previous transient line, and is excluded from the final
        replay so long runs do not bury the real output.
        """
        if text is None:
            return
        with self._lock:
            if self._closed:
                if transient:
                    return
                rendered = self._safe_line(text.rstrip("\n"), color=True)
                self.stream.write(rendered + "\n")
                self.stream.flush()
                return
            self._capture_locked(
                owner or self._current_owner(), text, transient=transient
            )

    def activate_output(self, owner: str) -> None:
        """Select the lower-pane owner when a runner stage starts."""
        with self._lock:
            if self._closed:
                return
            owner = owner.strip() or "CAMPAIGN"
            if owner not in self._captures:
                self._captures[owner] = []
                self._capture_order.append(owner)
            self._active_owner = owner
            self._activate_timeline_owner_locked(owner)
            if self._tui and self._started:
                self._invalidate_tui()

    def close(self, ok: bool = True) -> None:
        self._stop.set()
        if self._tui:
            self._stop_tui_input_reader()
            self._exit_tui()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._close_tui_pipe()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            final_lines: list[str] = []
            try:
                self.progress.finish(ok=ok)
                final_lines = self.renderer.final(self.progress, self._clock())
            finally:
                if not self._tui:
                    self._erase()
                    self.stream.write("\x1b[?25h")
            if self._tui:
                self._replay_output()
            for line in final_lines:
                self.stream.write(line + "\n")
            self.stream.flush()

    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                if self._closed:
                    return
                self._paint()
            self._stop.wait(self._next_interval)

    def _resize(self) -> None:
        """Follow a terminal resize, which an audit outlives.

        A shrunken window wraps the lines the last frame wrote, so the rewind
        can no longer find the top of the region. Abandoning the old frame to
        the scrollback and starting a new one below it is the only repair that
        does not overwrite the operator's screen.
        """
        size = shutil.get_terminal_size((100, 30))
        width = max(40, size.columns - 1)
        if size.lines == self.height and width == self.renderer.width:
            return
        self.height = size.lines
        self.renderer.width = width
        self._painted = 0

    def _paint(self) -> None:
        if self._tui:
            self._invalidate_tui()
            return
        self._resize()
        self._tick += 1
        now = self._clock()
        lines = self.renderer.live(self.progress, now, self._tick, self.height)
        out: list[str] = []
        if self._painted:
            out.append(f"\x1b[{self._painted}A")
        # The region never shrinks, so a shorter frame clears the tail instead
        # of leaving the cursor arithmetic to guess where the region ended.
        for index in range(max(len(lines), self._painted)):
            text = lines[index] if index < len(lines) else ""
            out.append("\x1b[2K" + text + "\n")
        self._painted = max(len(lines), self._painted)
        self.stream.write("".join(out))
        self.stream.flush()
        longest = max(
            (step.duration(now) or 0.0 for step in self.progress.running_steps()),
            default=0.0,
        )
        self._next_interval = (
            self.slow_interval if longest >= self.slow_after_s else self.interval
        )

    def _erase(self) -> None:
        if not self._painted:
            return
        self.stream.write(f"\x1b[{self._painted}A\x1b[J")
        self._painted = 0

    def _current_owner(self) -> str:
        # The explicit claim wins: a parallel sweep runs several steps at
        # once, so "the last running step" is arbitrary while activate_output
        # names the step the caller is actually printing about. Displays that
        # never activate an owner (run_with_progress) fall through to the
        # running step.
        if self._active_owner:
            return self._active_owner
        running = self.progress.running_steps()
        if running:
            return running[-1].title
        return "CAMPAIGN"

    def _capture_locked(
        self, owner: str, text: str, *, transient: bool = False, replay: bool = True
    ) -> None:
        owner = owner.strip() or "CAMPAIGN"
        if owner not in self._captures:
            self._captures[owner] = []
            self._capture_order.append(owner)
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if not lines:
            lines = [""]
        owns_heading = any(
            (match := _SECTION_OUT.match(strip_ansi(line).strip())) is not None
            and match.group(1).strip() == owner
            for line in lines
        )
        # Do not adopt `owner` as the active owner: only activate_output makes
        # that claim. A worker heartbeat carrying its own owner must not steal
        # attribution from the step the main thread is printing about.
        if owns_heading:
            synthetic = ("separator", f"── {owner} ──")
            if self._timeline and self._timeline[-1] == synthetic:
                self._mark_timeline_dirty_locked(len(self._timeline) - 1)
                self._timeline.pop()
                self._timeline_rendered.pop()
            self._timeline_owner = owner
        else:
            self._activate_timeline_owner_locked(owner)
        if transient:
            # Live-only: keep at most one transient line per owner in the
            # timeline and never record it for the final replay.
            if (
                self._tail_transient_owner == owner
                and self._timeline
                and self._timeline[-1][0] == "output"
            ):
                self._mark_timeline_dirty_locked(len(self._timeline) - 1)
                self._timeline[-1] = ("output", lines[-1])
                self._timeline_rendered[-1] = self._render_timeline_entry(
                    self._timeline[-1]
                )
            else:
                self._append_timeline_locked([("output", lines[-1])])
                self._tail_transient_owner = owner
            return
        self._tail_transient_owner = None
        if replay:
            self._captures[owner].extend(lines)
        self._append_timeline_locked(("output", line) for line in lines)

    def _activate_timeline_owner_locked(self, owner: str) -> None:
        if owner == self._timeline_owner:
            return
        self._timeline_owner = owner
        if owner in _UNLABELED_OUTPUT_OWNERS:
            return
        self._append_timeline_locked((("separator", f"── {owner} ──"),))

    def _append_timeline_locked(self, entries: Iterable[tuple[str, str]]) -> None:
        pending = list(entries)
        self._timeline.extend(pending)
        self._timeline_rendered.extend(
            self._render_timeline_entry(entry) for entry in pending
        )

    def _render_timeline_entry(self, entry: tuple[str, str]) -> list:
        return to_formatted_text(ANSI(self._timeline_line(entry)))

    def _mark_timeline_dirty_locked(self, index: int) -> None:
        if self._timeline_dirty_from is None:
            self._timeline_dirty_from = index
        else:
            self._timeline_dirty_from = min(self._timeline_dirty_from, index)

    def _enter_tui(self) -> None:
        progress_window = Window(
            content=FormattedTextControl(self._tui_progress_text),
            height=self._tui_top_capacity,
            wrap_lines=False,
            always_hide_cursor=True,
        )
        separator = Window(
            height=1,
            char=self.renderer.theme.encodable("─"),
            style="fg:#666666",
        )
        header = Window(
            content=FormattedTextControl(self._tui_header_text),
            height=1,
            wrap_lines=False,
            always_hide_cursor=True,
        )
        self._timeline_control = _TimelineControl(self)
        log_window = Window(
            content=self._timeline_control,
            get_vertical_scroll=lambda _: self._timeline_control.viewport_top,
            wrap_lines=False,
            always_hide_cursor=True,
        )
        self._tui_log_window = log_window

        bindings = KeyBindings()
        for key, action in (
            (Keys.Up, "up"),
            (Keys.Down, "down"),
            (Keys.PageUp, "page_up"),
            (Keys.PageDown, "page_down"),
            (Keys.Home, "home"),
            (Keys.End, "end"),
        ):
            bindings.add(key)(
                lambda event, selected=action: self._scroll_tui(selected)
            )

        @bindings.add("c-c")
        def interrupt(_event: object) -> None:
            os.kill(os.getpid(), signal.SIGINT)

        @bindings.add(Keys.Vt100MouseEvent, eager=True)
        def vt100_mouse(event: object) -> None:
            action = _vt100_wheel_action(event.data)
            if action is not None:
                self._queue_tui_scroll(action)

        @bindings.add(Keys.ScrollUp, eager=True)
        def terminal_scroll_up(_event: object) -> None:
            self._queue_tui_scroll("wheel_up")

        @bindings.add(Keys.ScrollDown, eager=True)
        def terminal_scroll_down(_event: object) -> None:
            self._queue_tui_scroll("wheel_down")

        root = HSplit(
            [progress_window, separator, header, log_window],
            height=lambda: get_app().output.get_size().rows,
        )
        app_input = create_input(stdin=sys.stdin)
        if self._dedicated_tui_input:
            self._tui_pipe_context = create_pipe_input()
            app_input = self._tui_pipe_context.__enter__()

        self._tui_app = Application(
            layout=Layout(root, focused_element=log_window),
            key_bindings=bindings,
            # Keep the terminal's existing output in normal scrollback. The
            # exact-height root still gives the live UI a full split pane, but
            # prompt-toolkit does not enter the alternate screen buffer.
            full_screen=False,
            erase_when_done=True,
            mouse_support=True,
            # Background output refreshes four times per second. Input-driven
            # invalidations can render at terminal speed and are never held
            # behind prompt-toolkit's high-CPU postponement queue.
            min_redraw_interval=self.input_interval,
            max_render_postpone_time=0,
            refresh_interval=self.log_refresh_interval,
            input=app_input,
            output=create_output(stdout=self.stream),
        )

    def _run_tui(self) -> None:
        assert self._tui_app is not None

        def ready() -> None:
            self._start_tui_input_reader()
            self._tui_ready.set()

        try:
            self._tui_app.run(
                pre_run=ready,
                set_exception_handler=False,
                handle_sigint=False,
            )
        except BaseException as exc:
            if not self._stop.is_set():
                self._tui_error = exc
        finally:
            self._tui_ready.set()

    def _start_tui_input_reader(self) -> None:
        if not self._dedicated_tui_input:
            return
        assert termios is not None and tty is not None
        input_fd = sys.stdin.fileno()
        self._tui_stdin_attrs = termios.tcgetattr(input_fd)
        tty.setraw(input_fd, when=termios.TCSANOW)
        self._tui_input_stop.clear()
        self._tui_input_thread = threading.Thread(
            target=self._tui_input_loop,
            args=(input_fd,),
            name="cmax-tui-input",
            daemon=True,
        )
        self._tui_input_thread.start()

    def _tui_input_loop(self, input_fd: int) -> None:
        parser = Vt100Parser(self._handle_tui_keypress)
        encoding = getattr(sys.stdin, "encoding", None) or "utf-8"
        try:
            while not self._tui_input_stop.is_set():
                readable, _, _ = select.select([input_fd], [], [], 0.05)
                if not readable:
                    parser.flush()
                    continue
                data = os.read(input_fd, 4096)
                if not data:
                    return
                parser.feed(data.decode(encoding, errors="surrogateescape"))
        except OSError as exc:
            if not self._tui_input_stop.is_set():
                self._tui_error = exc

    def _handle_tui_keypress(self, key_press: object) -> None:
        key = key_press.key
        if key == Keys.Vt100MouseEvent:
            action = _vt100_wheel_action(key_press.data)
            if action is not None:
                self._queue_tui_scroll(action)
            return
        if key == Keys.ScrollUp:
            self._queue_tui_scroll("wheel_up")
            return
        if key == Keys.ScrollDown:
            self._queue_tui_scroll("wheel_down")
            return

        app = self._tui_app
        loop = app.loop if app is not None else None
        if app is None or loop is None:
            return

        def deliver() -> None:
            if not app.is_running:
                return
            app.key_processor.feed(key_press)
            app.key_processor.process_keys()

        def deliver_in_context() -> None:
            if app.context is None:
                deliver()
            else:
                app.context.copy().run(deliver)

        loop.call_soon_threadsafe(deliver_in_context)

    def _stop_tui_input_reader(self) -> None:
        self._tui_input_stop.set()
        if self._tui_input_thread is not None:
            self._tui_input_thread.join(timeout=0.5)
            self._tui_input_thread = None
        if self._tui_stdin_attrs is not None and termios is not None:
            try:
                termios.tcsetattr(
                    sys.stdin.fileno(),
                    termios.TCSANOW,
                    self._tui_stdin_attrs,
                )
            except (OSError, ValueError):
                pass
            self._tui_stdin_attrs = None

    def _close_tui_pipe(self) -> None:
        if self._tui_pipe_context is not None:
            self._tui_pipe_context.__exit__(None, None, None)
            self._tui_pipe_context = None

    def _exit_tui(self) -> None:
        app = self._tui_app
        if app is None or not app.is_running:
            return

        def exit_app() -> None:
            if app.is_running:
                app.exit()

        try:
            app.loop.call_soon_threadsafe(exit_app)
        except RuntimeError:
            pass

    def _invalidate_tui(self) -> None:
        if self._tui_app is not None:
            self._tui_app.invalidate()

    def _queue_tui_scroll(self, action: str) -> None:
        """Coalesce a wheel burst before it touches shared display state."""
        self._mark_scroll_input()
        delta = -self.wheel_lines if action == "wheel_up" else self.wheel_lines
        with self._wheel_lock:
            if self._pending_wheel_delta * delta < 0:
                # A wheel or touchpad can report residual momentum in the
                # previous direction. The newest direction is current intent.
                self._pending_wheel_delta = delta
            else:
                self._pending_wheel_delta += delta
            if self._wheel_flush_scheduled:
                return
            self._wheel_flush_scheduled = True
        app = self._tui_app
        loop = app.loop if app is not None else None
        if loop is None:
            self._flush_tui_scroll()
            return
        loop.call_soon_threadsafe(self._schedule_tui_scroll_flush)

    def _schedule_tui_scroll_flush(self) -> None:
        app = self._tui_app
        loop = app.loop if app is not None else None
        if loop is None:
            self._flush_tui_scroll()
            return
        loop.call_later(self.input_interval, self._flush_tui_scroll)

    def _flush_tui_scroll(self) -> None:
        with self._wheel_lock:
            delta = self._pending_wheel_delta
            self._pending_wheel_delta = 0
            self._wheel_flush_scheduled = False
        control = self._timeline_control
        if not delta or control is None or self._closed:
            return
        control.scroll_viewport(delta)
        self._invalidate_tui()

    def _mark_scroll_input(self) -> None:
        self._last_scroll_input_at = time.monotonic()

    def _scroll_input_active(self) -> bool:
        return time.monotonic() - self._last_scroll_input_at < self.log_refresh_interval

    def _scroll_tui(self, action: str) -> None:
        self._mark_scroll_input()
        window = self._tui_log_window
        control = self._timeline_control
        if window is None or control is None:
            return
        page = (
            window.render_info.window_height
            if window.render_info is not None
            else max(1, self.height // 2)
        )
        if action in {"up", "page_up"}:
            distance = page if action == "page_up" else 1
            control.scroll_viewport(-distance)
        elif action in {"down", "page_down"}:
            distance = page if action == "page_down" else 1
            control.scroll_viewport(distance)
        elif action == "home":
            control.jump_to_start()
        elif action == "end":
            control.jump_to_end()
        self._invalidate_tui()

    def _sync_tui_size(self) -> None:
        size = get_app().output.get_size()
        self.height = max(1, size.rows)
        self.renderer.width = max(40, size.columns - 1)

    def _tui_top_capacity(self) -> int:
        self._sync_tui_size()
        return max(1, (self.height - 2) // 2)

    def _tui_progress_text(self) -> ANSI:
        if not self._lock.acquire(blocking=False):
            return self._tui_progress_cache
        try:
            top_height = self._tui_top_capacity()
            self._tick += 1
            now = self._clock()
            lines = self.renderer.live(
                self.progress, now, self._tick, top_height + 2
            )[:top_height]
            longest = max(
                (step.duration(now) or 0.0 for step in self.progress.running_steps()),
                default=0.0,
            )
            self._next_interval = (
                self.slow_interval if longest >= self.slow_after_s else self.interval
            )
            self._tui_progress_cache = ANSI("\n".join(lines))
            return self._tui_progress_cache
        finally:
            self._lock.release()

    def _tui_header_text(self) -> ANSI:
        if not self._lock.acquire(blocking=False):
            return self._tui_header_cache
        try:
            owner = self._active_owner or self._current_owner()
            self._tui_header_cache = ANSI(
                self.theme_line(f" RUNNING · {owner} ", "36")
            )
            return self._tui_header_cache
        finally:
            self._lock.release()

    def theme_line(self, text: str, *codes: str) -> str:
        return self.renderer.theme.paint(
            self.renderer.theme.encodable(text), *codes
        )

    def _safe_line(
        self, text: str, *, color: bool, prompt_toolkit: bool = False
    ) -> str:
        rendered = self.renderer.theme.encodable(text.replace("\r", ""))
        rendered = color_status_text(
            rendered, color=color and self.renderer.theme.color
        )
        return linkify_report_text(rendered, prompt_toolkit=prompt_toolkit)

    def _timeline_line(self, entry: tuple[str, str]) -> str:
        kind, text = entry
        if kind == "separator":
            return self.theme_line(text, "36", "1")
        return self._safe_line(text, color=True, prompt_toolkit=True)

    def _replay_output(self) -> None:
        ordered: list[str] = []
        for step in self.progress.steps:
            for name in (step.title, step.label):
                if name in self._captures and name not in ordered:
                    ordered.append(name)
        ordered.extend(name for name in self._capture_order if name not in ordered)
        for owner in ordered:
            if owner == "CAMPAIGN":
                continue
            lines = self._captures.get(owner, [])
            if not lines:
                continue
            owns_heading = any(
                (match := _SECTION_OUT.match(strip_ansi(line).strip())) is not None
                and match.group(1).strip() == owner
                for line in lines
            )
            if owner not in _UNLABELED_OUTPUT_OWNERS and not owns_heading:
                self.stream.write(
                    self.theme_line(f"── {owner} ──", "36", "1") + "\n"
                )
            for line in lines:
                self.stream.write(self._safe_line(line, color=True) + "\n")


class PlainDisplay:
    """One line per check for a log file, a pipe, or a dumb terminal."""

    def __init__(self, progress: AuditProgress, *, stream: TextIO | None = None) -> None:
        self.progress = progress
        self.stream = stream if stream is not None else sys.stdout
        self._last: Step | None = None

    def __enter__(self) -> "PlainDisplay":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close(ok=exc[0] is None)

    def start(self) -> None:
        self.progress.start()

    def feed(self, line: str) -> None:
        if not self.progress.feed(line):
            return
        step = self.progress.running_step()
        if step is None or step is self._last:
            return
        self._last = step
        index = self.progress.completed + 1
        self.stream.write(
            f"[{index:>3}/{self.progress.total}] {step.group} / {step.title}\n"
        )
        self.stream.flush()

    def close(self, ok: bool = True) -> None:
        self.progress.finish(ok=ok)
        word = "complete" if ok else "failed"
        self.stream.write(
            f"{self.progress.title} {word}: {self.progress.completed}/{self.progress.total} "
            f"checks in {format_duration(self.progress.elapsed())}\n"
        )
        self.stream.flush()


def make_display(
    progress: AuditProgress, *, stream: TextIO | None = None
) -> LiveDisplay | PlainDisplay:
    """A live region on a terminal, plain lines anywhere else."""
    target = stream if stream is not None else sys.stdout
    if not getattr(target, "isatty", lambda: False)() or not progress_enabled():
        return PlainDisplay(progress, stream=target)
    encoding = (getattr(target, "encoding", "") or "").lower()
    theme = Theme(color="NO_COLOR" not in os.environ, unicode="utf" in encoding)
    return LiveDisplay(progress, stream=target, theme=theme)


def run_with_progress(
    command: Sequence[str],
    *,
    cwd: Path | str | None,
    env: dict[str, str] | None,
    progress: AuditProgress,
    stream: TextIO | None = None,
) -> tuple[int, str]:
    """Run a collector, display its progress, and return its full output.

    The output is returned rather than printed because the audit wrapper
    persists it in `audit.out`. The caller decides which part an operator still
    needs on screen.
    """
    target = stream if stream is not None else sys.stdout
    display = make_display(progress, stream=target)
    chunks: list[str] = []
    proc = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # The collector prints dmesg excerpts and raw vendor tool output, which
        # can carry bytes that are not valid UTF-8. Strict decoding would raise
        # inside the read loop and kill a healthy collector mid-run.
        errors="replace",
        bufsize=1,
    )
    assert proc.stdout is not None
    display.start()
    try:
        for line in proc.stdout:
            chunks.append(line)
            display.feed(line)
        returncode = proc.wait()
    except BaseException:
        proc.kill()
        proc.wait()
        display.close(ok=False)
        raise
    display.close(ok=returncode == 0)
    return returncode, "".join(chunks)


def run_with_display(
    command: Sequence[str],
    *,
    cwd: Path | str | None,
    env: dict[str, str] | None,
    display: LiveDisplay,
) -> tuple[int, str]:
    """Run a collector inside an already active campaign display."""
    chunks: list[str] = []
    proc = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            chunks.append(line)
            display.feed_capture(line)
        returncode = proc.wait()
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    display.update(
        lambda tracker: getattr(tracker, "finish_collector", lambda _ok: None)(
            returncode == 0
        )
    )
    return returncode, "".join(chunks)


def print_tail(output: str, marker: str, stream: TextIO | None = None) -> bool:
    """Reprint the block from `marker` to the end of a captured run.

    The progress display replaces the collector's output, and some of that
    output is not optional: the audit findings block exists to be read and
    screenshotted while cluster access is live.
    """
    target = stream if stream is not None else sys.stdout
    lines = output.splitlines()
    color = bool(getattr(target, "isatty", lambda: False)()) and (
        "NO_COLOR" not in os.environ
    )
    for index, line in enumerate(lines):
        if marker in strip_ansi(line):
            for tail in lines[index:]:
                rendered = color_status_text(tail, color=color)
                if getattr(target, "isatty", lambda: False)():
                    rendered = linkify_report_text(rendered)
                target.write(rendered + "\n")
            target.flush()
            return True
    return False


def print_failure_tail(
    output: str, stream: TextIO | None = None, lines: int = 40
) -> None:
    """Show the end of a failed run, which the display otherwise swallowed."""
    target = stream if stream is not None else sys.stdout
    captured = output.splitlines()
    if not captured:
        return
    target.write(f"\nlast {min(lines, len(captured))} line(s) of collector output:\n")
    for line in captured[-lines:]:
        target.write(line + "\n")
    target.flush()
