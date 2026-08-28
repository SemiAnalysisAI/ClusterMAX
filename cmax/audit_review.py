"""Explore a saved ClusterMAX audit without running the collector again."""

from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO

from cmax import audit_report


class AuditReviewError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditArtifacts:
    values: Path | None
    raw: Path | None

    @property
    def source(self) -> Path:
        path = self.values or self.raw
        if path is None:  # pragma: no cover - construction prevents this state
            raise AuditReviewError("audit review has no source")
        return path


def _values_candidates(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        if path.suffix.lower() == ".json":
            return (path,)
        return (
            path.with_name("audit.values.json"),
            path.parent.parent / "audit.values.json",
        )
    return (
        path / "audit.values.json",
        path / "audit" / "audit.values.json",
        path / "logs" / "audit.values.json",
    )


def _raw_candidates(path: Path, values: Path | None) -> tuple[Path, ...]:
    candidates: list[Path] = []
    if path.is_file() and path.suffix.lower() != ".json":
        candidates.append(path)
    if values is not None:
        candidates.extend(
            (values.with_name("audit.out"), values.parent / "logs" / "audit.out")
        )
    if path.is_dir():
        candidates.extend(
            (
                path / "audit.out",
                path / "audit" / "audit.out",
                path / "logs" / "audit.out",
                path / "audit" / "logs" / "audit.out",
            )
        )
    return tuple(candidates)


def resolve_source(path: Path) -> AuditArtifacts:
    """Resolve an audit directory, values file, or raw output file."""
    source = path.expanduser().resolve()
    if not source.exists():
        raise AuditReviewError(f"audit source does not exist: {source}")
    values = next((item for item in _values_candidates(source) if item.is_file()), None)
    raw = next(
        (item for item in _raw_candidates(source, values) if item.is_file()), None
    )
    if values is None and raw is None:
        raise AuditReviewError(
            f"no audit.values.json or audit.out found at {source}"
        )
    return AuditArtifacts(values=values, raw=raw)


def _timestamp_key(values_path: Path) -> tuple[str, str]:
    parent = values_path.parent
    timestamp = parent.parent.name if parent.name == "audit" else parent.name
    return timestamp, str(values_path)


def find_latest(
    search_roots: list[Path] | None = None,
    private_root: Path | None = None,
) -> AuditArtifacts:
    """Find the newest audit in configured, checkout, or private storage."""
    roots = search_roots or [Path.cwd(), *Path.cwd().parents]
    candidates: set[Path] = set()
    custom_runs_root = os.environ.get("CLUSTERMAX_RUNS_ROOT")
    if custom_runs_root:
        custom_runs = Path(custom_runs_root).expanduser().resolve()
        if custom_runs.is_dir():
            candidates.update(custom_runs.glob("*/*/audit/audit.values.json"))
            candidates.update(custom_runs.glob("*/*/audit/audit.out"))
    for root in roots:
        runs = root.expanduser().resolve() / "runs"
        if runs.is_dir():
            candidates.update(runs.glob("*/*/audit/audit.values.json"))
            candidates.update(runs.glob("*/*/audit/audit.out"))
    private = private_root or Path.home() / ".clustermax" / "audit"
    if private.is_dir():
        candidates.update(private.glob("*/audit.values.json"))
        candidates.update(private.glob("*/audit.out"))
    files = [path.resolve() for path in candidates if path.is_file()]
    if not files:
        raise AuditReviewError(
            "no saved audit found under CLUSTERMAX_RUNS_ROOT, runs/, or "
            "~/.clustermax/audit"
        )
    # ClusterMAX timestamp directory names sort in chronological order.
    return resolve_source(max(files, key=_timestamp_key))


def load_checks(artifacts: AuditArtifacts, rules_root: Path):
    if artifacts.values is None:
        return []
    try:
        values = json.loads(artifacts.values.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditReviewError(
            f"could not read audit values from {artifacts.values}: {exc}"
        ) from exc
    return audit_report.evaluate(values, rules_root)


def _check_list(checks, selected: list[int] | None = None) -> str:
    indices = selected if selected is not None else list(range(len(checks)))
    if not indices:
        return "No matching audit checks."
    lines = ["number  status   check"]
    for index in indices:
        check = checks[index]
        lines.append(f"{index + 1:>6}  {check.status:<7}  {check.title}")
    return "\n".join(lines)


def _show_check(check, number: int) -> str:
    observed = json.dumps(check.observed, indent=2, sort_keys=True, default=str)
    return (
        f"{number}. {check.title}\n"
        f"status: {check.status}\n"
        f"key: {check.key}\n"
        f"observed: {observed}"
    )


HELP = """Audit review commands:
  summary              Show warnings, failures, and totals.
  all                  List every classified check with a number.
  passes               List passing checks.
  show <number|key>    Show one check and its observed value.
  find <text>          Find checks by title, key, or observed value.
  raw [text]           Show the raw log, or matching raw-log lines.
  paths                Show the selected artifact paths.
  help                 Show these commands.
  quit                 Exit the audit review."""


def execute_command(
    command: str,
    artifacts: AuditArtifacts,
    checks,
    *,
    color: bool = False,
) -> tuple[str, bool]:
    """Execute one review command and return its output and exit state."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return f"invalid command: {exc}", False
    if not parts:
        return "", False
    name, args = parts[0].lower(), parts[1:]
    if name in {"quit", "exit", "q"}:
        return "", True
    if name in {"help", "?"}:
        return HELP, False
    if name == "summary":
        if artifacts.values is None:
            return "Structured audit values are unavailable. Use 'raw'.", False
        return audit_report.format_report(
            checks, color=color, command="cmax audit review"
        ), False
    if name == "all":
        return _check_list(checks), False
    if name == "passes":
        selected = [i for i, check in enumerate(checks) if check.status == "pass"]
        return _check_list(checks, selected), False
    if name == "paths":
        return (
            f"values: {artifacts.values or 'not found'}\n"
            f"raw: {artifacts.raw or 'not found'}"
        ), False
    if name == "show":
        if not args:
            return "usage: show <number|key>", False
        query = " ".join(args)
        if query.isdigit():
            index = int(query) - 1
            if 0 <= index < len(checks):
                return _show_check(checks[index], index + 1), False
            return f"check number out of range: {query}", False
        matches = [
            i
            for i, check in enumerate(checks)
            if query.lower() in check.key.lower()
            or query.lower() in check.title.lower()
        ]
        if len(matches) == 1:
            index = matches[0]
            return _show_check(checks[index], index + 1), False
        return _check_list(checks, matches), False
    if name == "find":
        if not args:
            return "usage: find <text>", False
        query = " ".join(args).lower()
        matches = [
            i
            for i, check in enumerate(checks)
            if query in check.key.lower()
            or query in check.title.lower()
            or query in json.dumps(check.observed, default=str).lower()
        ]
        return _check_list(checks, matches), False
    if name == "raw":
        if artifacts.raw is None:
            return "Raw audit log not found.", False
        text = artifacts.raw.read_text(errors="replace")
        if not args:
            return text.rstrip(), False
        query = " ".join(args).lower()
        lines = [
            f"{number}: {line}"
            for number, line in enumerate(text.splitlines(), start=1)
            if query in line.lower()
        ]
        return "\n".join(lines) if lines else "No matching raw-log lines.", False
    return f"unknown command: {name}. Use 'help'.", False


def run(
    artifacts: AuditArtifacts,
    rules_root: Path,
    *,
    verbosity: int = 1,
    commands: list[str] | None = None,
    interactive: bool | None = None,
    input_fn: Callable[[str], str] = input,
    output: TextIO | None = None,
) -> int:
    """Render one saved audit and optionally start the review prompt."""
    output = output or sys.stdout
    color = bool(
        getattr(output, "isatty", lambda: False)()
        and "NO_COLOR" not in os.environ
    )
    checks = load_checks(artifacts, rules_root)
    print(f"Audit review: {artifacts.source}", file=output)
    if artifacts.values is not None:
        print(
            audit_report.format_report(
                checks,
                verbosity=min(verbosity, 3),
                color=color,
                command="cmax audit review",
            ),
            file=output,
        )
    else:
        print(
            "Structured audit values not found. Raw-log commands are available.",
            file=output,
        )
        if verbosity >= 3:
            raw_text, _ = execute_command("raw", artifacts, checks, color=color)
            print(raw_text, file=output)
    for command in commands or []:
        rendered, should_exit = execute_command(
            command, artifacts, checks, color=color
        )
        if rendered:
            print(rendered, file=output)
        if should_exit:
            return 0

    if interactive is None:
        interactive = bool(
            getattr(sys.stdin, "isatty", lambda: False)()
            and getattr(output, "isatty", lambda: False)()
        )
    if not interactive or commands:
        return 0

    print("\nType 'help' for review commands.", file=output)
    while True:
        try:
            command = input_fn("audit-review> ")
        except (EOFError, KeyboardInterrupt):
            print(file=output)
            return 0
        rendered, should_exit = execute_command(
            command, artifacts, checks, color=color
        )
        if rendered:
            print(rendered, file=output)
        if should_exit:
            return 0
