#!/usr/bin/env python3
"""Build the GitHub Pages copy of the minimum version table.

The `minimum-versions-publish` workflow runs this script. The script reads the
committed table `cmax/scripts/1-audit/minimum-versions.json` and writes one
file, `<out>/minimum-versions.json`. The workflow deploys that directory to
the GitHub Pages site of this repository. The site carries no other file.

The published copy is the committed table plus two top-level stamps:

  * `refreshed`: when the daily `minimum-versions-refresh` job last completed
    successfully. The job reads every upstream feed, so this stamp moves every
    day, also when no minimum changed. The command line compares this stamp
    against the current time to decide if its table is stale.
  * `changed`: when a minimum value last changed. The script reads the Git
    history of the committed table and finds the oldest consecutive revision
    whose minimum values equal the current values. The `generated` stamp of
    that revision is the moment the generator recorded the change. Metadata
    such as bulletin sources and the `generated` stamp itself do not move
    `changed`.

Every component block is copied byte for byte. The command line and the
website ignore keys they do not read.

The script is standard library only.

Usage::

    python3 .github/scripts/minimum_pages.py \\
        --table cmax/scripts/1-audit/minimum-versions.json \\
        --out "$RUNNER_TEMP/pages" \\
        --refreshed 2026-10-24T07:28:02Z
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUTPUT_FILE = "minimum-versions.json"
SCHEMA_VERSION = 1

# Each kind keeps its minimums under its own key. Name the metadata keys
# instead, so a new kind with a new value key needs no edit here. This list
# matches the gate in `minimum-versions-refresh`.
METADATA_KEYS = frozenset(
    {
        "advisory", "advisories", "advisoryRanges", "branchSources",
        "cves", "floorSources", "fixAvailability", "floorAvailability",
        "kind", "policy", "programCves", "programSources", "release",
        "source", "sources",
    }
)


class PublishError(RuntimeError):
    """The table must not reach the public site."""


def parse_stamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def format_stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def minimums(table: dict[str, Any]) -> dict[str, Any]:
    """Return the minimum values alone, without metadata and timestamps."""
    return {
        name: {key: value for key, value in block.items() if key not in METADATA_KEYS}
        for name, block in (table.get("components") or {}).items()
        if isinstance(block, dict)
    }


def check_complete(table: Any) -> None:
    """Raise `PublishError` for a table that must not be published.

    The public copy feeds an audit that grades a provider. An empty or
    partial table must never reach the site. This repeats the gate in
    `minimum-versions-refresh`, because a merge can also arrive by hand.
    """
    if not isinstance(table, dict):
        raise PublishError("the table is not a JSON object")
    if table.get("schemaVersion") != SCHEMA_VERSION:
        raise PublishError(
            f"the table declares schema version {table.get('schemaVersion')!r}. "
            f"The reader understands {SCHEMA_VERSION}."
        )
    components = table.get("components")
    if not isinstance(components, dict) or not components:
        raise PublishError("the table has no components")
    if parse_stamp(table.get("generated")) is None:
        raise PublishError(
            f"the table carries no usable generated timestamp: {table.get('generated')!r}"
        )
    empty = sorted(
        name for name, values in minimums(table).items() if not any(values.values())
    )
    if empty:
        raise PublishError(f"these components carry no minimum value: {', '.join(empty)}")


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def last_changed(table: dict[str, Any], path: Path, *, repo: Path) -> str:
    """Return the `generated` stamp of the revision that set the current minimums.

    The history walk goes from the newest revision of `path` to the oldest. It
    stops at the first revision whose minimum values differ from `table`. The
    oldest revision before that stop set the current minimums.

    A missing or shallow history, or any Git error, returns the `generated`
    stamp of `table`. That is never older than the real value, so the
    website can show a `changed` time that is late, never one that is early.
    """
    current = minimums(table)
    fallback = str(table["generated"])
    try:
        relative = path.resolve().relative_to(repo.resolve()).as_posix()
        revisions = _git("log", "--format=%H", "--", relative, cwd=repo).split()
    except (OSError, ValueError, subprocess.CalledProcessError):
        return fallback
    stamp: str | None = None
    for revision in revisions:
        try:
            older = json.loads(_git("show", f"{revision}:{relative}", cwd=repo))
        except (subprocess.CalledProcessError, ValueError):
            break
        if not isinstance(older, dict) or minimums(older) != current:
            break
        if parse_stamp(older.get("generated")) is not None:
            stamp = str(older["generated"])
    return stamp or fallback


def previous_refreshed(url: str | None, *, timeout: float = 15) -> str | None:
    """Return the `refreshed` stamp the public site serves now, or None."""
    if not url:
        return None
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "Cache-Control": "no-cache"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if isinstance(data, dict) and parse_stamp(data.get("refreshed")) is not None:
        return str(data["refreshed"])
    return None


def build(
    table: dict[str, Any],
    *,
    refreshed: str | None,
    changed: str,
    previous: str | None = None,
) -> dict[str, Any]:
    """Return the published copy of `table`.

    `refreshed` comes from the latest successful refresh run. When that lookup
    failed, the stamp the site serves now (`previous`) is kept, and the
    `generated` stamp is the last fallback. The result is never older than
    `generated` or `changed`, because the table cannot be newer than the
    last time the feeds were read.
    """
    generated = parse_stamp(table["generated"])
    assert generated is not None
    candidates = [generated]
    for value in (refreshed or previous, changed):
        stamp = parse_stamp(value)
        if stamp is not None:
            candidates.append(stamp)
    published = dict(table)
    published["refreshed"] = format_stamp(max(candidates))
    published["changed"] = changed
    return published


def render(table: dict[str, Any]) -> str:
    # Same rendering as the generator: sorted keys, two-space indent, trailing
    # newline.
    return json.dumps(table, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--table", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--refreshed",
        default="",
        help="Completion time of the latest successful refresh run.",
    )
    parser.add_argument(
        "--previous-url",
        default="",
        help="Public address of the published copy, read when --refreshed is empty.",
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    try:
        table = json.loads(args.table.read_text(encoding="utf-8"))
        check_complete(table)
    except (OSError, ValueError, PublishError) as exc:
        print(f"::error::{args.table}: {exc}. Refuse to publish it.", file=sys.stderr)
        return 1

    changed = last_changed(table, args.table, repo=args.repo)
    previous = None
    if parse_stamp(args.refreshed) is None:
        previous = previous_refreshed(args.previous_url or None)
        print(
            "::warning::no successful refresh run was found. "
            + (
                f"Keeping the published refreshed stamp {previous}."
                if previous
                else "Using the generated stamp of the table."
            )
        )
    published = build(table, refreshed=args.refreshed or None, changed=changed, previous=previous)

    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / OUTPUT_FILE
    target.write_text(render(published), encoding="utf-8")
    print(
        f"wrote {target}: generated={published['generated']} "
        f"changed={published['changed']} refreshed={published['refreshed']}"
    )
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            for key in ("generated", "changed", "refreshed"):
                handle.write(f"{key}={published[key]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
