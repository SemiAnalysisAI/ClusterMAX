#!/usr/bin/env python3
"""Run the legacy per-harness audit script and record its raw JSON output."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def collector_env() -> dict[str, str]:
    """Return the collector environment without the audit scope.

    Each harness has one collector. A category such as `security` only filters
    the checks that run_checks.py reports, so the collector must read the same
    evidence for every scope. host-check.sh and container-check.sh skip facts
    when CLUSTERMAX_AUDIT_SCOPE=security, and srun passes the environment to
    the worker, so the scope must not reach the collector.
    """
    env = dict(os.environ)
    env.pop("CLUSTERMAX_AUDIT_SCOPE", None)
    return env


def newest_json(path: Path) -> Path | None:
    candidates = [candidate for candidate in path.glob("*.json") if candidate.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate.stat().st_mtime_ns)


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(
            "usage: run_legacy_audit.py <audit-root> <audit-script> <slug> <tmpdir> <audit-json-path>",
            file=sys.stderr,
        )
        return 2

    audit_root = Path(argv[1])
    audit_script = Path(argv[2])
    slug = argv[3]
    tmpdir = Path(argv[4])
    audit_json_path = Path(argv[5])

    if not audit_script.is_file():
        print(f"ERROR: audit script not found at {audit_script}", file=sys.stderr)
        return 1
    if not tmpdir.is_dir():
        print(f"ERROR: audit temp dir not found at {tmpdir}", file=sys.stderr)
        return 1

    legacy_cwd_env = os.environ.get("CLUSTERMAX_AUDIT_LEGACY_CWD")
    legacy_cwd = Path(legacy_cwd_env) if legacy_cwd_env else audit_root
    legacy_cwd.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["bash", str(audit_script), "--name", slug, "--output-dir", str(tmpdir)],
        cwd=legacy_cwd,
        env=collector_env(),
    )
    if result.returncode != 0:
        return result.returncode

    audit_json = newest_json(tmpdir)
    if audit_json is None:
        print(f"ERROR: audit script produced no JSON file in {tmpdir}", file=sys.stderr)
        return 1

    audit_json_path.write_text(str(audit_json) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
