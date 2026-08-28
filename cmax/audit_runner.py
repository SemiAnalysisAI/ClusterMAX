from __future__ import annotations

import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from cmax import audit_report, progress, runtime_paths, security


class AuditError(RuntimeError):
    pass


def _slug() -> str:
    configured = (
        os.environ.get("CLUSTER_SLUG")
        or os.environ.get("CLUSTER_NAME")
        or os.environ.get("CLUSTERMAX_CLUSTER")
    )
    value = configured or f"{socket.gethostname().split('.')[0]}-cluster"
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "cluster"


def _audit_dir() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    if "CLUSTERMAX_RUNS_ROOT" in os.environ:
        runs_root = Path(os.environ["CLUSTERMAX_RUNS_ROOT"]).expanduser().resolve()
        return runs_root / _slug() / timestamp / "audit"
    return Path.home() / ".clustermax" / "audit" / timestamp


def run(
    *,
    repo: str | None = None,
    verbosity: int = 1,
    target: str | None = None,
    category: str | None = None,
    resolved_target: security.SecurityTarget | None = None,
    exit_on_fail: bool = False,
) -> int:
    try:
        runtime_root = security.find_runtime_root(repo)
        selected_target = resolved_target or security.detect_target(target)
    except security.SecurityAuditError as exc:
        raise AuditError(str(exc)) from exc

    runner = runtime_paths.audit_runner(runtime_root)
    audit_dir = _audit_dir()
    audit_dir.mkdir(parents=True, exist_ok=False)
    env = {
        **os.environ,
        "RUN_RESULTS_DIR": str(audit_dir),
        "CLUSTER_SLUG": _slug(),
        "CLUSTERMAX_AUDIT_HARNESS": selected_target.harness,
        "CLUSTERMAX_AUDIT_ENVIRONMENT": selected_target.environment,
        "CLUSTERMAX_AUDIT_SCOPE": category or "full",
        "CLUSTERMAX_REPO_ROOT": str(runtime_root),
    }
    print(f"==> cmax audit: {audit_dir}", flush=True)
    tracker = progress.AuditProgress(
        progress.audit_plan(
            runner.parent,
            selected_target.harness,
            scope=category or "full",
        ),
        title=(
            f"ClusterMAX {category} audit · {selected_target.harness}"
            if category
            else f"ClusterMAX audit · {selected_target.harness}"
        ),
    )
    returncode, output = progress.run_with_progress(
        ["bash", str(runner)],
        cwd=runtime_root,
        env=env,
        progress=tracker,
    )
    if returncode:
        progress.print_failure_tail(output)
    if returncode:
        raise AuditError(f"audit failed with exit {returncode}; results: {audit_dir}")

    values_path = audit_dir / "audit.values.json"
    if not values_path.is_file():
        raise AuditError(f"audit produced no results; logs: {audit_dir}")
    report = audit_report.render(
        values_path,
        runtime_root,
        verbosity=verbosity,
        rules_root=runtime_root,
        color=sys.stdout.isatty(),
        category=category,
        # Grade the printed report against the same confirmed target as the
        # exit-code path, so target-specific skipped checks cannot drift.
        harness=selected_target.harness,
        environment=selected_target.environment,
    )
    print(report)
    if exit_on_fail:
        values = json.loads(values_path.read_text())
        checks = audit_report.evaluate(
            values,
            runtime_root,
            category=category,
            harness=selected_target.harness,
            environment=selected_target.environment,
        )
        if any(check.status == audit_report.FAIL for check in checks):
            return 2
    return 0
