#!/usr/bin/env python3
"""Plan the audit harness, audit script, and result output paths."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SUPPORTED_HARNESSES = {"slurm", "k8s", "standalone"}


def command_ok(command: list[str]) -> bool:
    return subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def detect_harness() -> str:
    override = (
        os.environ.get("CLUSTERMAX_AUDIT_HARNESS")
        or os.environ.get("CLUSTERMAX_HARNESS")
    )
    if override:
        return override

    if os.environ.get("SLURM_JOB_ID"):
        return "slurm"
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "k8s"
    if shutil.which("sbatch"):
        return "slurm"
    if shutil.which("kubectl") and command_ok(["kubectl", "cluster-info"]):
        return "k8s"
    return "standalone"


def hostname_label() -> str:
    result = subprocess.run(
        ["hostname", "-s"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    label = result.stdout.strip() if result.returncode == 0 else ""
    if not label:
        result = subprocess.run(
            ["hostname"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        label = result.stdout.strip() if result.returncode == 0 else "cluster"
    return re.sub(r"-[0-9]+(-[0-9]+)?$", "", label) + "-cluster"


def cluster_slug() -> str:
    return (
        os.environ.get("CLUSTER_SLUG")
        or os.environ.get("CLUSTER_NAME")
        or os.environ.get("CLUSTERMAX_CLUSTER")
        or hostname_label()
    )


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def slug_from_results_dir(repo_root: Path, out_dir: Path) -> str:
    """Infer the cluster slug from runs/<slug>/<timestamp>[/audit]."""
    try:
        rel = out_dir.resolve().relative_to((repo_root / "runs").resolve())
    except ValueError:
        return out_dir.parent.name

    if len(rel.parts) >= 3 and rel.parts[2] == "audit":
        return rel.parts[0]
    if len(rel.parts) >= 2:
        return rel.parts[0]
    return out_dir.parent.name


def write_shell_plan(path: Path, plan: dict[str, str]) -> None:
    lines = [f"{key}={shlex.quote(value)}" for key, value in sorted(plan.items())]
    path.write_text("\n".join(lines) + "\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: plan_audit.py <repo-root> <plan-env-path>", file=sys.stderr)
        return 2

    repo_root = Path(argv[1])
    plan_path = Path(argv[2])
    harness = detect_harness()
    if harness not in SUPPORTED_HARNESSES:
        print(f"ERROR: unsupported audit harness: {harness}", file=sys.stderr)
        return 2

    # Collectors are flat siblings of this script in the audit scripts directory
    # (cluster-audit-<harness>.sh), selected here by detected harness.
    script_dir = Path(__file__).resolve().parent
    audit_root = script_dir
    audit_script = script_dir / f"cluster-audit-{harness}.sh"
    if not audit_script.is_file():
        print(f"ERROR: audit script not found at {audit_script}", file=sys.stderr)
        return 1

    run_results_dir = os.environ.get("RUN_RESULTS_DIR")
    if run_results_dir:
        out_dir = Path(run_results_dir)
        slug = os.environ.get("CLUSTER_SLUG") or slug_from_results_dir(
            repo_root, out_dir
        )
    else:
        slug = cluster_slug()
        out_dir = repo_root / "runs" / slug / now_ts() / "audit"

    write_shell_plan(
        plan_path,
        {
            "AUDIT_ROOT": str(audit_root),
            "AUDIT_SCRIPT": str(audit_script),
            "HARNESS": harness,
            "OUT_DIR": str(out_dir),
            "SLUG": slug,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
