"""Behavioral tests for the slurm collector's HPC-X-in-/opt reporting.

Executes the real HPC-X /opt reporting block with stubbed print_* helpers,
instead of pinning source fragments. The guarded incident: HPC-X installed
under /opt but not on the default PATH was reported as a warning that said
"this is a FAIL", even though the capability is present (users source
hpcx-init.sh or launch with srun --mpi=pmix). It must report at info severity.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

REPORT_BLOCK = bashtest.extract_block(
    WORKLOAD / "cluster-audit-slurm.sh",
    'if [[ -n "$HPCX_OPT_PATH" ]]; then',
    "# srun --mpi=list / PMIx integration",
)

PRINT_STUBS = {"print_info": "", "print_warn": "", "print_detail": ""}


def run_block(hpcx_opt_path: str, hpcx_in_path: str) -> bashtest.BashRun:
    prelude = f'HPCX_OPT_PATH="{hpcx_opt_path}"\nHPCX_IN_PATH="{hpcx_in_path}"\n'
    return bashtest.run_bash(prelude + REPORT_BLOCK, stubs=PRINT_STUBS)


def all_print_args(run: bashtest.BashRun) -> str:
    joined = []
    for stub in PRINT_STUBS:
        for call in run.calls(stub):
            joined.append(" ".join(call))
    return "\n".join(joined)


def test_hpcx_present_but_not_on_path_is_info_not_fail() -> None:
    run = run_block("/opt/hpcx-v2.26", "false")
    # It reports at info severity, and warns nowhere in this block.
    assert run.calls("print_info"), "expected an info line for installed HPC-X"
    assert not run.calls("print_warn"), "installed HPC-X must not warn"
    # The old "this is a FAIL" text is gone; the pmix guidance is present.
    text = all_print_args(run)
    assert "FAIL" not in text
    assert "srun --mpi=pmix" in text


def test_hpcx_on_path_reports_install_dir() -> None:
    run = run_block("/opt/hpcx-v2.26", "true")
    assert run.calls("print_info")
    assert not run.calls("print_warn")


def test_hpcx_absent_still_warns() -> None:
    # No /opt install and not on PATH remains a genuine warning.
    run = run_block("", "false")
    assert run.calls("print_warn"), "missing HPC-X should still warn"
