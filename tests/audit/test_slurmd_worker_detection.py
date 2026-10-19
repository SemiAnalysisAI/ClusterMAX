from __future__ import annotations

from pathlib import Path

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"


def test_host_check_detects_slurmd_on_the_worker() -> None:
    block = bashtest.extract_block(
        WORKLOAD / "host-check.sh",
        "# --- Slurm worker daemon ---",
        'echo "WORKER_SLURMD_RUNNING=${WORKER_SLURMD_RUNNING}"',
    )
    run = bashtest.run_bash(block, stubs={"pgrep": "exit 0"})

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "WORKER_SLURMD_RUNNING=true"
    assert run.calls("pgrep") == [["-x", "slurmd"]]


def test_host_check_reports_absent_slurmd_on_the_worker() -> None:
    block = bashtest.extract_block(
        WORKLOAD / "host-check.sh",
        "# --- Slurm worker daemon ---",
        'echo "WORKER_SLURMD_RUNNING=${WORKER_SLURMD_RUNNING}"',
    )
    run = bashtest.run_bash(block, stubs={"pgrep": "exit 1"})

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "WORKER_SLURMD_RUNNING=false"


def test_slurm_collector_uses_worker_result() -> None:
    block = bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        "# The compute node is the only valid vantage point for slurmd.",
        "# Geolocation must describe the compute node's egress path.",
    )
    setup = """WORKER_CHECK_OK=true
WORKER_SLURMD_RUNNING=true
WORKER_HOSTNAME=gpu-1
SLURMD_RUNNING=false
SLURMD_CHECK_SCOPE=unverified
"""
    report = '\nprintf "%s %s\\n" "$SLURMD_RUNNING" "$SLURMD_CHECK_SCOPE"\n'
    run = bashtest.run_bash(
        setup + block + report,
        stubs={"print_section": "", "print_info": "", "print_warn": ""},
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true worker"


def test_successful_worker_step_proves_slurmd_when_the_process_is_hidden() -> None:
    block = bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        "# The compute node is the only valid vantage point for slurmd.",
        "# Geolocation must describe the compute node's egress path.",
    )
    setup = """WORKER_CHECK_OK=true
WORKER_SLURMD_RUNNING=false
WORKER_HOSTNAME=gpu-1
SLURMD_RUNNING=false
SLURMD_CHECK_SCOPE=unverified
"""
    report = '\nprintf "%s %s\\n" "$SLURMD_RUNNING" "$SLURMD_CHECK_SCOPE"\n'
    run = bashtest.run_bash(
        setup + block + report,
        stubs={"print_info": "", "print_detail": "", "print_warn": ""},
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true worker"
    assert run.calls("print_warn") == []
