"""Behavioral tests for AMD hardware-counter access classification."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest


ROCM_COUNTER_ACCESS_STATE = bashtest.extract_function(
    WORKLOAD / "audit-common.sh", "rocm_counter_access_state"
)


@pytest.mark.parametrize(
    ("kfd_access", "render_access", "expected"),
    (
        ("allowed", "allowed", "allowed"),
        ("denied", "allowed", "denied"),
        ("allowed", "denied", "denied"),
        ("absent", "allowed", "denied"),
        ("allowed", "absent", "denied"),
        ("unknown", "allowed", "untested"),
    ),
)
def test_rocm_counter_access_state(
    kfd_access: str, render_access: str, expected: str
) -> None:
    run = bashtest.run_bash(
        ROCM_COUNTER_ACCESS_STATE
        + f"\nrocm_counter_access_state {kfd_access} {render_access}"
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected
