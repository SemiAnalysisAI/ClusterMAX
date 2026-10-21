"""Behavioral tests for the slurm collector's per-GPU-class idle power ceiling."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

FUNC = bashtest.extract_function(WORKLOAD / "cluster-audit-slurm.sh", "gpu_idle_power_ceiling")

def ceiling(model: str) -> int:
    run = bashtest.run_bash(f'{FUNC}\ngpu_idle_power_ceiling "{model}"')
    assert run.returncode == 0, run.stderr
    return int(run.stdout.strip())

@pytest.mark.parametrize(
    "model,expected",
    [
        ("NVIDIA-GB300", 300),
        ("NVIDIA-GB200-NVL72", 300),
        ("NVIDIA-B300-SXM6", 250),
        ("NVIDIA-B200", 250),
        ("NVIDIA-H100-80GB-HBM3", 150),
        ("NVIDIA-H200", 150),
    ],
)
def test_ceiling_scales_with_gpu_class(model: str, expected: int) -> None:
    assert ceiling(model) == expected

def test_unknown_model_keeps_conservative_default() -> None:
    assert ceiling("some-future-gpu") == 150
    assert ceiling("") == 150
