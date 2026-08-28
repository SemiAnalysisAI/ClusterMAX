"""Behavioral tests for AMD GPU model detection in the host check."""

from __future__ import annotations

import sys
from pathlib import Path


AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest


MODEL_FUNCTION = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "detect_amd_gpu_model"
)


def run_model_check(
    rocm_output: str, amd_csv_output: str | None
) -> bashtest.BashRun:
    stubs = {
        "rocm-smi": (
            'if [[ "$1" == "--showproductname" ]]; then\n'
            f"  printf '%b\\n' {rocm_output!r}\n"
            "fi"
        ),
    }
    if amd_csv_output is not None:
        stubs["amd-smi"] = (
            'if [[ "$*" == "static --asic --csv" ]]; then\n'
            f"  printf '%b\\n' {amd_csv_output!r}\n"
            "fi"
        )
    return bashtest.run_bash(
        MODEL_FUNCTION + "\ndetect_amd_gpu_model",
        stubs=stubs,
    )


def test_rocm_smi_na_falls_back_to_amd_smi_market_name() -> None:
    run = run_model_check(
        "GPU[0] : Card Series: N/A",
        'gpu,market_name\n0,"AMD Instinct MI355X"',
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "AMD-Instinct-MI355X"
    assert run.calls("amd-smi") == [["static", "--asic", "--csv"]]


def test_valid_rocm_smi_model_does_not_call_amd_smi() -> None:
    run = run_model_check(
        "GPU[0] : Card Series:   AMD Instinct MI355X",
        'gpu,market_name\n0,"unused"',
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "AMD-Instinct-MI355X"
    assert run.calls("amd-smi") == []


def test_rocm_smi_na_without_amd_smi_remains_unknown() -> None:
    run = run_model_check(
        "GPU[0] : Card Series: N/A",
        None,
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "unknown"
    assert run.calls("amd-smi") == []
