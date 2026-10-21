"""AMD host model and tool discovery."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

AUDIT_DIR = Path(__file__).resolve().parent

WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"

MODEL_FUNCTION = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "detect_amd_gpu_model_without_cli"
) + bashtest.extract_function(
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
    with tempfile.TemporaryDirectory() as root:
        return bashtest.run_bash(
            MODEL_FUNCTION + "\ndetect_amd_gpu_model",
            stubs=stubs,
            env={"CLUSTERMAX_AUDIT_ROOT": root},
        )

@pytest.mark.parametrize(
    "rocm_output,amd_output,expected,calls",
    [
        ("GPU[0] : Card Series: N/A", 'gpu,market_name\n0,"AMD Instinct MI355X"',
         "AMD-Instinct-MI355X", [["static", "--asic", "--csv"]]),
        ("GPU[0] : Card Series:   AMD Instinct MI355X", 'gpu,market_name\n0,"unused"',
         "AMD-Instinct-MI355X", []),
        ("GPU[0] : Card Series: N/A", None, "unknown", []),
    ],
    ids=["amd-smi-fallback", "rocm-model-wins", "no-model"],
)
def test_amd_model_selection(rocm_output, amd_output, expected, calls):
    run = run_model_check(rocm_output, amd_output)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected
    assert run.calls("amd-smi") == calls

FIND_ROCM_BINARY = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "find_rocm_binary"
)

FIND_TRANSFERBENCH_BINARY = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "find_transferbench_binary"
)

@pytest.mark.parametrize(
    "tool,dirname,arguments",
    [
        ("rocprofv3", "rocm", "rocprofv3 rocprof-compute rocprof"),
        ("rvs", "custom-rocm", "rvs"),
    ],
)
def test_tool_is_found_in_rocm_bin_without_path(tmp_path: Path, tool, dirname, arguments) -> None:
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    rocm_bin = tmp_path / dirname / "bin"
    rocm_bin.mkdir(parents=True)
    rocprof = rocm_bin / tool
    rocprof.write_text("#!/bin/sh\nexit 0\n")
    rocprof.chmod(0o755)

    run = bashtest.run_bash(
        'PATH="$CMAX_TEST_EMPTY_PATH"\n'
        + FIND_ROCM_BINARY
        + f"\nfind_rocm_binary {arguments}",
        env={
            "CMAX_TEST_EMPTY_PATH": str(empty_path),
            "ROCM_BIN_DIR": str(rocm_bin),
        },
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == str(rocprof)

def test_transferbench_is_found_in_versioned_rocm_extras(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    rocm_root = tmp_path / "rocm"
    transferbench = rocm_root / "extras-7" / "bin" / "TransferBench"
    transferbench.parent.mkdir(parents=True)
    transferbench.write_text("#!/bin/sh\nexit 0\n")
    transferbench.chmod(0o755)

    run = bashtest.run_bash(
        'PATH="$CMAX_TEST_EMPTY_PATH"\n'
        + FIND_TRANSFERBENCH_BINARY
        + "\nfind_transferbench_binary",
        env={
            "CMAX_TEST_EMPTY_PATH": str(empty_path),
            "ROCM_BIN_DIR": str(rocm_root / "bin"),
            "ROCM_ROOT_DIR": str(rocm_root),
        },
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == str(transferbench)
