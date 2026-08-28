"""Behavioral tests for AMD tool discovery in the worker host check."""

from __future__ import annotations

import sys
from pathlib import Path


AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest


FIND_ROCM_BINARY = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "find_rocm_binary"
)
FIND_TRANSFERBENCH_BINARY = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "find_transferbench_binary"
)


def test_rocprofv3_is_found_in_rocm_bin_when_it_is_not_on_path(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    rocm_bin = tmp_path / "rocm" / "bin"
    rocm_bin.mkdir(parents=True)
    rocprof = rocm_bin / "rocprofv3"
    rocprof.write_text("#!/bin/sh\nexit 0\n")
    rocprof.chmod(0o755)

    run = bashtest.run_bash(
        'PATH="$CMAX_TEST_EMPTY_PATH"\n'
        + FIND_ROCM_BINARY
        + "\nfind_rocm_binary rocprofv3 rocprof-compute rocprof",
        env={
            "CMAX_TEST_EMPTY_PATH": str(empty_path),
            "ROCM_BIN_DIR": str(rocm_bin),
        },
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == str(rocprof)


def test_rvs_is_found_in_custom_rocm_bin_when_it_is_not_on_path(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    rocm_bin = tmp_path / "custom-rocm" / "bin"
    rocm_bin.mkdir(parents=True)
    rvs = rocm_bin / "rvs"
    rvs.write_text("#!/bin/sh\nexit 0\n")
    rvs.chmod(0o755)

    run = bashtest.run_bash(
        'PATH="$CMAX_TEST_EMPTY_PATH"\n'
        + FIND_ROCM_BINARY
        + "\nfind_rocm_binary rvs",
        env={
            "CMAX_TEST_EMPTY_PATH": str(empty_path),
            "ROCM_BIN_DIR": str(rocm_bin),
        },
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == str(rvs)


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
