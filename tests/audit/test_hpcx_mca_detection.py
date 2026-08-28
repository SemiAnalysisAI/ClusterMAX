"""Behavioral tests for host-check.sh HPC-X detection.

Executes the real detection chain with stubbed mpirun / ompi_info, instead of
pinning source fragments. The guarded incident: HPC-X ships its own Open MPI
build that reports a plain "Open MPI 4.1.9a1" version string and installs at
/usr/mpi/gcc/openmpi-*, so the version grep missed it and the audit reported
"mpirun is NOT HPC-X" even though the UCX pml and HCOLL coll MCA components (the
real signal) were present.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

DETECT_CHAIN = bashtest.extract_block(
    WORKLOAD / "host-check.sh",
    "MPI_VER=$(mpirun --version",
    "    fi",
)

# HPC-X's Open MPI: plain version, UCX pml + HCOLL coll MCA components present.
HPCX_OMPI_INFO = (
    "                 Package: Open MPI\n"
    "                Open MPI: 4.1.9a1\n"
    "                MCA coll: hcoll (MCA v2.1.0, Component v4.1.9)\n"
    "                 MCA pml: ucx (MCA v2.1.0, Component v4.1.9)\n"
)
# Generic Open MPI: no UCX/HCOLL components.
GENERIC_OMPI_INFO = (
    "                 Package: Open MPI\n"
    "                Open MPI: 4.1.6\n"
    "                MCA coll: basic (MCA v2.1.0, Component v4.1.6)\n"
    "                 MCA pml: ob1 (MCA v2.1.0, Component v4.1.6)\n"
)


def detect(mpirun_path: str, mpi_version_line: str, ompi_info_out: str) -> str:
    stubs = {
        "mpirun": f'echo "{mpi_version_line}"',
        "ompi_info": (
            'if [ "$1" = "--version" ]; then\n'
            f'  printf "%s\\n" "{mpi_version_line}"\n'
            "else\n"
            f'  printf %s {shquote(ompi_info_out)}\n'
            "fi"
        ),
    }
    prelude = f'MPIRUN_P="{mpirun_path}"\n'
    run = bashtest.run_bash(prelude + DETECT_CHAIN, stubs=stubs)
    assert run.returncode == 0, run.stderr
    for line in run.stdout.splitlines():
        if line.startswith("WORKER_HPCX_DETECTED="):
            return line.split("=", 1)[1]
    raise AssertionError(f"no WORKER_HPCX_DETECTED in output: {run.stdout!r}")


def shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def test_hpcx_ompi_with_plain_version_is_detected_via_mca() -> None:
    # The regression: plain "Open MPI 4.1.9a1" at /usr/mpi, but UCX+HCOLL MCA
    # components are present -> HPC-X.
    result = detect(
        "/usr/mpi/gcc/openmpi-4.1.9a1/bin/mpirun",
        "mpirun (Open MPI) 4.1.9a1",
        HPCX_OMPI_INFO,
    )
    assert result == "true"


def test_generic_ompi_without_ucx_hcoll_is_not_hpcx() -> None:
    result = detect(
        "/usr/bin/mpirun",
        "mpirun (Open MPI) 4.1.6",
        GENERIC_OMPI_INFO,
    )
    assert result == "false"


def test_explicit_hpcx_version_string_still_detected() -> None:
    result = detect(
        "/opt/hpcx/ompi/bin/mpirun",
        "mpirun (Open MPI) 4.1.9a1 (HPC-X)",
        HPCX_OMPI_INFO,
    )
    assert result == "true"
