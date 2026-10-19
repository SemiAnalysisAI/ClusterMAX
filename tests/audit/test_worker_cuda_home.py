from __future__ import annotations

from pathlib import Path

import pytest

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
STANDALONE = WORKLOAD / "cluster-audit-standalone.sh"
CUDA_REPORT = (
    '\nprintf "%s|%s|%s\\n" "$CUDA_HOME_VAL" '
    '"$CUDA_HOME_SOURCE" "$CUDA_HOME_EXISTS"\n'
)
WORKER_CUDA_SCRIPT = (
    bashtest.extract_function(HOST_CHECK, "collect_worker_cuda_home")
    + "\ncollect_worker_cuda_home"
)
SLURM_CUDA_SCRIPT = bashtest.extract_block(
    SLURM, 'CUDA_HOME_VAL="none"', "# NVIDIA HPC SDK"
) + CUDA_REPORT
STANDALONE_CUDA_SCRIPT = bashtest.extract_block(
    STANDALONE, 'CUDA_HOME_VAL="${CUDA_HOME:-}"', "# NVIDIA HPC SDK"
) + CUDA_REPORT
PRINT_STUBS = dict.fromkeys(("print_info", "print_detail", "print_warn"), "")


@pytest.mark.parametrize(
    ("use_environment", "expected_source"),
    [(True, "environment"), (False, "canonical-path")],
    ids=("environment", "canonical-path"),
)
def test_worker_cuda_home_selection(
    tmp_path: Path, use_environment: bool, expected_source: str
) -> None:
    canonical = tmp_path / "cuda-canonical"
    canonical.mkdir()
    environment = tmp_path / "cuda-env"
    if use_environment:
        environment.mkdir()
    expected_path = environment if use_environment else canonical
    run = bashtest.run_bash(
        WORKER_CUDA_SCRIPT,
        env={
            "CUDA_HOME": str(environment) if use_environment else "",
            "CLUSTERMAX_CUDA_CANONICAL_DIR": str(canonical),
        },
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        f"WORKER_CUDA_HOME={expected_path}",
        f"WORKER_CUDA_HOME_SOURCE={expected_source}",
        "WORKER_CUDA_HOME_EXISTS=true",
    ]


def test_slurm_collector_does_not_use_the_controller_cuda_home() -> None:
    setup = (
        "WORKER_CHECK_OK=true; WORKER_CUDA_HOME=/worker/cuda; "
        "WORKER_CUDA_HOME_SOURCE=environment; WORKER_CUDA_HOME_EXISTS=true; "
        "WORKER_HOSTNAME=gpu-1; CUDA_HOME=/controller/cuda\n"
    )
    run = bashtest.run_bash(
        setup + SLURM_CUDA_SCRIPT,
        stubs=PRINT_STUBS,
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "/worker/cuda|environment|true"


@pytest.mark.parametrize("exists", [True, False], ids=("exists", "missing"))
def test_standalone_cuda_home(tmp_path: Path, exists: bool) -> None:
    cuda_home = tmp_path / "cuda"
    if exists:
        cuda_home.mkdir()
    run = bashtest.run_bash(
        STANDALONE_CUDA_SCRIPT,
        env={
            "CUDA_HOME": str(cuda_home) if exists else "",
            "CLUSTERMAX_CUDA_CANONICAL_DIR": str(cuda_home),
        },
        stubs=PRINT_STUBS,
    )

    assert run.returncode == 0, run.stderr
    expected = f"{cuda_home}|environment|true" if exists else "none|not-found|false"
    assert run.stdout.strip() == expected
