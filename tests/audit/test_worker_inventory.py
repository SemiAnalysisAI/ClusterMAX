from __future__ import annotations

from pathlib import Path

import pytest

import bashtest


WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
STANDALONE = WORKLOAD / "cluster-audit-standalone.sh"
PRINT_STUBS = dict.fromkeys(
    ("print_section", "print_info", "print_detail", "print_warn"), ""
)


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


SLURM_GEO_SCRIPT = (
    bashtest.extract_block(
        SLURM,
        "# Geolocation must describe the compute node's egress path.",
        "# Build worker drive config JSON from parsed check variables.",
    )
    + '\nprintf "%s|%s|%s|%s\\n" "$GEO_IP" "$GEO_CITY" '
    '"$GEO_REGION" "$GEO_CHECK_SCOPE"\n'
)


def test_host_check_collects_geolocation_from_the_worker() -> None:
    function = bashtest.extract_function(HOST_CHECK, "collect_worker_geolocation")
    response = (
        "printf '%s\\n' "
        "'{\"ip\":\"203.0.113.8\",\"city\":\"Reno\",\"region\":\"Nevada\","
        "\"country\":\"US\",\"org\":\"AS64500 Example\",\"loc\":\"39.5,-119.8\"}'"
    )
    run = bashtest.run_bash(
        function + "\ncollect_worker_geolocation",
        stubs={"curl": response},
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "WORKER_GEO_CHECK_STATUS=success",
        "WORKER_GEO_IP=203.0.113.8",
        "WORKER_GEO_CITY=Reno",
        "WORKER_GEO_REGION=Nevada",
        "WORKER_GEO_COUNTRY=US",
        "WORKER_GEO_ORG=AS64500 Example",
        "WORKER_GEO_LOC=39.5,-119.8",
    ]
    assert run.calls("curl") == [["-sf", "--max-time", "10", "https://ipinfo.io/json"]]


def test_null_geolocation_fields_are_blank():
    function = bashtest.extract_function(HOST_CHECK, "collect_worker_geolocation")
    run = bashtest.run_bash(
        function + "\ncollect_worker_geolocation",
        stubs={"curl": """printf '%s' '{"ip":"203.0.113.8","city":null,"region":null,"org":null,"loc":null}'"""},
    )
    assert run.returncode == 0, run.stderr
    assert "None" not in run.stdout
    assert "WORKER_GEO_CITY=\n" in run.stdout


@pytest.mark.parametrize(
    ("worker_ok", "status", "geo", "expected"),
    [
        ("true", "success", ("203.0.113.9", "Chicago", "Illinois"), "203.0.113.9|Chicago|Illinois|worker"),
        ("false", "unavailable", ("", "", ""), "|||unverified"),
    ],
    ids=("worker-result", "no-controller-fallback"),
)
def test_slurm_geolocation_scope(
    worker_ok: str, status: str, geo: tuple[str, str, str], expected: str
) -> None:
    ip, city, region = geo
    setup = (
        f"WORKER_CHECK_OK={worker_ok}\nWORKER_GEO_CHECK_STATUS={status}\n"
        f"WORKER_GEO_IP={ip}\nWORKER_GEO_CITY={city}\nWORKER_GEO_REGION={region}\n"
        "WORKER_HOSTNAME=gpu-1\nGEO_CHECK_SCOPE=unverified\n"
    )
    run = bashtest.run_bash(
        setup + SLURM_GEO_SCRIPT,
        stubs={"curl": "printf '{\"ip\":\"198.51.100.1\"}'", **PRINT_STUBS},
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected
    assert run.calls("curl") == []


@pytest.mark.parametrize("running", [True, False], ids=["present", "absent"])
def test_worker_slurmd_detection(running: bool) -> None:
    block = bashtest.extract_block(
        HOST_CHECK, "# --- Slurm worker daemon ---",
        'echo "WORKER_SLURMD_RUNNING=${WORKER_SLURMD_RUNNING}"',
    )
    run = bashtest.run_bash(block, stubs={"pgrep": f"exit {0 if running else 1}"})
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == f"WORKER_SLURMD_RUNNING={str(running).lower()}"
    assert run.calls("pgrep") == [["-x", "slurmd"]]


@pytest.mark.parametrize("visible", ["true", "false"], ids=["visible-process", "hidden-process"])
def test_worker_step_proves_slurmd_without_controller_fallback(visible: str) -> None:
    block = bashtest.extract_block(
        SLURM, "# The compute node is the only valid vantage point for slurmd.",
        "# Geolocation must describe the compute node's egress path.",
    )
    run = bashtest.run_bash(
        "WORKER_CHECK_OK=true; WORKER_HOSTNAME=gpu-1\n"
        f"WORKER_SLURMD_RUNNING={visible}; SLURMD_RUNNING=false; SLURMD_CHECK_SCOPE=unverified\n"
        + block + '\nprintf "%s %s\\n" "$SLURMD_RUNNING" "$SLURMD_CHECK_SCOPE"',
        stubs=PRINT_STUBS,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true worker"
    assert run.calls("print_warn") == []


NHC_SCRIPT = (
    bashtest.extract_block(
        SLURM,
        "# NHC (Node Health Check)",
        "# Monitoring stack detection",
    )
    + '\nprintf "%s|%s|%s|%s\\n" "$NHC_INSTALLED" "$NHC_PATH" '
    '"$NHC_CONF_LINES" "$NHC_CHECK_SCOPE"\n'
)


STUBS = dict.fromkeys(("print_section", "print_info", "print_detail", "nhc"), "")


@pytest.mark.parametrize(
    ("worker_ok", "installed", "path", "checks", "host", "expected"),
    [
        ("true", "false", "none", 0, "gpu-1", "false|none|0|worker"),
        ("true", "true", "/usr/sbin/nhc", 12, "gpu-2", "true|/usr/sbin/nhc|12|worker"),
        ("false", "false", "none", 0, "none", "|head-fallback"),
    ],
    ids=("worker-absent", "worker-configured", "head-fallback"),
)
def test_nhc_scope(worker_ok: str, installed: str, path: str, checks: int, host: str, expected: str) -> None:
    setup = (
        f"WORKER_CHECK_OK={worker_ok}\nWORKER_NHC_INSTALLED={installed}\n"
        f"WORKER_NHC_PATH={path}\nWORKER_NHC_CONF_CHECKS={checks}\nWORKER_HOSTNAME={host}\n"
    )
    run = bashtest.run_bash(setup + NHC_SCRIPT, stubs=STUBS)

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip().endswith(expected)

