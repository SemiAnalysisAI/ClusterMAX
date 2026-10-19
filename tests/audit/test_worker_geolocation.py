from __future__ import annotations

from pathlib import Path

import pytest

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
SLURM_GEO_SCRIPT = (
    bashtest.extract_block(
        SLURM,
        "# Geolocation must describe the compute node's egress path.",
        "# Build worker drive config JSON from parsed check variables.",
    )
    + '\nprintf "%s|%s|%s|%s\\n" "$GEO_IP" "$GEO_CITY" '
    '"$GEO_REGION" "$GEO_CHECK_SCOPE"\n'
)
PRINT_STUBS = dict.fromkeys(
    ("print_section", "print_info", "print_detail", "print_warn"), ""
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
