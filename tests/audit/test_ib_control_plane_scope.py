from __future__ import annotations

from pathlib import Path

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
WORKER_BLOCK = bashtest.extract_block(
    HOST_CHECK,
    "# --- InfiniBand control-plane queries ---",
    'echo "WORKER_IB_SM_KEY_CHECK_SCOPE=${WORKER_IB_SM_KEY_CHECK_SCOPE}"',
)
COLLECTOR_BLOCK = bashtest.extract_block(
    SLURM,
    'SAQUERY_OUT="${WORKER_SAQUERY_NODE_RECORDS:-0}"',
    "# SHARP check",
)
COLLECTOR_REPORT = (
    '\nprintf "%s|%s|%s|%s\\n" "$SAQUERY_OUT" "$IB_SM_KEY_CONFIGURED" '
    '"$IB_SM_KEY_STATUS" "$IB_SM_KEY_CHECK_SCOPE"\n'
)
PRINT_STUBS = dict.fromkeys(
    ("print_section", "print_info", "print_detail", "print_warn"), ""
)


def run_worker(stubs: dict[str, str], env: dict[str, str] | None = None) -> bashtest.BashRun:
    run = bashtest.run_bash(
        WORKER_BLOCK,
        env=env,
        stubs={**stubs, "timeout": 'shift; "$@"'},
    )
    assert run.returncode == 0, run.stderr
    return run


def run_collector(setup: str) -> bashtest.BashRun:
    run = bashtest.run_bash(
        setup + COLLECTOR_BLOCK + COLLECTOR_REPORT,
        stubs={
            **PRINT_STUBS,
            "saquery": "exit 99",
            "sminfo": "exit 99",
            "pgrep": "exit 99",
        },
    )
    assert run.returncode == 0, run.stderr
    assert all(run.calls(command) == [] for command in ("saquery", "sminfo", "pgrep"))
    return run


def test_worker_queries_the_sa_and_sm_without_claiming_remote_key_state() -> None:
    run = run_worker(
        {
            "saquery": "printf 'NodeDescription A\\nNodeDescription B\\n'",
            "sminfo": "printf 'sminfo: sm lid 7\\n'",
            "pgrep": "exit 1",
        }
    )

    values = dict(line.split("=", 1) for line in run.stdout.splitlines())
    keys = ("WORKER_SAQUERY_STATUS", "WORKER_SAQUERY_NODE_RECORDS", "WORKER_SMINFO_STATUS", "WORKER_SM_LID", "WORKER_IB_SM_KEY_CONFIGURED", "WORKER_IB_SM_KEY_STATUS", "WORKER_IB_SM_KEY_CHECK_SCOPE")
    assert tuple(values[key] for key in keys) == (
        "pass", "2", "pass", "7", "unknown", "unverified", "remote-sm-unavailable"
    )
    assert run.calls("saquery") == [["NodeRecord"]]
    assert run.calls("sminfo") == [[]]


def test_local_subnet_manager_configuration_can_prove_a_nonzero_key(tmp_path: Path) -> None:
    config = tmp_path / "opensm.conf"
    config.write_text("sm_key 0x123456789abcdef0\n")
    run = run_worker(
        {
            "saquery": "exit 1",
            "sminfo": "exit 1",
            "pgrep": "exit 0",
        },
        env={"CLUSTERMAX_OPENSM_CONF": str(config)},
    )

    values = dict(line.split("=", 1) for line in run.stdout.splitlines())
    keys = ("WORKER_OPENSM_RUNNING", "WORKER_IB_SM_KEY_CONFIGURED", "WORKER_IB_SM_KEY_STATUS", "WORKER_IB_SM_KEY_CHECK_SCOPE")
    assert tuple(values[key] for key in keys) == (
        "true", "true", "configured", "local-subnet-manager"
    )


def test_collector_uses_worker_results_without_local_fabric_queries() -> None:
    setup = (
        "WORKER_SAQUERY_NODE_RECORDS=9; WORKER_SAQUERY_STATUS=pass; WORKER_SMINFO_STATUS=pass; WORKER_SM_LID=4; "
        "WORKER_IB_SM_KEY_CONFIGURED=unknown; WORKER_IB_SM_KEY_STATUS=unverified; "
        "WORKER_IB_SM_KEY_CHECK_SCOPE=remote-sm-unavailable; WORKER_HOSTNAME=gpu-1\n"
    )
    run = run_collector(setup)

    assert run.stdout.strip() == "9|unknown|unverified|remote-sm-unavailable"


def test_collector_reports_missing_sm_query_as_detail() -> None:
    setup = (
        "WORKER_SAQUERY_STATUS=not-found; WORKER_SMINFO_STATUS=not-found; "
        "WORKER_IB_SM_KEY_CONFIGURED=unknown; WORKER_IB_SM_KEY_STATUS=unverified; "
        "WORKER_IB_SM_KEY_CHECK_SCOPE=worker-tool-unavailable; WORKER_HOSTNAME=gpu-1\n"
    )
    run = run_collector(setup)

    assert run.calls("print_warn") == []
    assert any("SM query was not available" in " ".join(call) for call in run.calls("print_detail"))
