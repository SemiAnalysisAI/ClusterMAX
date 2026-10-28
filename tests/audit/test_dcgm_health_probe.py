"""The DCGM health-watches probe must be read-only.

``dcgmi health -g 0 -s a`` SETS every DCGM health watch on a node, including
watches for subsystems that may not be deployed (the IMEX daemon on the GB300
cluster). A site health checker that polls DCGM health then reports a failure
and drains the node. The audit probe must query the current watch state and
must never set or clear watches.
"""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"

WATCH_TABLE_ON = """Health monitor systems report
+-----------------+--------------------------------------------------------------------+
| PCIe            | On                                                                 |
| NVLINK          | On                                                                 |
| IMEX            | Off                                                                |
"""

WATCH_TABLE_OFF = """Health monitor systems report
+-----------------+--------------------------------------------------------------------+
| PCIe            | Off                                                                |
| NVLINK          | Off                                                                |
| IMEX            | Off                                                                |
"""

PRINT_STUBS = {
    "print_section": "",
    "print_info": "",
    "print_warn": "",
    "print_detail": "",
}


def dcgmi_stub(watch_output: str, rc: int = 0) -> str:
    lines = " ".join(f"'{line}'" for line in watch_output.splitlines())
    return (
        'if [[ "$1" == "health" ]]; then\n'
        f"    printf '%s\\n' {lines}\n"
        f"    exit {rc}\n"
        "fi\n"
        "exit 0\n"
    )


def run_probe(dcgmi_body: str) -> bashtest.BashRun:
    block = bashtest.extract_block(
        HOST_CHECK,
        "# Read-only DCGM health-watches probe",
        "timeout 60 dcgmi diag -r 1",
    )
    return bashtest.run_bash(block, stubs={"dcgmi": dcgmi_body})


def values(run: bashtest.BashRun) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in run.stdout.splitlines() if "=" in line
    )


def assert_never_sets_watches(run: bashtest.BashRun) -> None:
    for argv in run.calls("dcgmi"):
        assert "-s" not in argv, f"probe must not set watches: {argv}"
        assert "--set" not in argv, f"probe must not set watches: {argv}"
        assert "--clear" not in argv, f"probe must not clear watches: {argv}"
    assert any(
        argv == ["health", "-g", "0", "-f"] for argv in run.calls("dcgmi")
    ), "probe must fetch the current watch state with 'dcgmi health -g 0 -f'"


def test_active_watches_report_ok():
    run = run_probe(dcgmi_stub(WATCH_TABLE_ON))
    assert run.returncode == 0, run.stderr
    v = values(run)
    assert v["WORKER_DCGM_HEALTH_OK"] == "true"
    assert v["WORKER_DCGM_HEALTH_QUERY"] == "active-watches"
    assert_never_sets_watches(run)


def test_no_active_watches_report_not_enabled():
    run = run_probe(dcgmi_stub(WATCH_TABLE_OFF))
    assert run.returncode == 0, run.stderr
    v = values(run)
    assert v["WORKER_DCGM_HEALTH_OK"] == "false"
    assert v["WORKER_DCGM_HEALTH_QUERY"] == "no-watches"
    assert_never_sets_watches(run)


def test_failed_watch_query_reports_query_failure():
    run = run_probe(dcgmi_stub(WATCH_TABLE_ON, rc=1))
    assert run.returncode == 0, run.stderr
    v = values(run)
    assert v["WORKER_DCGM_HEALTH_OK"] == "false"
    assert v["WORKER_DCGM_HEALTH_QUERY"] == "failed"
    assert_never_sets_watches(run)


def consumer_block(collector: str) -> str:
    return bashtest.extract_block(
        WORKLOAD / collector,
        'if [[ "$WORKER_DCGM_HEALTH_OK" == "true" ]]; then',
        'case "$DCGM_DIAG_R1" in',
    )


def run_consumer(collector: str, ok: str, query: str) -> bashtest.BashRun:
    setup = (
        f"WORKER_DCGM_HEALTH_OK={ok}\n"
        f"WORKER_DCGM_HEALTH_QUERY={query}\n"
        "DCGM_HEALTH_WATCHES_ENABLED=false\n"
        "DCGM_DIAG_R1=pass\n"
        "DCGM_DIAG_R2=skipped\n"
        "set +e\n"
    )
    return bashtest.run_bash(
        setup + consumer_block(collector) + "\nesac\n", stubs=PRINT_STUBS
    )


def test_collectors_distinguish_watch_states():
    for collector in ("cluster-audit-slurm.sh", "cluster-audit-standalone.sh"):
        active = run_consumer(collector, "true", "active-watches")
        assert active.returncode == 0, active.stderr
        assert active.calls("print_info") == [
            ["DCGM health watches: Active on compute node (dcgmi health -g 0 -f)"]
        ], collector

        failed = run_consumer(collector, "false", "failed")
        assert failed.returncode == 0, failed.stderr
        assert failed.calls("print_warn") == [
            [
                "DCGM health watches: Could not read watch status on compute "
                "node (dcgmi health -g 0 -f failed)"
            ]
        ], collector

        none = run_consumer(collector, "false", "no-watches")
        assert none.returncode == 0, none.stderr
        assert none.calls("print_warn") == [
            [
                "DCGM health watches: Not enabled on compute node "
                "(no active DCGM health watches)"
            ]
        ], collector
