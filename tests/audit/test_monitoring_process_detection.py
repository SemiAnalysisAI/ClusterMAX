"""Behavioral tests for the DCGM Exporter detection block.

Executes the real detection block from the slurm and standalone collectors
with stubbed ss, systemctl, and pgrep instead of pinning source fragments.

"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

COLLECTORS = ("cluster-audit-slurm.sh", "cluster-audit-standalone.sh")

# print_* are shell functions in the full collector; stub them as executables
# so the extracted block runs standalone.
PRINT_STUBS = {"print_section": "", "print_info": "", "print_detail": ""}

REPORT = '\nprintf "dcgm=%s\\n" "$DCGM_EXPORTER_DETECTED"'


def detection_block(collector: str) -> str:
    return bashtest.extract_block(
        WORKLOAD / collector,
        "# Monitoring stack detection:",
        "if pgrep -x grafana",
    )


@pytest.mark.parametrize("collector", COLLECTORS)
def test_absent_dcgm_exporter_is_not_detected(collector: str) -> None:
    run = bashtest.run_bash(
        detection_block(collector) + REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": "exit 0",
            "systemctl": "exit 1",
            "pgrep": "exit 1",
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=false"


@pytest.mark.parametrize("collector", COLLECTORS)
def test_listening_port_detects_dcgm_exporter(collector: str) -> None:
    listing = (
        "State Recv-Q Send-Q Local:Port Peer\n"
        "LISTEN 0 128 0.0.0.0:9400 users\n"
    )
    run = bashtest.run_bash(
        detection_block(collector) + REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": f"cat <<'SS_EOF'\n{listing}SS_EOF",
            "systemctl": "exit 1",
            "pgrep": "exit 1",
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=true"
