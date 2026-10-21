"""Behavioral tests for the DCGM Exporter detection block."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

COLLECTORS = ("cluster-audit-slurm.sh", "cluster-audit-standalone.sh")

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

SERVICE_URL = "http://nvidia-dcgm-exporter.gpu-operator.svc:9400/metrics"
POD_RESOLV = "search slurm.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\n"
HOST_RESOLV = "search example.internal\nnameserver 10.0.0.2\n"
DCGM_METRICS = 'DCGM_FI_DEV_GPU_TEMP{gpu="0"} 41\n'

def service_probe_block() -> str:
    return bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        "# Monitoring stack detection:",
        '[[ "$DCGM_EXPORTER_DETECTED" == "true" ]] && print_info',
    )

def run_service_probe(
    tmp_path: Path, resolv: str, curl: str, env: dict[str, str] | None = None
) -> bashtest.BashRun:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(resolv)
    return bashtest.run_bash(
        service_probe_block() + REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": "exit 0",
            "systemctl": "exit 1",
            "pgrep": "exit 1",
            "curl": curl,
        },
        env={"CLUSTERMAX_RESOLV_CONF": str(resolv_conf), **(env or {})},
    )

def test_pod_head_node_detects_exporter_service(tmp_path: Path) -> None:
    run = run_service_probe(tmp_path, POD_RESOLV, f"printf '{DCGM_METRICS}'")
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=true"
    assert run.calls("curl")[0][-1] == SERVICE_URL
    assert ["dcgm-exporter: detected (DCGM metrics at " + SERVICE_URL + ")"] in run.calls("print_info")

@pytest.mark.parametrize(
    "curl",
    ["printf 'node_load1 0.5\\n'", "exit 7"],
    ids=["not-dcgm-metrics", "unreachable"],
)
def test_service_without_dcgm_metrics_is_not_detected(tmp_path: Path, curl: str) -> None:
    run = run_service_probe(tmp_path, POD_RESOLV, curl)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=false"

def test_bare_metal_head_node_does_not_query_service(tmp_path: Path) -> None:
    run = run_service_probe(tmp_path, HOST_RESOLV, f"printf '{DCGM_METRICS}'")
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=false"
    assert run.calls("curl") == []

def test_exporter_url_override_is_queried(tmp_path: Path) -> None:
    url = "http://dcgm-exporter.monitoring.svc:9400/metrics"
    run = run_service_probe(
        tmp_path,
        HOST_RESOLV,
        f"printf '{DCGM_METRICS}'",
        env={"CLUSTERMAX_DCGM_EXPORTER_URL": url},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dcgm=true"
    assert run.calls("curl")[0][-1] == url
