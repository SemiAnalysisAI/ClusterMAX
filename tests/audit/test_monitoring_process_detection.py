"""Worker, service and endpoint evidence for monitoring detection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit"
)

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = SCRIPT_DIR
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

COLLECTORS = ("cluster-audit-slurm.sh", "cluster-audit-standalone.sh")

PRINT_STUBS = {"print_section": "", "print_info": "", "print_detail": "", "curl": "exit 7"}

REPORT = (
    '\nprintf "prom=%s dcgm=%s node=%s grafana=%s head=%s worker=%s\\n" '
    '"$PROMETHEUS_DETECTED" "$DCGM_EXPORTER_DETECTED" '
    '"$NODE_EXPORTER_DETECTED" "$GRAFANA_DETECTED" '
    '"${GRAFANA_HEAD_NODE_DETECTED:-unknown}" '
    '"${GRAFANA_WORKER_NODE_DETECTED:-unknown}"'
)


def detection_block(collector: str) -> str:
    end_anchor = (
        "# Record every metrics/dashboard query endpoint"
        if collector == "cluster-audit-slurm.sh"
        else "if pgrep -x grafana"
    )
    return bashtest.extract_block(
        WORKLOAD / collector,
        "# Monitoring stack detection:",
        end_anchor,
    )


@pytest.mark.parametrize("collector", COLLECTORS)
def test_grafana_without_systemd_is_detected_via_comm_name(collector: str) -> None:
    run = bashtest.run_bash(
        detection_block(collector) + REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": "exit 0",  # no listening sockets visible
            "systemctl": "exit 1",  # no grafana-server unit
            "pgrep": '[[ "$1" == -x && "$2" == grafana ]] && exit 0\nexit 1',
        },
    )
    assert run.returncode == 0, run.stderr
    assert "grafana=true" in run.stdout
    if collector == "cluster-audit-slurm.sh":
        assert "head=true" in run.stdout
    assert run.calls("pgrep")[0] == ["-x", "grafana"]


@pytest.mark.parametrize("collector", COLLECTORS)
def test_nothing_running_detects_nothing(collector: str) -> None:
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
    expected = (
        "prom=unknown dcgm=unknown node=unknown grafana=unknown head=false worker=unknown"
        if collector == "cluster-audit-slurm.sh"
        else "prom=false dcgm=false node=false grafana=false head=unknown worker=unknown"
    )
    assert run.stdout.strip() == expected


@pytest.mark.parametrize("collector", COLLECTORS)
def test_listening_ports_detect_visible_monitoring_services(collector: str) -> None:
    listing = (
        "State Recv-Q Send-Q Local:Port Peer\n"
        "LISTEN 0 128 0.0.0.0:9090 users\n"
        "LISTEN 0 128 0.0.0.0:9400 users\n"
        "LISTEN 0 128 127.0.0.1:3000 users\n"
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
    expected = (
        "prom=true dcgm=unknown node=unknown grafana=true head=true worker=unknown"
        if collector == "cluster-audit-slurm.sh"
        else "prom=true dcgm=true node=false grafana=true head=unknown worker=unknown"
    )
    assert run.stdout.strip() == expected


def run_slurm_worker_detection(
    scope: str, dcgm: str, node: str, grafana: str
) -> tuple[str, ...]:
    setup = f"""WORKER_CHECK_OK=true
WORKER_MONITORING_CHECK_OK=true
WORKER_CONTAINER_RUNTIME_SCOPE={scope}
WORKER_DCGM_EXPORTER_DETECTED={dcgm}
WORKER_NODE_EXPORTER_DETECTED={node}
WORKER_GRAFANA_DETECTED={grafana}
"""
    run = bashtest.run_bash(
        setup + detection_block("cluster-audit-slurm.sh") + REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": "exit 0",
            "systemctl": "exit 1",
            "pgrep": "exit 1",
        },
    )
    assert run.returncode == 0, run.stderr
    return tuple(part.split("=", 1)[1] for part in run.stdout.split())


@pytest.mark.parametrize(
    ("scope", "dcgm", "node", "grafana", "expected"),
    (
        ("host", "true", "true", "true", ("unknown", "true", "true", "true", "false", "true")),
        ("nested-container", "false", "false", "true", ("unknown", "unknown", "unknown", "true", "false", "true")),
        ("host", "false", "false", "false", ("unknown", "false", "false", "unknown", "false", "false")),
    ),
)
def test_slurm_worker_scope_controls_monitoring_status(
    scope: str, dcgm: str, node: str, grafana: str, expected: tuple[str, ...]
) -> None:
    assert run_slurm_worker_detection(scope, dcgm, node, grafana) == expected


def test_slurm_reports_one_status_for_each_detected_exporter() -> None:
    status_block = bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        "# Report exactly one status for each monitoring component.",
        "# Auto-remediation:",
    )
    setup = (
        "PROMETHEUS_DETECTED=unknown; DCGM_EXPORTER_DETECTED=true; "
        "NODE_EXPORTER_DETECTED=true; GRAFANA_DETECTED=unknown; "
        "DCGM_EXPORTER_EVIDENCE='on compute node worker-1'; "
        "GRAFANA_HEAD_NODE_DETECTED=false; GRAFANA_WORKER_NODE_DETECTED=unknown; "
        "SLURM_EXPORTER_DETECTED=false; WORKER_HOSTNAME=worker-1\n"
    )
    run = bashtest.run_bash(setup + status_block, stubs=PRINT_STUBS)
    assert run.returncode == 0, run.stderr
    assert run.calls("print_info") == [
        ["dcgm-exporter: detected on compute node worker-1"],
        ["node-exporter: detected on compute node worker-1"],
    ]
    assert run.calls("print_detail") == [
        ["Prometheus: not visible from tenant nodes; provider verification required"],
        ["Grafana: not visible from tenant nodes; provider verification required"],
        ["Grafana placement: head=false, worker=unknown"],
    ]


def run_worker_monitoring(ss_body: str, pgrep_body: str = "exit 1") -> bashtest.BashRun:
    block = bashtest.extract_block(
        WORKLOAD / "host-check.sh",
        "# --- Monitoring services ---",
        'echo "WORKER_GRAFANA_DETECTED=${WORKER_GRAFANA_DETECTED}"',
    )
    run = bashtest.run_bash(
        block,
        stubs={"ss": ss_body, "systemctl": "exit 1", "pgrep": pgrep_body},
    )
    assert run.returncode == 0, run.stderr
    return run


@pytest.mark.parametrize(
    ("ss_body", "expected"),
    (
        (
            "printf 'State Header\\nLISTEN 0 128 0.0.0.0:9400 peer\\n"
            "LISTEN 0 128 0.0.0.0:9100 peer\\n"
            "LISTEN 0 128 0.0.0.0:3000 peer\\n'",
            ("true", "true", "true", "true"),
        ),
        ("exit 1", ("false", "false", "false", "false")),
    ),
)
def test_worker_exporter_check(
    ss_body: str, expected: tuple[str, str, str, str]
) -> None:
    run = run_worker_monitoring(ss_body)
    assert tuple(line.split("=", 1)[1] for line in run.stdout.splitlines()) == expected


def test_worker_grafana_process_requires_an_exact_comm_name() -> None:
    run = run_worker_monitoring(
        "exit 1",
        '[[ "$2" == "grafana|grafana-server" ]] && exit 0\nexit 1',
    )

    assert "WORKER_GRAFANA_DETECTED=false" in run.stdout
    assert ["-x", "grafana"] in run.calls("pgrep")
    assert ["-x", "grafana-server"] in run.calls("pgrep")


COMMON = WORKLOAD / "audit-common.sh"

EVIDENCE_SOURCE = (
    bashtest.extract_block(
        COMMON,
        "# Query and user-interface ports of multi-tenant metrics backends",
        'CMAX_MONITORING_PROCESSES="prometheus:prometheus',
    )
    + bashtest.extract_function(COMMON, "_cmax_list_add")
    + bashtest.extract_function(COMMON, "_cmax_json_array_body")
    + bashtest.extract_function(COMMON, "collect_monitoring_evidence")
)

EVIDENCE_REPORT = (
    '\nprintf "endpoints=[%s] platforms=[%s]\\n" '
    '"$MONITORING_ENDPOINTS" "$MONITORING_PLATFORMS"'
)


def run_evidence(listening: str, pgrep_body: str = "exit 1") -> bashtest.BashRun:
    return bashtest.run_bash(
        EVIDENCE_SOURCE
        + f'\ncollect_monitoring_evidence "$(cat <<\'LISTEN_EOF\'\n{listening}LISTEN_EOF\n)"'
        + EVIDENCE_REPORT,
        stubs={**PRINT_STUBS, "pgrep": pgrep_body},
    )


class TestMonitoringEvidence:
    def test_query_ports_are_recorded_as_checkable_addresses(self) -> None:
        run = run_evidence("0.0.0.0:9090\n127.0.0.1:3000\n")
        assert run.returncode == 0, run.stderr
        assert '"127.0.0.1:9090"' in run.stdout
        assert '"127.0.0.1:3000"' in run.stdout
        assert '"prometheus"' in run.stdout
        assert '"grafana"' in run.stdout

    def test_exporter_ports_are_platform_evidence_and_never_endpoints(self) -> None:
        run = run_evidence("0.0.0.0:9400\n0.0.0.0:9100\n")
        assert run.returncode == 0, run.stderr
        assert "endpoints=[]" in run.stdout
        assert '"dcgm-exporter"' in run.stdout
        assert '"node-exporter"' in run.stdout

    def test_full_ss_rows_parse_and_the_peer_column_is_ignored(self) -> None:
        listing = (
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "LISTEN 0 128 10.0.0.5:9090 0.0.0.0:*\n"
        )
        run = run_evidence(listing)
        assert run.returncode == 0, run.stderr
        assert 'endpoints=["10.0.0.5:9090"]' in run.stdout

    def test_repeated_addresses_are_recorded_once(self) -> None:
        run = run_evidence("0.0.0.0:9090\n*:9090\n[::]:9090\n")
        assert run.returncode == 0, run.stderr
        assert 'endpoints=["127.0.0.1:9090"]' in run.stdout
        assert 'platforms=["prometheus"]' in run.stdout

    def test_process_only_backend_is_recorded_as_a_platform(self) -> None:
        run = run_evidence("", pgrep_body='[[ "$2" == grafana* ]] && exit 0\nexit 1')
        assert run.returncode == 0, run.stderr
        assert 'platforms=["grafana"]' in run.stdout

    def test_build_suffixed_and_truncated_binaries_are_matched(self) -> None:
        pgrep = (
            'name="$2"\n'
            'printf "%s\\n" victoria-metric vmselect-prod '
            '| grep -qE "^${name}$" && exit 0\n'
            "exit 1"
        )
        run = run_evidence("", pgrep_body=pgrep)
        assert run.returncode == 0, run.stderr
        assert '"victoriametrics"' in run.stdout
        assert '"vmselect"' in run.stdout

    def test_a_truncated_exporter_name_is_not_matched(self) -> None:
        pgrep = (
            'name="$2"\n'
            'printf "%s\\n" prometheus-node | grep -qE "^${name}$" && exit 0\n'
            "exit 1"
        )
        run = run_evidence("", pgrep_body=pgrep)
        assert run.returncode == 0, run.stderr
        assert run.stdout.strip() == "endpoints=[] platforms=[]"

    def test_nothing_listening_records_nothing(self) -> None:
        run = run_evidence("")
        assert run.returncode == 0, run.stderr
        assert run.stdout.strip() == "endpoints=[] platforms=[]"


SERVICE_URL = "http://nvidia-dcgm-exporter.gpu-operator.svc:9400/metrics"
POD_RESOLV = "search slurm.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\n"
HOST_RESOLV = "search example.internal\nnameserver 10.0.0.2\n"
DCGM_METRICS = 'DCGM_FI_DEV_GPU_TEMP{gpu="0"} 41\n'

def service_probe_block() -> str:
    return (
        EVIDENCE_SOURCE
        + bashtest.extract_function(COMMON, "worker_monitoring_addresses")
        + bashtest.extract_block(
            WORKLOAD / "cluster-audit-slurm.sh",
            "# Monitoring stack detection:",
            "# Auto-remediation:",
        )
    )

def run_service_probe(
    tmp_path: Path, resolv: str, curl: str, env: dict[str, str] | None = None
) -> bashtest.BashRun:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(resolv)
    return bashtest.run_bash(
        service_probe_block() + REPORT + EVIDENCE_REPORT,
        stubs={
            **PRINT_STUBS,
            "ss": 'printf "%b" "${SERVICE_TEST_LISTENING:-}"',
            "systemctl": "exit 1",
            "pgrep": "exit 1",
            "curl": curl,
        },
        env={"CLUSTERMAX_RESOLV_CONF": str(resolv_conf), **(env or {})},
    )

def test_pod_head_node_detects_exporter_service(tmp_path: Path) -> None:
    run = run_service_probe(tmp_path, POD_RESOLV, f"printf '{DCGM_METRICS}'")
    assert run.returncode == 0, run.stderr
    assert "dcgm=true" in run.stdout
    assert run.calls("curl")[0][-1] == SERVICE_URL
    assert ["dcgm-exporter: detected via DCGM metrics at " + SERVICE_URL] in run.calls("print_info")
    assert 'platforms=["dcgm-exporter"]' in run.stdout
    assert "endpoints=[]" in run.stdout
    assert sum("dcgm-exporter:" in call[0] for call in run.calls("print_info")) == 1

@pytest.mark.parametrize(
    "curl",
    ["printf 'node_load1 0.5\\n'", "exit 7"],
    ids=["not-dcgm-metrics", "unreachable"],
)
def test_service_without_dcgm_metrics_is_not_detected(tmp_path: Path, curl: str) -> None:
    run = run_service_probe(tmp_path, POD_RESOLV, curl)
    assert run.returncode == 0, run.stderr
    assert "dcgm=unknown" in run.stdout

def test_bare_metal_head_node_does_not_query_service(tmp_path: Path) -> None:
    run = run_service_probe(tmp_path, HOST_RESOLV, f"printf '{DCGM_METRICS}'")
    assert run.returncode == 0, run.stderr
    assert "dcgm=unknown" in run.stdout
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
    assert "dcgm=true" in run.stdout
    assert run.calls("curl")[0][-1] == url


@pytest.mark.parametrize("exporter_listener", [False, True], ids=["append", "deduplicate"])
def test_service_preserves_existing_backend_platform_and_query_endpoint(
    tmp_path: Path, exporter_listener: bool
) -> None:
    run = run_service_probe(
        tmp_path,
        POD_RESOLV,
        f"printf '{DCGM_METRICS}'",
        env={
            "SERVICE_TEST_LISTENING": (
                "State Header\nLISTEN 0 128 127.0.0.1:9090 peer\n"
            ) + ("LISTEN 0 128 127.0.0.1:9400 peer\n" if exporter_listener else ""),
        },
    )
    assert run.returncode == 0, run.stderr
    evidence = run.stdout.splitlines()[-1]
    endpoint_json, platform_json = evidence.removeprefix("endpoints=").split(" platforms=")
    assert json.loads(endpoint_json) == ["127.0.0.1:9090"]
    assert json.loads(platform_json) == ["prometheus", "dcgm-exporter"]


@pytest.mark.parametrize(
    ("curl", "expected"),
    [(f"printf '{DCGM_METRICS}'", "true"), ("exit 7", "false")],
    ids=["verified-service", "unreachable-service"],
)
def test_service_evidence_combines_with_a_negative_worker_host_scan(
    tmp_path: Path, curl: str, expected: str
) -> None:
    run = run_service_probe(
        tmp_path,
        POD_RESOLV,
        curl,
        env={
            "WORKER_CHECK_OK": "true",
            "WORKER_MONITORING_CHECK_OK": "true",
            "WORKER_CONTAINER_RUNTIME_SCOPE": "host",
            "WORKER_DCGM_EXPORTER_DETECTED": "false",
            "WORKER_NODE_EXPORTER_DETECTED": "false",
            "WORKER_GRAFANA_DETECTED": "false",
        },
    )
    assert run.returncode == 0, run.stderr
    assert f"dcgm={expected}" in run.stdout


def test_worker_sockets_reach_controller_evidence_without_loopback_substitution():
    worker = bashtest.run_bash(
        bashtest.extract_block(WORKLOAD / "host-check.sh", "# --- Monitoring services ---", "# --- DCGM ---"),
        stubs={
            "ss": """printf 'State Recv-Q Send-Q Local:Port Peer
LISTEN 0 128 0.0.0.0:3000 0.0.0.0:*
LISTEN 0 128 10.0.0.9:9090 0.0.0.0:*
LISTEN 0 128 127.0.0.1:8428 0.0.0.0:*
LISTEN 0 128 [::1]:8481 [::]:*
'""",
            "systemctl": "exit 1", "pgrep": "exit 1",
        },
    )
    assert worker.returncode == 0, worker.stderr
    values = dict(line.split("=", 1) for line in worker.stdout.splitlines())
    source = EVIDENCE_SOURCE + bashtest.extract_function(COMMON, "worker_monitoring_addresses")
    call = bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        "# Record every metrics/dashboard query endpoint", "# Report exactly one status",
    )
    run = bashtest.run_bash(
        source + call + '\nprintf "[%s]" "$MONITORING_ENDPOINTS"',
        env={**values, "WORKER_HOSTNAME": "gpu-worker", "LISTENING": "127.0.0.1:9090"},
        stubs={"pgrep": "exit 1", "print_detail": ""},
    )
    assert run.returncode == 0, run.stderr
    assert set(json.loads(run.stdout)) == {
        "127.0.0.1:9090", "gpu-worker:3000", "10.0.0.9:9090",
    }


def test_worker_ipv6_and_wildcard_scope():
    run = bashtest.run_bash(
        bashtest.extract_function(COMMON, "worker_monitoring_addresses")
        + '\nworker_monitoring_addresses "$SOCKETS" gpu-worker',
        env={"SOCKETS": "[::]:3000|:::9090|[2001:db8::9]:8428|::1:9090|*:8481"},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "gpu-worker:3000", "gpu-worker:9090", "[2001:db8::9]:8428", "gpu-worker:8481",
    ]
