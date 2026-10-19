import json
from pathlib import Path
import bashtest

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"
COMMON = WORKLOAD / "audit-common.sh"


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
    source = bashtest.extract_block(
        COMMON, "# Query and user-interface ports of multi-tenant metrics backends",
        'CMAX_MONITORING_PROCESSES="prometheus:prometheus',
    ) + "".join(bashtest.extract_function(COMMON, name) for name in (
        "_cmax_list_add", "_cmax_json_array_body", "collect_monitoring_evidence",
        "worker_monitoring_addresses",
    ))
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
