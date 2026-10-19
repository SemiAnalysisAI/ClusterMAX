from __future__ import annotations

import json
from pathlib import Path

import pytest

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
COMMON = WORKLOAD / "audit-common.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
TWO_WORKERS = [
    {"name": "gpu-a", "state": "IDLE", "gpus": 8},
    {"name": "gpu-b", "state": "IDLE", "gpus": 8},
]
EXPECTED_SRUN_CALL = [
    "--immediate=10", "-w", "gpu-a", "-N1", "--ntasks=1", "--gres=gpu:1",
    "--time=1:00", "bash", "-s", "--", "gpu-b",
]
PRINT_STUBS = dict.fromkeys(
    ("print_section", "print_detail", "print_info", "print_error", "print_warn"),
    "",
)
PROBE_SCRIPT = (
    bashtest.extract_function(COMMON, "select_worker_ssh_nodes")
    + "\nWORKER_HOSTNAME=gpu-a\nAUDIT_SRUN_FLAGS=()\nGPU_SRUN_SCOPE_ARGS=()\n"
    + bashtest.extract_block(
        SLURM,
        'print_section "Worker-to-Worker SSH"',
        'print_section "Accounting"',
    )
    + '\nprintf "%s|%s|%s|%s|%s\\n" "$SSH_TO_COMPUTE" '
    '"$PASSWORDLESS_SSH" "$SSH_SOURCE_NODE" "$SSH_TARGET_NODE" "$SSH_CHECK_SCOPE"\n'
)


def run_ssh_probe(nodes: list[dict[str, object]], srun_stub: str) -> bashtest.BashRun:
    return bashtest.run_bash(
        PROBE_SCRIPT,
        env={"NODES_JSON": json.dumps(nodes)},
        stubs={"srun": srun_stub, **PRINT_STUBS},
    )


def test_node_selection_prefers_the_checked_gpu_worker() -> None:
    nodes = [
        {"name": "login-1", "state": "IDLE", "gpus": 0},
        {"name": "gpu-b", "state": "ALLOCATED", "gpus": 8},
        {"name": "gpu-a", "state": "IDLE", "gpus": 8},
        {"name": "gpu-c", "state": "DOWN+DRAIN", "gpus": 8},
        {"name": "gpu-d", "state": "IDLE+CLOUD+POWERED_DOWN", "gpus": 8},
    ]
    script = (
        bashtest.extract_function(COMMON, "select_worker_ssh_nodes")
        + '\nselect_worker_ssh_nodes "$NODES_JSON" gpu-b\n'
    )
    run = bashtest.run_bash(script, env={"NODES_JSON": json.dumps(nodes)})

    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == ["gpu-b", "gpu-a"]


@pytest.mark.parametrize(
    ("nodes", "srun_stub", "expected", "expects_srun"),
    [
        (
            TWO_WORKERS,
            "printf 'gpu-b\\n'",
            "true|enabled|gpu-a|gpu-b|worker-to-worker",
            True,
        ),
        (TWO_WORKERS[:1], "exit 99", "unknown|unknown|||unverified", False),
        (
            TWO_WORKERS,
            "exit 1",
            "false|disabled|gpu-a|gpu-b|worker-to-worker",
            True,
        ),
    ],
    ids=("success", "one-worker", "failure"),
)
def test_ssh_probe(
    nodes: list[dict[str, object]],
    srun_stub: str,
    expected: str,
    expects_srun: bool,
) -> None:
    run = run_ssh_probe(nodes, srun_stub)

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected
    assert run.calls("srun") == ([EXPECTED_SRUN_CALL] if expects_srun else [])
    assert run.calls("ssh") == []
