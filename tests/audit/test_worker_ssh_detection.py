from __future__ import annotations

import json
from pathlib import Path

import pytest

import bashtest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
COMMON = WORKLOAD / "audit-common.sh"
SLURM = WORKLOAD / "cluster-audit-slurm.sh"
@pytest.mark.parametrize("state", ["idle~", "drain$", "drng", "alloc*", "idle#", "down", "UNKNOWN", "IDLE+NOT_RESPONDING"])
def test_selector_rejects_unusable_sinfo_states(state):
    nodes = [{"name": "bad", "state": state, "gpus": 8}, *TWO_WORKERS]
    run = bashtest.run_bash(
        bashtest.extract_function(COMMON, "select_worker_ssh_nodes")
        + 'select_worker_ssh_nodes "$NODES_JSON" bad',
        env={"NODES_JSON": json.dumps(nodes)},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == ["gpu-a", "gpu-b"]


TWO_WORKERS = [
    {"name": "gpu-a", "state": "IDLE", "gpus": 8},
    {"name": "gpu-b", "state": "IDLE", "gpus": 8},
]
EXPECTED_SRUN_CALL = [
    "--input=all", "--immediate=10", "-w", "gpu-a", "-N1", "--ntasks=1", "--gres=none",
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
            "printf 'CMAX_SSH_STATUS=true\\n'",
            "true|enabled|gpu-a|gpu-b|worker-to-worker",
            True,
        ),
        (TWO_WORKERS[:1], "exit 99", "unknown|unknown|||unverified", False),
        (
            TWO_WORKERS,
            "printf 'CMAX_SSH_STATUS=false\\n'",
            "false|disabled|gpu-a|gpu-b|worker-to-worker",
            True,
        ),
        (TWO_WORKERS, "exit 1", "unknown|unknown|gpu-a|gpu-b|unverified", True),
    ],
    ids=("success", "one-worker", "failure", "scheduling-failure"),
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


@pytest.mark.parametrize("job_nodelist", ["node-[2-3]", ""])
def test_allocated_probe_forwards_script_and_uses_slurm_node_names(job_nodelist):
    nodes = [
        {"name": name, "state": "ALLOCATED", "gpus": 8}
        for name in ("node-1", "node-2", "node-3")
    ]
    # Simulate Slurm dropping stdin unless --input=all is explicitly requested,
    # then execute the actual shipped shell script and stub only remote SSH.
    srun = """
[[ " $* " == *" --input=all "* ]] || exit 0
while [[ "$1" != bash ]]; do shift; done
exec "$@"
"""
    run = bashtest.run_bash(
        PROBE_SCRIPT.replace("WORKER_HOSTNAME=gpu-a", "WORKER_HOSTNAME=host-fqdn.example"),
        env={
            "NODES_JSON": json.dumps(nodes), "SLURM_JOB_ID": "123",
            "SLURM_JOB_NODELIST": job_nodelist, "SLURM_NODELIST": "",
            "SLURMD_NODENAME": "node-3",
        },
        stubs={
            "scontrol": "printf 'node-2\\nnode-3\\n'",
            "squeue": "printf 'node-[2-3]\\n'",
            "srun": srun, "ssh": "exit 0", **PRINT_STUBS,
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true|enabled|node-3|node-2|worker-to-worker"
    assert run.calls("scontrol") == [["show", "hostnames", "node-[2-3]"]]
    assert run.calls("squeue") == ([] if job_nodelist else [["-h", "-j", "123", "-o", "%N"]])
    assert run.calls("ssh")[0][-2:] == ["node-2", "hostname"]
    assert run.calls("srun")[0][run.calls("srun")[0].index("-w") + 1] == "node-3"


def test_unknown_allocation_never_falls_back_to_cluster_inventory():
    run = bashtest.run_bash(
        PROBE_SCRIPT,
        env={"NODES_JSON": json.dumps(TWO_WORKERS), "SLURM_JOB_ID": "123",
             "SLURM_JOB_NODELIST": "", "SLURM_NODELIST": ""},
        stubs={"squeue": "exit 1", "scontrol": "exit 1", "srun": "exit 99", **PRINT_STUBS},
    )
    assert run.returncode == 0, run.stderr
    assert run.calls("srun") == []
    assert run.stdout.strip() == "unknown|unknown|||unverified"
