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
    "--input=all", "--immediate=10", "-w", "gpu-a", "-N1", "--ntasks=1", "--gres=gpu:1",
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
    assert run.stdout.splitlines() == ["gpu-a", "gpu-b"]


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
    assert "--gres=none" in run.calls("srun")[0]


def test_login_node_probe_uses_idle_gpu_source_with_required_gres():
    nodes = [
        {"name": "gpu-a", "state": "ALLOCATED", "gpus": 8},
        {"name": "gpu-b", "state": "MIXED", "gpus": 8},
        {"name": "gpu-c", "state": "IDLE", "gpus": 8},
    ]
    run = bashtest.run_bash(
        PROBE_SCRIPT,
        env={"NODES_JSON": json.dumps(nodes), "SLURM_JOB_ID": ""},
        stubs={"srun": '[[ " $* " == *" --gres=gpu:1 "* ]] || exit 1; echo CMAX_SSH_STATUS=true', **PRINT_STUBS},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true|enabled|gpu-c|gpu-a|worker-to-worker"
    assert run.calls("srun")[0][run.calls("srun")[0].index("-w") + 1] == "gpu-c"


def test_login_node_probe_does_not_launch_on_fully_allocated_workers():
    nodes = [dict(node, state="ALLOCATED") for node in TWO_WORKERS]
    run = bashtest.run_bash(
        PROBE_SCRIPT,
        env={"NODES_JSON": json.dumps(nodes), "SLURM_JOB_ID": ""},
        stubs={"srun": "exit 99", **PRINT_STUBS},
    )
    assert run.returncode == 0, run.stderr
    assert run.calls("srun") == []


def test_snodes_unknown_gpu_counts_use_partition_scope_and_request_gpu_gres():
    # Invent individual table rows. No GPU counts are available in this format.
    snodes = "\n".join([
        "PARTITION AVAIL TIMELIMIT NODES STATE NODELIST",
        "synthetic-cpu up infinite 1 idle aaa-cpu",
        "synthetic-gpu* up infinite 1 idle synthetic-a",
        "synthetic-gpu up infinite 1 idle synthetic-b",
    ])
    script = (
        bashtest.extract_function(COMMON, "snodes_inventory")
        + '\nNODES_JSON=$(snodes_inventory "$SNODES_OUT")\n'
        + PROBE_SCRIPT.replace(
            "GPU_SRUN_SCOPE_ARGS=()", 'GPU_SRUN_SCOPE_ARGS=(-p "$GPU_PARTITION")'
        )
    )
    run = bashtest.run_bash(
        script,
        env={"SNODES_OUT": snodes, "GPU_PARTITION": "synthetic-gpu", "SLURM_JOB_ID": ""},
        stubs={
            "srun": '[[ " $* " == *" --gres=gpu:1 "* ]] || exit 99; echo CMAX_SSH_STATUS=true',
            **PRINT_STUBS,
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true|enabled|synthetic-a|synthetic-b|worker-to-worker"
    call, = run.calls("srun")
    assert call[:2] == ["-p", "synthetic-gpu"]
    assert call[call.index("-w") + 1] == "synthetic-a"
    assert "--gres=gpu:1" in call


def test_grouped_snodes_inventory_expands_to_individual_probe_workers():
    run = bashtest.run_bash(
        bashtest.extract_function(COMMON, "snodes_inventory")
        + '\nNODES_JSON=$(snodes_inventory "$SNODES_OUT")\n' + PROBE_SCRIPT,
        env={
            "SNODES_OUT": "PARTITION AVAIL TIMELIMIT NODES STATE NODELIST\n"
                          "synthetic-gpu up infinite 2 idle synthetic-[1-2]",
            "GPU_PARTITION": "synthetic-gpu", "SLURM_JOB_ID": "",
        },
        stubs={
            "scontrol": "printf 'synthetic-1\\nsynthetic-2\\n'",
            "srun": '[[ " $* " == *" --gres=gpu:1 "* ]] || exit 99; echo CMAX_SSH_STATUS=true',
            **PRINT_STUBS,
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true|enabled|synthetic-1|synthetic-2|worker-to-worker"
    assert run.calls("scontrol") == [["show", "hostnames", "synthetic-[1-2]"]]


def test_unexpandable_snodes_hostlists_do_not_become_ssh_hostnames():
    run = bashtest.run_bash(
        bashtest.extract_function(COMMON, "snodes_inventory")
        + '\nsnodes_inventory "$SNODES_OUT"\n',
        env={
            "SNODES_OUT": "PARTITION AVAIL TIMELIMIT NODES STATE NODELIST\n"
                          "synthetic-gpu up infinite 2 idle synthetic-[1-2]",
        },
        stubs={"scontrol": "exit 1"},
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == []


@pytest.mark.parametrize("gpu_count", [0, None])
def test_cpu_or_unscoped_unknown_inventory_does_not_request_gpu_gres(gpu_count):
    nodes = [dict(node, gpus=gpu_count) for node in TWO_WORKERS]
    run = bashtest.run_bash(
        PROBE_SCRIPT,
        env={"NODES_JSON": json.dumps(nodes), "SLURM_JOB_ID": "", "GPU_PARTITION": ""},
        stubs={"srun": "echo CMAX_SSH_STATUS=true", **PRINT_STUBS},
    )
    assert run.returncode == 0, run.stderr
    assert "--gres=none" in run.calls("srun")[0]
    assert "--gres=gpu:1" not in run.calls("srun")[0]


def test_allocated_unknown_gpu_counts_remain_in_the_allocation_without_new_gres():
    nodes = [
        dict(node, gpus=None, state="ALLOCATED", partition="synthetic-gpu")
        for node in TWO_WORKERS
    ]
    run = bashtest.run_bash(
        PROBE_SCRIPT,
        env={
            "NODES_JSON": json.dumps(nodes), "SLURM_JOB_ID": "1",
            "SLURM_JOB_NODELIST": "gpu-[a-b]", "GPU_PARTITION": "synthetic-gpu",
        },
        stubs={
            "scontrol": "printf 'gpu-a\\ngpu-b\\n'",
            "srun": "echo CMAX_SSH_STATUS=true", **PRINT_STUBS,
        },
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "true|enabled|gpu-a|gpu-b|worker-to-worker"
    assert "--gres=none" in run.calls("srun")[0]
    assert "--gres=gpu:1" not in run.calls("srun")[0]


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
