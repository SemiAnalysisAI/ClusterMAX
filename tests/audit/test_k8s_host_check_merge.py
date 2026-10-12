import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bashtest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-k8s.sh"
)

# Facts as an nvidia-driver daemonset pod reports them: the driver is visible,
# host-installed tools are not.
DRIVER_POD_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=nvidia-driver-daemonset-2hhjv",
        "WORKER_DRIVER_VERSION=580.173.02",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=",
        "WORKER_PERF_STAT_ACCESS=no-perf",
        "WORKER_IPMITOOL_PATH=",
    ]
)

# Facts as the privileged host pod reports them from chroot /host on a GPU
# Operator node: host tools are visible, nvidia-smi is not.
HOST_ROOT_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=gpu080023",
        "WORKER_DRIVER_VERSION=unknown",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=/usr/bin/perf",
        "WORKER_PERF_STAT_ACCESS=granted",
        "WORKER_IPMITOOL_PATH=",
        "WORKER_LSPCI_ONLY_ON_HOST=/usr/bin/lspci",
    ]
)


def merge(driver_out: str, host_out: str) -> dict[str, str]:
    block = bashtest.extract_function(SCRIPT, "merge_host_check_facts")
    run = bashtest.run_bash(
        block + '\nmerge_host_check_facts "$DRIVER_OUT" "$HOST_OUT"',
        env={"DRIVER_OUT": driver_out, "HOST_OUT": host_out},
    )
    assert run.returncode == 0, run.stderr
    facts: dict[str, str] = {}
    for line in run.stdout.splitlines():
        key, _, value = line.partition("=")
        assert key not in facts, f"duplicate key in merged output: {key}"
        facts[key] = value
    return facts


def test_host_root_supplies_host_installed_tools():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_PERF_PATH"] == "/usr/bin/perf"
    assert facts["WORKER_PERF_STAT_ACCESS"] == "granted"
    assert facts["WORKER_HOSTNAME"] == "gpu080023"


def test_driver_pod_keeps_facts_the_host_root_cannot_report():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_DRIVER_VERSION"] == "580.173.02"


def test_empty_on_both_sides_stays_empty():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_IPMITOOL_PATH"] == ""


def test_host_only_facts_are_kept():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_LSPCI_ONLY_ON_HOST"] == "/usr/bin/lspci"


def test_no_host_root_output_leaves_driver_facts_unchanged():
    facts = merge(DRIVER_POD_OUT, "")
    assert facts == dict(line.split("=", 1) for line in DRIVER_POD_OUT.splitlines())


def test_values_containing_equals_signs_survive():
    facts = merge("WORKER_X=a=b", "WORKER_Y=c=d")
    assert facts == {"WORKER_X": "a=b", "WORKER_Y": "c=d"}
