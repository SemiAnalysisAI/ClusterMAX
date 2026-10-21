import re
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

# Facts as an nvidia-driver daemonset pod reports them: the driver and GPUs are
# visible, host-installed tools are not.
DRIVER_POD_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=nvidia-driver-daemonset-2hhjv",
        "WORKER_DRIVER_VERSION=580.173.02",
        "WORKER_GPU_COUNT=4",
        "WORKER_GPU_MODEL=NVIDIA GB300",
        "WORKER_CUDA_VERSION=13.0",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=",
        "WORKER_PERF_STAT_ACCESS=no-perf",
        "WORKER_IPMITOOL_PATH=",
        "WORKER_IPMI_USER_ACCESS=not-installed",
        "WORKER_NCU_PATH=",
        "WORKER_NCU_COUNTER_ACCESS=no-ncu",
        "WORKER_NVHPC_INSTALLED=false",
        "WORKER_NVHPC_COMPONENTS_MISSING=not-checked",
        "WORKER_NCCL_VERSION=not-found",
    ]
)

# Facts as the privileged host pod reports them from chroot /host on a GPU
# Operator node: host tools are visible, nvidia-smi is not, so the GPU facts
# carry absence sentinels.
HOST_ROOT_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=gpu080023",
        "WORKER_DRIVER_VERSION=unknown",
        "WORKER_GPU_COUNT=0",
        "WORKER_GPU_MODEL=no-nvidia-smi",
        "WORKER_CUDA_VERSION=not-found",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=/usr/bin/perf",
        "WORKER_PERF_STAT_ACCESS=granted",
        "WORKER_IPMITOOL_PATH=",
        "WORKER_IPMI_USER_ACCESS=blocked",
        "WORKER_NCU_PATH=/usr/local/cuda/bin/ncu",
        "WORKER_NCU_COUNTER_ACCESS=granted",
        "WORKER_NVHPC_INSTALLED=true",
        "WORKER_NVHPC_COMPONENTS_MISSING=none",
        "WORKER_NCCL_VERSION=2.30.7",
        "WORKER_NETUTIL_LSPCI_PATH=/usr/bin/lspci",
        "WORKER_SOMETHING_HOST_ONLY=1",
    ]
)


def merge(driver_out: str, host_out: str) -> dict[str, str]:
    text = SCRIPT.read_text(encoding="utf-8")
    allow = re.search(r"^HOST_ROOT_FACT_KEYS=.*$", text, re.M)
    assert allow, "HOST_ROOT_FACT_KEYS assignment not found"
    block = allow.group(0) + "\n" + bashtest.extract_function(SCRIPT, "merge_host_check_facts")
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


def test_host_sentinels_do_not_replace_driver_pod_gpu_facts():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_DRIVER_VERSION"] == "580.173.02"
    assert facts["WORKER_GPU_COUNT"] == "4"
    assert facts["WORKER_GPU_MODEL"] == "NVIDIA GB300"
    assert facts["WORKER_CUDA_VERSION"] == "13.0"
    assert facts["WORKER_HOSTNAME"] == "nvidia-driver-daemonset-2hhjv"


def test_host_root_is_authoritative_for_whole_tool_families():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_NCU_PATH"] == "/usr/local/cuda/bin/ncu"
    assert facts["WORKER_NCU_COUNTER_ACCESS"] == "granted"
    assert facts["WORKER_IPMI_USER_ACCESS"] == "blocked"
    assert facts["WORKER_NCCL_VERSION"] == "2.30.7"
    # "none" here means no NVHPC component is missing; it must not be read as an absence marker.
    assert facts["WORKER_NVHPC_INSTALLED"] == "true"
    assert facts["WORKER_NVHPC_COMPONENTS_MISSING"] == "none"


def test_host_tool_sentinels_also_come_from_the_host_root():
    facts = merge("WORKER_PERF_PATH=/opt/perf", "WORKER_PERF_PATH=")
    assert facts["WORKER_PERF_PATH"] == ""


def test_empty_on_both_sides_stays_empty():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_IPMITOOL_PATH"] == ""


def test_only_allowlisted_host_only_facts_are_added():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_NETUTIL_LSPCI_PATH"] == "/usr/bin/lspci"
    assert "WORKER_SOMETHING_HOST_ONLY" not in facts


def test_no_host_root_output_leaves_driver_facts_unchanged():
    facts = merge(DRIVER_POD_OUT, "")
    assert facts == dict(line.split("=", 1) for line in DRIVER_POD_OUT.splitlines())


def test_values_containing_equals_signs_survive():
    facts = merge("WORKER_PERF_PATH=a=b", "WORKER_NCU_PATH=c=d")
    assert facts == {"WORKER_PERF_PATH": "a=b", "WORKER_NCU_PATH": "c=d"}
