"""CPU, memory, and device-assignment inventory."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

AUDIT_DIR = Path(__file__).resolve().parent

WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"

# CPU inventory
CPU_FUNC = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_cpu_inventory")

X86_CPUINFO = "\n".join(
    line
    for cpu in range(8)
    for line in (
        f"processor\t: {cpu}",
        "model name\t: INTEL(R) XEON(R) PLATINUM 8570",
        f"physical id\t: {cpu // 4}",
        "",
    )
)

ARM_CPUINFO = "\n".join(
    line
    for cpu in range(4)
    for line in (
        f"processor\t: {cpu}",
        "BogoMIPS\t: 2000.00",
        "CPU implementer\t: 0x41",
        "",
    )
)

X86_LSCPU = (
    "Architecture:        x86_64\n"
    "Model name:          SHOULD NOT WIN over /proc/cpuinfo\n"
    "Socket(s):           4\n"
    "Core(s) per socket:  28\n"
    "Thread(s) per core:  2\n"
)

ARM_LSCPU = (
    "Architecture:        aarch64\n"
    "Model name:          Neoverse-V2\n"
    "Socket(s):           2\n"
    "Core(s) per socket:  72\n"
    "Thread(s) per core:  1\n"
)

def shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"

def write_rapl_domain(
    powercap: Path,
    domain: str,
    name: str,
    constraints: dict[int, tuple[str, int]],
) -> None:
    d = powercap / domain
    d.mkdir(parents=True)
    (d / "name").write_text(name + "\n")
    for idx, (cname, uw) in constraints.items():
        (d / f"constraint_{idx}_name").write_text(cname + "\n")
        (d / f"constraint_{idx}_power_limit_uw").write_text(f"{uw}\n")

def make_x86_root(root: Path) -> None:
    (root / "proc").mkdir(parents=True)
    (root / "proc" / "cpuinfo").write_text(X86_CPUINFO)
    cpufreq = root / "sys" / "devices" / "system" / "cpu" / "cpu0" / "cpufreq"
    cpufreq.mkdir(parents=True)
    (cpufreq / "base_frequency").write_text("2100000\n")
    (cpufreq / "cpuinfo_max_freq").write_text("4000000\n")
    (cpufreq / "scaling_cur_freq").write_text("1800000\n")
    for cpu, governor in ((0, "performance"), (1, "performance"), (2, "powersave")):
        gov_dir = root / "sys" / "devices" / "system" / "cpu" / f"cpu{cpu}" / "cpufreq"
        gov_dir.mkdir(parents=True, exist_ok=True)
        (gov_dir / "scaling_governor").write_text(governor + "\n")
    powercap = root / "sys" / "class" / "powercap"
    # Package 1 puts long_term on constraint_1; dram and psys are not packages.

    write_rapl_domain(powercap, "intel-rapl:0", "package-0", {0: ("long_term", 350000000)})
    write_rapl_domain(
        powercap,
        "intel-rapl:1",
        "package-1",
        {0: ("short_term", 400000000), 1: ("long_term", 300000000)},
    )
    write_rapl_domain(powercap, "intel-rapl:0:0", "dram", {0: ("long_term", 100000000)})
    write_rapl_domain(powercap, "intel-rapl:2", "psys", {0: ("long_term", 900000000)})

def run_cpu_inventory(root: Path, lscpu_output: str) -> dict[str, str]:
    run = bashtest.run_bash(
        CPU_FUNC + "\ncollect_cpu_inventory",
        stubs={"lscpu": f"printf %s {shquote(lscpu_output)}"},
        env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
    )
    return inventory_facts(run)

def inventory_facts(run: bashtest.BashRun) -> dict[str, str]:
    assert run.returncode == 0, run.stderr
    return dict(line.split("=", 1) for line in run.stdout.splitlines())

def test_x86_inventory_reads_rerooted_proc_and_sys(tmp_path: Path) -> None:
    make_x86_root(tmp_path)
    facts = run_cpu_inventory(tmp_path, X86_LSCPU)

    assert facts["WORKER_CPU_MODEL"] == "INTEL(R) XEON(R) PLATINUM 8570"
    assert facts["WORKER_CPU_SOCKETS"] == "2"
    assert facts["WORKER_CPU_THREADS"] == "8"

    assert facts["WORKER_CPU_CORES_PER_SOCKET"] == "28"
    assert facts["WORKER_CPU_THREADS_PER_CORE"] == "2"

    assert facts["WORKER_CPU_BASE_MHZ"] == "2100"
    assert facts["WORKER_CPU_MAX_MHZ"] == "4000"
    assert facts["WORKER_CPU_CUR_MHZ"] == "1800"

    assert facts["WORKER_CPU_GOVERNOR"] == "performance,powersave"
    assert facts["WORKER_CPU_RAPL_PACKAGES"] == "2"
    assert facts["WORKER_CPU_PACKAGE_POWER_LIMIT_W"] == "350,300"

def test_rapl_falls_back_to_constraint_zero_without_long_term(tmp_path: Path) -> None:
    write_rapl_domain(
        tmp_path / "sys" / "class" / "powercap",
        "intel-rapl:0",
        "package-0",
        {0: ("peak_power", 500000000)},
    )
    facts = run_cpu_inventory(tmp_path, "")
    assert facts["WORKER_CPU_RAPL_PACKAGES"] == "1"
    assert facts["WORKER_CPU_PACKAGE_POWER_LIMIT_W"] == "500"

def test_arm_falls_back_to_lscpu_for_model_and_sockets(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir(parents=True)
    (tmp_path / "proc" / "cpuinfo").write_text(ARM_CPUINFO)
    facts = run_cpu_inventory(tmp_path, ARM_LSCPU)

    assert facts["WORKER_CPU_MODEL"] == "Neoverse-V2"
    assert facts["WORKER_CPU_SOCKETS"] == "2"
    assert facts["WORKER_CPU_CORES_PER_SOCKET"] == "72"
    assert facts["WORKER_CPU_THREADS_PER_CORE"] == "1"

    assert facts["WORKER_CPU_THREADS"] == "4"

def test_missing_cpu_inventory_degrades_to_unknown(tmp_path: Path) -> None:
    facts = run_cpu_inventory(tmp_path, "")

    for key in (
        "WORKER_CPU_MODEL",
        "WORKER_CPU_SOCKETS",
        "WORKER_CPU_CORES_PER_SOCKET",
        "WORKER_CPU_THREADS",
        "WORKER_CPU_THREADS_PER_CORE",
        "WORKER_CPU_BASE_MHZ",
        "WORKER_CPU_MAX_MHZ",
        "WORKER_CPU_CUR_MHZ",
        "WORKER_CPU_GOVERNOR",
        "WORKER_CPU_PACKAGE_POWER_LIMIT_W",
    ):
        assert facts[key] == "unknown", key
    assert facts["WORKER_CPU_RAPL_PACKAGES"] == "0"

MERGE_PATH = WORKLOAD / "merge_audit.py"

def load_merge_module():
    spec = importlib.util.spec_from_file_location("merge_audit_cpu_under_test", MERGE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

merge_audit = load_merge_module()

def test_k8s_remap_builds_compute_node_cpu_block() -> None:
    audit = {
        "hostCheck": {
            "WORKER_CPU_MODEL": "Neoverse-V2",
            "WORKER_CPU_SOCKETS": "2",
            "WORKER_CPU_CORES_PER_SOCKET": "72",
            "WORKER_CPU_THREADS": "144",
            "WORKER_CPU_THREADS_PER_CORE": "1",
            "WORKER_CPU_BASE_MHZ": "unknown",
            "WORKER_CPU_MAX_MHZ": "3438",
            "WORKER_CPU_CUR_MHZ": "3438",
            "WORKER_CPU_GOVERNOR": "performance",
            "WORKER_CPU_RAPL_PACKAGES": "0",
            "WORKER_CPU_PACKAGE_POWER_LIMIT_W": "unknown",
        }
    }
    merge_audit.remap_k8s_canonical(audit)
    cpu = audit["computeNodeCpu"]
    assert cpu["model"] == "Neoverse-V2"
    assert cpu["sockets"] == "2"
    assert cpu["coresPerSocket"] == "72"
    assert cpu["threads"] == "144"
    assert cpu["threadsPerCore"] == "1"
    assert cpu["baseMhz"] == "unknown"
    assert cpu["maxMhz"] == "3438"
    assert cpu["curMhz"] == "3438"
    assert cpu["governors"] == "performance"
    assert cpu["raplPackages"] == "0"
    assert cpu["packagePowerLimitW"] == "unknown"
    assert cpu["source"] == "host-check"

def test_k8s_remap_never_overwrites_existing_cpu_facts() -> None:
    audit = {
        "computeNodeCpu": {"model": "already-recorded", "source": "backfill"},
        "hostCheck": {"WORKER_CPU_MODEL": "check-model", "WORKER_CPU_SOCKETS": "2"},
    }
    merge_audit.remap_k8s_canonical(audit)
    cpu = audit["computeNodeCpu"]
    assert cpu["model"] == "already-recorded"
    assert cpu["source"] == "backfill"

    assert cpu["sockets"] == "2"

def test_k8s_remap_without_cpu_keys_adds_no_block() -> None:
    audit = {"hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"}}
    merge_audit.remap_k8s_canonical(audit)
    assert "computeNodeCpu" not in audit

# Memory inventory
MEM_FUNC = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "collect_memory_inventory"
)

def dmi_device(
    size: str,
    mem_type: str,
    speed: str,
    configured: str,
    configured_label: str = "Configured Memory Speed",
) -> str:
    return (
        "Handle 0x1100, DMI type 17, 40 bytes\n"
        "Memory Device\n"
        "\tArray Handle: 0x1000\n"
        "\tTotal Width: 80 bits\n"
        "\tData Width: 64 bits\n"
        f"\tSize: {size}\n"
        "\tForm Factor: DIMM\n"
        "\tLocator: DIMM_A1\n"
        "\tBank Locator: P0 CHANNEL A\n"
        f"\tType: {mem_type}\n"
        "\tType Detail: Synchronous Registered (Buffered)\n"
        f"\tSpeed: {speed}\n"
        f"\t{configured_label}: {configured}\n"
        "\n"
    )

EMPTY_SLOT = dmi_device("No Module Installed", "Unknown", "Unknown", "Unknown")

FLASH_ROM = (
    "Handle 0x1108, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tArray Handle: 0x1000\n"
    "\tSize: 16384 kB\n"
    "\tForm Factor: Chip\n"
    "\tLocator: SYSTEM ROM\n"
    "\tType: Flash\n"
    "\tSpeed: Unknown\n"
    "\n"
)

def run_memory_inventory(
    root: Path, dmidecode_body: str, sockets: str = "", threads: str = ""
) -> dict[str, str]:
    # Disable real privilege escalation outside the explicit sudo fixture.

    run = bashtest.run_bash(
        MEM_FUNC + f"\ncollect_memory_inventory '{sockets}' '{threads}'",
        stubs={"dmidecode": dmidecode_body, "sudo": "exit 1"},
        env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
    )
    return inventory_facts(run)

def test_dmidecode_counts_populated_slots_and_unique_speeds(tmp_path: Path) -> None:

    dmi = (
        "# dmidecode 3.4\n"
        "Getting SMBIOS data from sysfs.\n"
        + dmi_device("64 GB", "DDR5", "6400 MT/s", "6400 MT/s")
        + dmi_device("64 GB", "DDR5", "6400 MT/s", "4800 MT/s")
        + dmi_device("32768 MB", "DDR5", "6400 MT/s", "6400 MT/s")
        + EMPTY_SLOT
        + FLASH_ROM
    )
    facts = run_memory_inventory(tmp_path, f"printf %s {shquote(dmi)}", sockets="2", threads="32")

    assert facts["WORKER_MEM_DIMMS"] == "3"

    assert facts["WORKER_MEM_DIMM_SIZES_GB"] == "32,64"
    assert facts["WORKER_MEM_TYPES"] == "DDR5"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "6400"

    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "4800,6400"

    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "57.6"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "3.60"
    assert facts["WORKER_MEM_SOURCE"] == "dmidecode"

def test_old_dmidecode_configured_clock_speed_label(tmp_path: Path) -> None:

    dmi = dmi_device(
        "32 GB",
        "DDR4",
        "2933 MT/s",
        "2400 MHz",
        configured_label="Configured Clock Speed",
    )
    facts = run_memory_inventory(tmp_path, f"printf %s {shquote(dmi)}", sockets="1")

    assert facts["WORKER_MEM_DIMMS"] == "1"
    assert facts["WORKER_MEM_TYPES"] == "DDR4"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "2933"
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "2400"

    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "19.2"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "unknown"
    assert facts["WORKER_MEM_SOURCE"] == "dmidecode"

def test_unprivileged_check_elevates_with_passwordless_sudo(tmp_path: Path) -> None:

    dmi = dmi_device("64 GB", "DDR5", "6400 MT/s", "6400 MT/s")
    dmidecode_stub = (
        'if [[ "${DMI_ELEVATED:-}" == 1 ]]; then\n'
        f"    printf %s {shquote(dmi)}\n"
        "else\n"
        "    exit 1\n"
        "fi\n"
    )
    sudo_stub = (
        '[[ "$1" == "-n" ]] && shift\n'
        '[[ "$1" == "true" ]] && exit 0\n'
        'DMI_ELEVATED=1 exec "$@"\n'
    )
    run = bashtest.run_bash(
        MEM_FUNC + "\ncollect_memory_inventory '2' '64'",
        stubs={"dmidecode": dmidecode_stub, "sudo": sudo_stub},
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    facts = dict(line.partition("=")[::2] for line in run.stdout.splitlines())
    assert facts["WORKER_MEM_DIMMS"] == "1"
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "6400"
    assert facts["WORKER_MEM_SOURCE"] == "dmidecode"

def make_edac_dimm(root: Path, mc: int, dimm: int, size_mb: str, mem_type: str) -> None:
    d = root / "sys" / "devices" / "system" / "edac" / "mc" / f"mc{mc}" / f"dimm{dimm}"
    d.mkdir(parents=True)
    (d / "size").write_text(size_mb + "\n")
    (d / "dimm_mem_type").write_text(mem_type + "\n")

def test_edac_fallback_when_dmidecode_fails(tmp_path: Path) -> None:

    make_edac_dimm(tmp_path, 0, 0, "65536", "DDR5")
    make_edac_dimm(tmp_path, 0, 1, "65536", "DDR5")
    make_edac_dimm(tmp_path, 1, 0, "65536", "Unknown")

    make_edac_dimm(tmp_path, 1, 1, "0", "Unknown")
    facts = run_memory_inventory(tmp_path, "exit 1", sockets="2", threads="64")

    assert facts["WORKER_MEM_DIMMS"] == "3"
    assert facts["WORKER_MEM_DIMM_SIZES_GB"] == "64"
    assert facts["WORKER_MEM_TYPES"] == "DDR5"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "unknown"
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "unknown"

    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "unknown"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "unknown"
    assert facts["WORKER_MEM_SOURCE"] == "edac"

def test_missing_memory_inventory_degrades_to_unknown(tmp_path: Path) -> None:
    facts = run_memory_inventory(tmp_path, "exit 1")

    for key in (
        "WORKER_MEM_DIMMS",
        "WORKER_MEM_DIMM_SIZES_GB",
        "WORKER_MEM_TYPES",
        "WORKER_MEM_RATED_SPEED_MTS",
        "WORKER_MEM_CONFIGURED_SPEED_MTS",
        "WORKER_MEM_BW_PER_SOCKET_GBS",
        "WORKER_MEM_BW_PER_CORE_GBS",
        "WORKER_MEM_SOURCE",
    ):
        assert facts[key] == "unknown", key

def test_k8s_remap_builds_compute_node_memory_block() -> None:
    audit = {
        "hostCheck": {
            "WORKER_MEM_DIMMS": "16",
            "WORKER_MEM_DIMM_SIZES_GB": "64",
            "WORKER_MEM_TYPES": "DDR5",
            "WORKER_MEM_RATED_SPEED_MTS": "6400",
            "WORKER_MEM_CONFIGURED_SPEED_MTS": "4800,6400",
            "WORKER_MEM_BW_PER_SOCKET_GBS": "307.2",
            "WORKER_MEM_BW_PER_CORE_GBS": "3.20",
            "WORKER_MEM_SOURCE": "dmidecode",
        }
    }
    merge_audit.remap_k8s_canonical(audit)
    memory = audit["computeNodeMemory"]
    assert memory["populatedDimms"] == "16"
    assert memory["dimmSizesGB"] == "64"
    assert memory["types"] == "DDR5"
    assert memory["ratedSpeedMts"] == "6400"
    assert memory["configuredSpeedMts"] == "4800,6400"
    assert memory["effectiveBandwidthPerSocketGBs"] == "307.2"
    assert memory["effectiveBandwidthPerCoreGBs"] == "3.20"
    assert memory["source"] == "dmidecode"

def test_k8s_remap_never_overwrites_existing_memory_facts() -> None:
    audit = {
        "computeNodeMemory": {"populatedDimms": "24", "source": "backfill"},
        "hostCheck": {"WORKER_MEM_DIMMS": "16", "WORKER_MEM_TYPES": "DDR5"},
    }
    merge_audit.remap_k8s_canonical(audit)
    memory = audit["computeNodeMemory"]
    assert memory["populatedDimms"] == "24"
    assert memory["source"] == "backfill"

    assert memory["types"] == "DDR5"

def test_k8s_remap_without_memory_keys_adds_no_block() -> None:
    audit = {"hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"}}
    merge_audit.remap_k8s_canonical(audit)
    assert "computeNodeMemory" not in audit

K8S_COLLECTOR = WORKLOAD / "cluster-audit-k8s.sh"

# Device assignment
CHECK = bashtest.extract_block(
    WORKLOAD / "host-check.sh",
    'echo "WORKER_CUDA_VISIBLE_DEVICES=',
    'MPIRUN_P=""',
)

def test_cuda_visible_devices_is_recorded_from_worker_environment() -> None:
    run = bashtest.run_bash(
        CHECK,
        env={
            "CUDA_VISIBLE_DEVICES": "GPU-a,GPU-b",
            "NVIDIA_VISIBLE_DEVICES": "GPU-a,GPU-b",
        },
    )

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=GPU-a,GPU-b" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=GPU-a,GPU-b" in run.stdout

def test_unassigned_cuda_devices_are_recorded_as_unset() -> None:
    run = bashtest.run_bash(CHECK)

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=unset" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=unset" in run.stdout

def test_k8s_gpu_check_records_the_assigned_devices() -> None:
    function = bashtest.extract_function(K8S_COLLECTOR, "run_gpu_smi_check")
    run = bashtest.run_bash(
        function
        + """
K8S_AUDIT_CHECK_NS=clustermax-audit
K8S_AUDIT_GPU_CHECK_IMAGE=cuda-image
apply_gpu_check_pod() { echo gpu-check-pod; }
cleanup_audit_check_pod() { :; }
check_deadline() { shift; "$@"; }
run_gpu_smi_check worker-0
""",
        stubs={
            "kubectl": bashtest.exec_from("bash"),
            "nvidia-smi": """
case "$*" in
  *--query-gpu=driver_version*) echo 590.48.01 ;;
  *--query-gpu=name*) echo "NVIDIA H100" ;;
  *--query-gpu=memory.total*) echo 81559 ;;
  *) echo "CUDA Version: 13.0" ;;
esac
""",
        },
        env={
            "CUDA_VISIBLE_DEVICES": "GPU-a",
            "NVIDIA_VISIBLE_DEVICES": "GPU-a",
        },
    )

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=GPU-a" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=GPU-a" in run.stdout


def run_gpu_smi_check_with_policy(driver: str, policy: str) -> bashtest.BashRun:
    """Run the real k8s GPU check with a controlled driver-floor policy.

    The nvidia-smi stub reports the given driver, the collector stub resolves
    the given policy, and the kubectl stub runs the pod payload in-process
    with the policy environment applied, exactly as the remote command does.
    """
    function = bashtest.extract_function(K8S_COLLECTOR, "run_gpu_smi_check")
    return bashtest.run_bash(
        function
        + f"""
K8S_AUDIT_CHECK_NS=clustermax-audit
K8S_AUDIT_GPU_CHECK_IMAGE=cuda-image
nvidia_driver_floors() {{ printf '%s\\n' '{policy}'; }}
apply_gpu_check_pod() {{ echo gpu-check-pod; }}
cleanup_audit_check_pod() {{ :; }}
check_deadline() {{ shift; "$@"; }}
run_gpu_smi_check worker-0
""",
        stubs={
            "kubectl": bashtest.exec_from("env"),
            "nvidia-smi": f"""
case "$*" in
  *--query-gpu=driver_version*) echo {driver} ;;
  *--query-gpu=name*) echo "NVIDIA H100" ;;
  *--query-gpu=memory.total*) echo 81559 ;;
  *) echo "CUDA Version: 13.0" ;;
esac
""",
        },
    )


def gpu_smi_patched(driver: str, policy: str) -> tuple[str, list[list[str]]]:
    run = run_gpu_smi_check_with_policy(driver, policy)
    assert run.returncode == 0, run.stderr
    facts = dict(
        line.split("=", 1)
        for line in run.stdout.splitlines()
        if line.startswith("WORKER_")
    )
    return (
        facts["WORKER_NVIDIA_MAY_2026_PATCHED"],
        run.calls("kubectl"),
    )


@pytest.mark.parametrize(
    ("driver", "expected"),
    [
        ("580.126.09", "false"),  # below the floor
        ("580.178.04", "true"),  # exactly at the floor
        ("580.178.05", "true"),  # above the floor
        ("615.71.09", "true"),  # a different listed branch
        ("615.71.08", "false"),  # a different listed branch, below floor
    ],
)
def test_k8s_gpu_check_grades_the_driver_against_the_injected_floor(
    driver: str, expected: str
) -> None:
    patched, _ = gpu_smi_patched(driver, "580=580.178.04 615=615.71.09")
    assert patched == expected


def test_k8s_gpu_check_grades_a_branch_the_old_case_did_not_list() -> None:
    # 570 and 590 are published by the table but were missing from the
    # hardcoded branch list this check used to carry; the injected policy
    # grades them like any other branch.
    patched, _ = gpu_smi_patched("570.100.00", "570=570.211.01 580=580.178.04")
    assert patched == "false"
    patched, _ = gpu_smi_patched("590.48.01", "590=590.48.01")
    assert patched == "true"


def test_k8s_gpu_check_floor_change_regrades_without_shell_edits() -> None:
    # A refreshed bulletin only moves the table; the same driver flips
    # verdicts when the injected floor moves across it.
    patched, _ = gpu_smi_patched("580.173.02", "580=580.170.00")
    assert patched == "true"
    patched, _ = gpu_smi_patched("580.173.02", "580=580.180.00")
    assert patched == "false"


def test_k8s_gpu_check_without_a_policy_stays_unknown() -> None:
    patched, _ = gpu_smi_patched("580.178.04", "")
    assert patched == "unknown"


@pytest.mark.parametrize("driver", ["620.05.00", "600.10.00", "560.127.09"])
def test_k8s_gpu_check_unlisted_branch_stays_unknown(driver: str) -> None:
    # A branch the table does not list is never assumed fixed; the
    # collect-side fact matches the report-side grader's unknown verdict.
    patched, _ = gpu_smi_patched(driver, "580=580.178.04 615=615.71.09")
    assert patched == "unknown"


def test_k8s_gpu_check_sends_the_policy_to_the_pod() -> None:
    # The remote command itself must carry the policy, not just the extracted
    # script block: the pod environment is the only channel by which the
    # table reaches code that cannot see the checkout.
    _, calls = gpu_smi_patched("580.178.04", "580=580.178.04 615=615.71.09")
    assert calls, "kubectl was never invoked"
    argv = calls[0]
    assert "env" in argv
    assert "CLUSTERMAX_NVIDIA_BRANCH_FLOORS=580=580.178.04 615=615.71.09" in argv
