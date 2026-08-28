"""Behavioral tests for the compute-node CPU inventory.

Two surfaces are exercised, per the repo testing doctrine (real code under
stubs, no assertIn source pinning):

1. host-check.sh collect_cpu_inventory() runs against a fake /proc + /sys
   tree (CLUSTERMAX_AUDIT_ROOT) with a stubbed lscpu, covering the x86
   cpuinfo path, the ARM lscpu fallback, the RAPL long_term constraint
   selection, and the everything-missing degradation to "unknown".
2. merge_audit.py remap_k8s_canonical() folds hostCheck.WORKER_CPU_* onto
   the canonical audit_data.computeNodeCpu block the slurm and standalone
   collectors emit directly, without overwriting existing values.

The guarded incident: OEMs and providers can configure a CPU below its
datasheet (lowered RAPL package limit, capped frequency, powersave
governor). The audit must record the configured values, and a check run on
a host that exposes none of these files must degrade to "unknown" instead
of failing the whole check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

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
    # package-0 names its long_term limit on constraint_0; package-1 lists
    # short_term first, so the long_term selection must not just take
    # constraint_0. The dram sub-domain and psys must both be skipped.
    write_rapl_domain(powercap, "intel-rapl:0", "package-0", {0: ("long_term", 350000000)})
    write_rapl_domain(
        powercap,
        "intel-rapl:1",
        "package-1",
        {0: ("short_term", 400000000), 1: ("long_term", 300000000)},
    )
    write_rapl_domain(powercap, "intel-rapl:0:0", "dram", {0: ("long_term", 100000000)})
    write_rapl_domain(powercap, "intel-rapl:2", "psys", {0: ("long_term", 900000000)})


def run_inventory(root: Path, lscpu_output: str) -> dict[str, str]:
    run = bashtest.run_bash(
        CPU_FUNC + "\ncollect_cpu_inventory",
        stubs={"lscpu": f"printf %s {shquote(lscpu_output)}"},
        env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
    )
    assert run.returncode == 0, run.stderr
    facts = {}
    for line in run.stdout.splitlines():
        key, _, value = line.partition("=")
        facts[key] = value
    return facts


def test_x86_inventory_reads_rerooted_proc_and_sys(tmp_path: Path) -> None:
    make_x86_root(tmp_path)
    facts = run_inventory(tmp_path, X86_LSCPU)

    # Re-rooted /proc/cpuinfo wins over live lscpu for model and sockets.
    assert facts["WORKER_CPU_MODEL"] == "INTEL(R) XEON(R) PLATINUM 8570"
    assert facts["WORKER_CPU_SOCKETS"] == "2"
    assert facts["WORKER_CPU_THREADS"] == "8"
    # Topology fields cpuinfo cannot provide come from lscpu.
    assert facts["WORKER_CPU_CORES_PER_SOCKET"] == "28"
    assert facts["WORKER_CPU_THREADS_PER_CORE"] == "2"
    # kHz sysfs values are reported in MHz.
    assert facts["WORKER_CPU_BASE_MHZ"] == "2100"
    assert facts["WORKER_CPU_MAX_MHZ"] == "4000"
    assert facts["WORKER_CPU_CUR_MHZ"] == "1800"
    # The unique governor set across CPUs, not one sampled CPU.
    assert facts["WORKER_CPU_GOVERNOR"] == "performance,powersave"


def test_rapl_reads_long_term_package_limits_only(tmp_path: Path) -> None:
    make_x86_root(tmp_path)
    facts = run_inventory(tmp_path, X86_LSCPU)

    # Two package domains; dram and psys domains are not counted.
    assert facts["WORKER_CPU_RAPL_PACKAGES"] == "2"
    # package-1 long_term sits on constraint_1 behind a short_term
    # constraint_0; the check must pick 300 W, not 400 W. The unequal
    # per-package limits (an OEM misconfiguration) both surface.
    assert facts["WORKER_CPU_PACKAGE_POWER_LIMIT_W"] == "350,300"


def test_rapl_falls_back_to_constraint_zero_without_long_term(tmp_path: Path) -> None:
    write_rapl_domain(
        tmp_path / "sys" / "class" / "powercap",
        "intel-rapl:0",
        "package-0",
        {0: ("peak_power", 500000000)},
    )
    facts = run_inventory(tmp_path, "")
    assert facts["WORKER_CPU_RAPL_PACKAGES"] == "1"
    assert facts["WORKER_CPU_PACKAGE_POWER_LIMIT_W"] == "500"


def test_arm_falls_back_to_lscpu_for_model_and_sockets(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir(parents=True)
    (tmp_path / "proc" / "cpuinfo").write_text(ARM_CPUINFO)
    facts = run_inventory(tmp_path, ARM_LSCPU)

    # ARM cpuinfo has no "model name" or "physical id"; lscpu resolves both.
    assert facts["WORKER_CPU_MODEL"] == "Neoverse-V2"
    assert facts["WORKER_CPU_SOCKETS"] == "2"
    assert facts["WORKER_CPU_CORES_PER_SOCKET"] == "72"
    assert facts["WORKER_CPU_THREADS_PER_CORE"] == "1"
    # Thread count still comes from the re-rooted cpuinfo processor lines.
    assert facts["WORKER_CPU_THREADS"] == "4"


def test_missing_everything_degrades_to_unknown(tmp_path: Path) -> None:
    facts = run_inventory(tmp_path, "")

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
    # Fields the existing block does not carry are still filled additively.
    assert cpu["sockets"] == "2"


def test_k8s_remap_without_cpu_keys_adds_no_block() -> None:
    audit = {"hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"}}
    merge_audit.remap_k8s_canonical(audit)
    assert "computeNodeCpu" not in audit
