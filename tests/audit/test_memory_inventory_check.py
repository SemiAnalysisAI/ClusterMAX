"""Behavioral tests for the compute-node memory inventory.

Two surfaces are exercised, per the repo testing doctrine (real code under
stubs, no assertIn source pinning):

1. host-check.sh collect_memory_inventory() runs with a stubbed dmidecode
   and a fake EDAC sysfs tree (CLUSTERMAX_AUDIT_ROOT), covering the SMBIOS
   Memory Device parsing, the old "Configured Clock Speed" label, the EDAC
   fallback, and the everything-missing degradation to "unknown".
2. merge_audit.py remap_k8s_canonical() folds hostCheck.WORKER_MEM_* onto
   the canonical audit_data.computeNodeMemory block the slurm and
   standalone collectors emit directly, without overwriting existing
   values.

The guarded incident: a provider can populate fewer memory channels than
the platform offers or run modules below their rated speed. Both cut the
memory bandwidth ceiling (channels x MT/s x 8 bytes) and are invisible in
STREAM results alone. The audit must record the populated DIMM count and
the configured speed next to the rated speed, count populated slots only,
and degrade to "unknown" instead of failing the check.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

MEM_FUNC = bashtest.extract_function(
    WORKLOAD / "host-check.sh", "collect_memory_inventory"
)


def shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


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

# SMBIOS type 17 also lists firmware chips. This record must never count
# as a DIMM, leak its type, or surface kB as thousands of GB.
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


def run_inventory(
    root: Path, dmidecode_body: str, sockets: str = "", threads: str = ""
) -> dict[str, str]:
    # sudo is stubbed to fail so the elevation retry never leaves the
    # sandbox; the dedicated sudo test provides a working stub.
    run = bashtest.run_bash(
        MEM_FUNC + f"\ncollect_memory_inventory '{sockets}' '{threads}'",
        stubs={"dmidecode": dmidecode_body, "sudo": "exit 1"},
        env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
    )
    assert run.returncode == 0, run.stderr
    facts = {}
    for line in run.stdout.splitlines():
        key, _, value = line.partition("=")
        facts[key] = value
    return facts


def test_dmidecode_counts_populated_slots_and_unique_speeds(tmp_path: Path) -> None:
    # 3 populated DIMMs and 1 empty slot. One module runs configured below
    # its rated 6400 MT/s (the guarded incident), and one reports its size
    # in MB, which older firmware does.
    dmi = (
        "# dmidecode 3.4\n"
        "Getting SMBIOS data from sysfs.\n"
        + dmi_device("64 GB", "DDR5", "6400 MT/s", "6400 MT/s")
        + dmi_device("64 GB", "DDR5", "6400 MT/s", "4800 MT/s")
        + dmi_device("32768 MB", "DDR5", "6400 MT/s", "6400 MT/s")
        + EMPTY_SLOT
        + FLASH_ROM
    )
    facts = run_inventory(tmp_path, f"printf %s {shquote(dmi)}", sockets="2", threads="32")

    # The empty slot must not count and its Unknown speeds must not surface.
    assert facts["WORKER_MEM_DIMMS"] == "3"
    # MB sizes are converted to GB; sizes are a unique sorted set.
    assert facts["WORKER_MEM_DIMM_SIZES_GB"] == "32,64"
    assert facts["WORKER_MEM_TYPES"] == "DDR5"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "6400"
    # Both configured speeds surface, so the below-rated module is visible.
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "4800,6400"
    # Bandwidth uses the lowest configured speed: 3 DIMMs x 4800 MT/s x 8 B
    # = 115.2 GB/s node; /2 sockets = 57.6; /32 logical cores = 3.6.
    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "57.6"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "3.60"
    assert facts["WORKER_MEM_SOURCE"] == "dmidecode"


def test_old_dmidecode_configured_clock_speed_label(tmp_path: Path) -> None:
    # dmidecode before 3.1 prints "Configured Clock Speed" with an MHz unit.
    dmi = dmi_device(
        "32 GB",
        "DDR4",
        "2933 MT/s",
        "2400 MHz",
        configured_label="Configured Clock Speed",
    )
    facts = run_inventory(tmp_path, f"printf %s {shquote(dmi)}", sockets="1")

    assert facts["WORKER_MEM_DIMMS"] == "1"
    assert facts["WORKER_MEM_TYPES"] == "DDR4"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "2933"
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "2400"
    # 1 DIMM x 2400 MT/s x 8 B = 19.2 GB/s. No thread count was passed
    # (the CPU check degraded), so the per-core figure stays unknown.
    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "19.2"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "unknown"
    assert facts["WORKER_MEM_SOURCE"] == "dmidecode"


def test_unprivileged_check_elevates_with_passwordless_sudo(tmp_path: Path) -> None:
    # Slurm and standalone checks run as the operator user: plain dmidecode
    # fails, and the check must retry through passwordless sudo.
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
    # Without root, dmidecode exits nonzero. The rootless EDAC sysfs tree
    # still yields count, sizes, and types - no speeds.
    make_edac_dimm(tmp_path, 0, 0, "65536", "DDR5")
    make_edac_dimm(tmp_path, 0, 1, "65536", "DDR5")
    make_edac_dimm(tmp_path, 1, 0, "65536", "Unknown")
    # A zero-size entry is an unpopulated slot and must not count.
    make_edac_dimm(tmp_path, 1, 1, "0", "Unknown")
    facts = run_inventory(tmp_path, "exit 1", sockets="2", threads="64")

    assert facts["WORKER_MEM_DIMMS"] == "3"
    assert facts["WORKER_MEM_DIMM_SIZES_GB"] == "64"
    assert facts["WORKER_MEM_TYPES"] == "DDR5"
    assert facts["WORKER_MEM_RATED_SPEED_MTS"] == "unknown"
    assert facts["WORKER_MEM_CONFIGURED_SPEED_MTS"] == "unknown"
    # EDAC carries no speed, so no bandwidth can be derived.
    assert facts["WORKER_MEM_BW_PER_SOCKET_GBS"] == "unknown"
    assert facts["WORKER_MEM_BW_PER_CORE_GBS"] == "unknown"
    assert facts["WORKER_MEM_SOURCE"] == "edac"


def test_missing_everything_degrades_to_unknown(tmp_path: Path) -> None:
    facts = run_inventory(tmp_path, "exit 1")

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


MERGE_PATH = WORKLOAD / "merge_audit.py"


def load_merge_module():
    spec = importlib.util.spec_from_file_location(
        "merge_audit_memory_under_test", MERGE_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


merge_audit = load_merge_module()


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
    # Fields the existing block does not carry are still filled additively.
    assert memory["types"] == "DDR5"


def test_k8s_remap_without_memory_keys_adds_no_block() -> None:
    audit = {"hostCheck": {"WORKER_DRIVER_VERSION": "590.48.01"}}
    merge_audit.remap_k8s_canonical(audit)
    assert "computeNodeMemory" not in audit
