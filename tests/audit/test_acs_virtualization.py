"""Behavioral tests for the PCIe ACS virtualization handling.

Two real blocks are executed with stubs, instead of pinning source fragments:

1. host-check.sh sets WORKER_ACS_VIRTUALIZED from systemd-detect-virt and, when
   that returns "docker" inside a pod, from the emulated QEMU PCI host bridge.
2. cluster-audit-slurm.sh reports the unresolved-topology ACS case as info
   ("not applicable") on a virtualized node, and keeps the warning on bare metal.

The guarded incident: on an SR-IOV / passthrough VM the guest cannot see the
real GPU<->NIC PCIe switch, so the ACS topology never resolves. That is not a
tenant finding; the old code warned "topology not resolved" anyway.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

VIRT_BLOCK = bashtest.extract_block(
    WORKLOAD / "host-check.sh",
    "WORKER_ACS_VIRTUALIZED=false",
    "# Helper: given a PCI endpoint sysfs dir",
)

DISPLAY_BLOCK = (
    bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm.sh",
        'if [[ "${WORKER_ACS_VIRTUALIZED:-false}" == "true"',
        "Check manually which switch the GPU and its backend NIC share",
    )
    + "\nfi\n"
)

PRINT_STUBS = {"print_info": "", "print_warn": "", "print_detail": ""}

BARE_METAL_LSPCI = "00:00.0 Host bridge: Intel Corporation Device 09a2\n"
QEMU_LSPCI = "00:00.0 Host bridge: Red Hat, Inc. QEMU PCIe Host bridge\n"


def detect_virt(virt: str, lspci_out: str) -> str:
    stubs = {"systemd-detect-virt": f'echo "{virt}"', "lspci": f'printf %s {shquote(lspci_out)}'}
    run = bashtest.run_bash(VIRT_BLOCK + '\nprintf %s "$WORKER_ACS_VIRTUALIZED"', stubs=stubs)
    assert run.returncode == 0, run.stderr
    return run.stdout.strip()


def shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def run_display(virtualized: str, scoped: str) -> bashtest.BashRun:
    prelude = (
        f'WORKER_ACS_VIRTUALIZED="{virtualized}"\n'
        f'WORKER_ACS_SCOPED="{scoped}"\n'
        'WORKER_ACS_TOTAL_BRIDGES="29"\n'
    )
    return bashtest.run_bash(prelude + DISPLAY_BLOCK, stubs=PRINT_STUBS)


def test_systemd_detect_virt_qemu_is_virtualized() -> None:
    assert detect_virt("qemu", BARE_METAL_LSPCI) == "true"


def test_pod_on_vm_falls_back_to_emulated_host_bridge() -> None:
    # systemd-detect-virt reports "docker" inside the pod; the QEMU host bridge
    # still marks the node virtualized.
    assert detect_virt("docker", QEMU_LSPCI) == "true"


def test_bare_metal_is_not_virtualized() -> None:
    assert detect_virt("none", BARE_METAL_LSPCI) == "false"


def test_virtualized_unresolved_topology_is_info_not_warn() -> None:
    run = run_display("true", "false")
    assert run.calls("print_info"), "virtualized ACS should report at info severity"
    assert not run.calls("print_warn"), "virtualized ACS must not warn"
    info_text = " ".join(" ".join(c) for c in run.calls("print_info"))
    assert "not applicable" in info_text


def test_bare_metal_unresolved_topology_still_warns() -> None:
    run = run_display("false", "false")
    assert run.calls("print_warn"), "bare-metal unresolved topology should still warn"
    assert not run.calls("print_info")


def test_scoped_topology_takes_neither_branch() -> None:
    # When the topology did resolve, neither the info nor the warn branch fires
    # (the later scoped branches, not in this extract, handle it).
    run = run_display("true", "true")
    assert not run.calls("print_info")
    assert not run.calls("print_warn")
