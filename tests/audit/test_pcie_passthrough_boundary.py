#!/usr/bin/env python3
"""The PCIe passthrough check separates an absent guest from missing evidence.

The check grades a hypervisor passthrough boundary. On a bare-metal Kubernetes
worker that the tenant reaches directly, the sampled node is the physical host
and no guest consumes a VFIO device. An inventory that stays ``unknown`` there
must not read as a failure.

The distinction that matters is the guest, not the inventory. A real guest that
uses passthrough with an incomplete inventory stays a warning, because the
missing scan is the only thing that could clear it.
"""

from __future__ import annotations

import json
from pathlib import Path

from cmax import audit_report, security

CASES = Path(__file__).parent / "fixtures" / "pcie-passthrough-boundary.json"


def load_case(name: str) -> dict:
    return json.loads(CASES.read_text())[name]


def test_bare_metal_host_with_no_guest_is_not_applicable() -> None:
    status, observed, assessment = security._pcie_boundary(
        load_case("bare_metal_host_no_guest")
    )
    assert status == security.NOT_APPLICABLE
    assert "target guest=false" in observed
    assert "VFIO devices=0" in observed
    assert "no guest consumes" in assessment


def test_guest_with_passthrough_and_incomplete_inventory_stays_warning() -> None:
    status, observed, _ = security._pcie_boundary(
        load_case("guest_passthrough_incomplete_inventory")
    )
    assert status == security.WARNING
    assert "target guest=true" in observed
    assert "inventory complete=unknown" in observed


def _report_check(values: dict, environment: str) -> audit_report.AuditCheck:
    return next(
        check
        for check in audit_report.evaluate(
            values,
            security.find_runtime_root(),
            harness="standalone",
            environment=environment,
        )
        if check.key == "pcie-passthrough"
    )


def test_container_on_a_vm_is_skipped_like_the_vm_target() -> None:
    """The guest flag, not the target flag, decides the report skip."""
    values = {
        "cluster": {"orchestrator": "standalone", "environment": "container"},
        "audit_data": {
            "security": {
                "virtualization": {"guest": True},
                "pciePassthrough": {"hostVerificationRequired": True},
            }
        },
    }
    container = _report_check(values, "container")
    vm = _report_check(values, "vm")
    assert container.status == vm.status == audit_report.SKIPPED
    assert container.observed == vm.observed == "running in a VM"

    values["audit_data"]["security"]["virtualization"]["guest"] = False
    assert _report_check(values, "container").status != audit_report.SKIPPED
