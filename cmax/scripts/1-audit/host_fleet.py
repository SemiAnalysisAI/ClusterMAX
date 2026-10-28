"""Grade host-kernel CVE evidence for every node the audit can reach.

The sampled GPU worker is enough to describe a cluster's hardware, but not its
security posture: one unpatched worker or control-plane host defeats the tenant
boundary. This module consumes the passive facts collected from every host and
returns the host-kernel verdicts together, so a caller cannot accidentally
publish a sampled result as a fleet result.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pwnescape


def _fragnesia_host(host: dict[str, Any], grace: bool) -> dict[str, Any]:
    """Grade one host's Ubuntu Noble kernel package ABI against the floor."""
    entry = pwnescape._host_entry(host)
    facts = pwnescape.parse_facts(str(host.get("facts") or ""))
    if not host.get("checked") or "WORKER_GUEST_KERNEL_RUNNING" not in facts:
        return entry
    status = facts.get("WORKER_FRAGNESIA_STATUS", "unknown")
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    virtualization = facts.get("WORKER_VIRT_TYPE", "unknown")
    abi = facts.get("WORKER_FRAGNESIA_ABI", "unknown")
    floor = facts.get("WORKER_FRAGNESIA_ABI_FLOOR", "unknown")
    if status == "fail" and grace:
        status = "pass"
        reason = (
            f"The running kernel {running} is below the Fragnesia fixed ABI {floor}, "
            "but the fix is still inside the published grace period."
        )
    elif status == "fail":
        reason = f"The running kernel {running} is below the Fragnesia fixed ABI {floor}."
    elif status == "pass":
        reason = f"The running kernel {running} meets the Fragnesia fixed ABI {floor}."
    elif status == "not-applicable":
        reason = f"The running kernel {running} is outside the Ubuntu Noble 6.8 Fragnesia scope."
    else:
        reason = (
            f"The running kernel {running} needs the Fragnesia fixed ABI; "
            "the distribution package level could not be compared."
        )
    entry.update(
        status=status,
        reason=reason,
        minimum=floor,
        localKernelStatus=status,
        virtualization=virtualization,
        abi=abi,
        abiFloor=floor,
    )
    return entry


def _januscape_host(host: dict[str, Any]) -> dict[str, Any]:
    """Grade one host's nested-virtualization exposure from the passive facts."""
    entry = pwnescape._host_entry(host)
    facts = pwnescape.parse_facts(str(host.get("facts") or ""))
    if not host.get("checked") or "WORKER_GUEST_KERNEL_RUNNING" not in facts:
        return entry
    exposed = facts.get("WORKER_JANUSCAPE_EXPOSED", "unknown")
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    if exposed == "true":
        status = "fail"
        reason = "Nested virtualization exposes the Januscape attack surface on this host."
    elif exposed == "false":
        status = "pass"
        reason = "The host does not expose the complete Januscape attack prerequisites."
    else:
        status = "unknown"
        reason = "The host's nested-virtualization state could not be established."
    entry.update(
        status=status,
        reason=reason,
        minimum="host-kernel-fix",
        localKernelStatus=status,
        exposed=exposed,
        cpuVirtualizationExposed=facts.get("WORKER_NESTED_CPU_EXPOSED", "unknown"),
        kvmDeviceExposed=facts.get("WORKER_KVM_DEVICE", "unknown"),
        module=facts.get("WORKER_NESTED_MODULE", "none"),
        nestedEnabled=facts.get("WORKER_NESTED_ENABLED", "unknown"),
    )
    return entry


def _fleet(
    entries: list[dict[str, Any]],
    control_plane: dict[str, Any],
    *,
    label: str,
    pass_statuses: set[str],
    fail_statuses: set[str],
    clean: str,
) -> dict[str, Any]:
    control_entries = [entry for entry in entries if entry["role"] == "control-plane"]
    checked = [entry for entry in entries if entry["checked"]]
    unassessed = [entry for entry in entries if not entry["checked"]]
    failing = [entry for entry in checked if entry["status"] in fail_statuses]
    unknown = [entry for entry in checked if entry["status"] not in pass_statuses | fail_statuses]
    control_discovered = bool(control_plane.get("discovered")) and bool(control_entries)
    coverage_complete = bool(entries) and not unassessed and (
        control_discovered and all(entry["checked"] for entry in control_entries)
    )
    if failing:
        status = "fail"
    elif not coverage_complete:
        status = "coverage-incomplete"
    elif unknown:
        status = "unknown"
    else:
        status = "pass"
    reasons: list[str] = []
    if failing:
        reasons.append(
            f"{len(failing)} host(s) fail the {label} check: {pwnescape._names(failing)}."
        )
    elif unassessed:
        reasons.append(
            f"The audit could not read {len(unassessed)} host(s): {pwnescape._names(unassessed)}. "
            "Request the running-kernel build and CVE-specific patch evidence for each one."
        )
    if not control_discovered:
        reasons.append(
            str(control_plane.get("detail") or "The audit could not find the control-plane hosts.")
            + " Request the running-kernel build and CVE-specific patch evidence for every control-plane host."
        )
    roles: dict[str, dict[str, int]] = {}
    for entry in entries:
        counts = roles.setdefault(entry["role"], {"total": 0, "checked": 0, "failing": 0})
        counts["total"] += 1
        counts["checked"] += int(entry["checked"])
        counts["failing"] += int(entry["status"] in fail_statuses)
    return {
        "status": status,
        "reason": " ".join(reasons) if reasons else clean,
        "scope": "fleet",
        "nodesTotal": len(entries),
        "nodesChecked": len(checked),
        "coverageComplete": coverage_complete,
        "failingNodes": [entry["node"] for entry in failing],
        "unassessedNodes": [entry["node"] for entry in unassessed],
        "roles": roles,
        "controlPlane": {
            "discovered": control_discovered,
            "coverageComplete": control_discovered and all(entry["checked"] for entry in control_entries),
            "hosts": [entry["node"] for entry in control_entries],
            "detail": str(control_plane.get("detail") or ""),
        },
        "hosts": entries,
        "exploitTested": False,
    }


def grade_fleet(
    hosts: list[dict[str, Any]],
    control_plane: dict[str, Any],
    fragnesia_abi_floor: str = "unknown",
    fragnesia_grace: bool = False,
) -> dict[str, Any]:
    pwn = pwnescape.grade_fleet(hosts, control_plane)

    frag_entries = [_fragnesia_host(host, fragnesia_grace) for host in hosts]
    frag = _fleet(
        frag_entries,
        control_plane,
        label="Fragnesia",
        pass_statuses={"pass", "not-applicable"},
        fail_statuses={"fail"},
        clean="Every audited host is outside the Fragnesia scope or meets its fixed ABI.",
    )
    frag_passes = [entry for entry in frag_entries if entry["checked"] and entry["status"] == "pass"]
    if frag["status"] == "pass" and not frag_passes:
        frag["status"] = "not-applicable"
    frag["cve"] = "CVE-2026-46300"
    frag["abiFloor"] = fragnesia_abi_floor

    jan_entries = [_januscape_host(host) for host in hosts]
    jan = _fleet(
        jan_entries,
        control_plane,
        label="Januscape",
        pass_statuses={"pass"},
        fail_statuses={"fail"},
        clean="No audited host exposes the complete Januscape attack prerequisites.",
    )
    exposed_entries = [
        entry for entry in jan_entries if entry["checked"] and entry.get("exposed") == "true"
    ]
    unknown_entries = [
        entry for entry in jan_entries if entry["checked"] and entry.get("exposed") == "unknown"
    ]
    if exposed_entries:
        jan["exposed"] = True
    elif unknown_entries or not jan["coverageComplete"]:
        jan["exposed"] = "unknown"
    else:
        jan["exposed"] = False
    jan["cve"] = "CVE-2026-53359"

    return {
        "pwnescape": pwn,
        "fragnesia": frag,
        "januscape": jan,
    }


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (ValueError, TypeError):
        raise SystemExit("host_fleet.py expects a JSON document on stdin")
    hosts = payload.get("hosts") or []
    control = payload.get("controlPlane") or {}
    floor = str(payload.get("fragnesiaAbiFloor") or "unknown")
    grace = payload.get("fragnesiaGrace") is True
    print(json.dumps(grade_fleet(hosts, control, floor, grace), sort_keys=True))


if __name__ == "__main__":
    main()
