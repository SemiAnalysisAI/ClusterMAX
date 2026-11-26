"""Grade host-kernel CVE evidence for every node the audit can reach.

The sampled GPU worker is enough to describe a cluster's hardware, but not its
security posture: one unpatched worker or control-plane host defeats the tenant
boundary. This module consumes the passive facts collected from every host and
returns the host-kernel verdicts together, so a caller cannot accidentally
publish a sampled result as a fleet result.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

sys.path.insert(0, os.path.dirname(__file__))

import kvm_svm
import pwnescape
import sctp_sendall


def parse_facts(text: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.startswith("WORKER_"):
            if key in facts and facts[key] != value:
                facts[key] = "unknown"
            else:
                facts[key] = value
    return facts


def _unchecked(host: dict[str, Any], error: str) -> dict[str, Any]:
    return {
        "node": str(host.get("node") or "unknown"),
        "role": str(host.get("role") or "worker"),
        "checked": False,
        "status": "unassessed",
        "error": error,
    }


def _entry(host: dict[str, Any], grader: Callable[[dict[str, str]], dict[str, Any]]) -> dict[str, Any]:
    node = str(host.get("node") or "unknown")
    role = str(host.get("role") or "worker")
    facts = parse_facts(str(host.get("facts") or ""))
    if not host.get("checked") or "WORKER_GUEST_KERNEL_RUNNING" not in facts:
        return _unchecked(
            host,
            str(host.get("error") or "The host returned no kernel facts."),
        )
    value = grader(facts)
    return {
        "node": node,
        "role": role,
        "checked": True,
        "status": value.get("status", "unknown"),
        "runningKernel": value.get("runningKernel", "unknown"),
        "minimum": value.get("minimum", "unknown"),
        "localKernelStatus": value.get("localKernelStatus", "unknown"),
        "virtualization": value.get("virtualization", "unknown"),
        "livepatch": value.get("livepatch", "unknown"),
        "reason": value.get("reason", ""),
        "facts": value,
    }


def _coverage(entries: list[dict[str, Any]], control_plane: dict[str, Any]) -> tuple[bool, bool, list[dict[str, Any]]]:
    control_entries = [entry for entry in entries if entry["role"] == "control-plane"]
    control_discovered = bool(control_plane.get("discovered")) and bool(control_entries)
    control_complete = control_discovered and all(entry["checked"] for entry in control_entries)
    unassessed = [entry for entry in entries if not entry["checked"]]
    coverage_complete = bool(entries) and not unassessed and control_complete
    return coverage_complete, control_discovered, control_entries


def _names(entries: list[dict[str, Any]], limit: int = 10) -> str:
    names = [str(entry["node"]) for entry in entries]
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _reasons(
    label: str,
    failing: list[dict[str, Any]],
    unassessed: list[dict[str, Any]],
    control_discovered: bool,
    control_plane: dict[str, Any],
    clean: str,
) -> str:
    reasons: list[str] = []
    if failing:
        reasons.append(
            f"{len(failing)} host(s) fail the {label} check: {_names(failing)}."
        )
    elif unassessed:
        reasons.append(
            f"The audit could not read {len(unassessed)} host(s): {_names(unassessed)}. "
            "Request the running-kernel build and CVE-specific patch evidence for each one."
        )
    if not control_discovered:
        reasons.append(
            str(control_plane.get("detail") or "The audit could not find the control-plane hosts.")
            + " Request the running-kernel build and CVE-specific patch evidence for every control-plane host."
        )
    return " ".join(reasons) if reasons else clean


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
    coverage_complete, control_discovered, _ = _coverage(entries, control_plane)
    if failing:
        status = "fail"
    elif not coverage_complete:
        status = "coverage-incomplete"
    elif unknown:
        status = "unknown"
    elif all(entry["status"] in pass_statuses for entry in checked):
        status = "pass"
    else:
        status = "unknown"
    worst = (failing or unknown or checked or [{}])[0]
    roles: dict[str, dict[str, int]] = {}
    for entry in entries:
        counts = roles.setdefault(entry["role"], {"total": 0, "checked": 0, "failing": 0})
        counts["total"] += 1
        counts["checked"] += int(entry["checked"])
        counts["failing"] += int(entry["status"] in fail_statuses)
    return {
        "status": status,
        "reason": _reasons(
            label,
            failing,
            unassessed,
            control_discovered,
            control_plane,
            clean,
        ),
        "scope": "fleet",
        "runningKernel": worst.get("runningKernel", "unknown"),
        "runningKernels": sorted({entry["runningKernel"] for entry in checked}),
        "localKernelStatus": worst.get("localKernelStatus", "unknown"),
        "minimum": worst.get("minimum", "unknown"),
        "virtualization": worst.get("virtualization", "unknown"),
        "livepatch": worst.get("livepatch", "unknown"),
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


def _sctp_host(host: dict[str, Any]) -> dict[str, Any]:
    return _entry(host, sctp_sendall.grade)


def _fragnesia_host(host: dict[str, Any], grace: bool) -> dict[str, Any]:
    def grade(facts: dict[str, str]) -> dict[str, Any]:
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
        return {
            "status": status,
            "reason": reason,
            "runningKernel": running,
            "minimum": floor,
            "localKernelStatus": status,
            "virtualization": virtualization,
            "livepatch": "unknown",
            "abi": abi,
            "abiFloor": floor,
        }

    return _entry(host, grade)


def _januscape_host(host: dict[str, Any]) -> dict[str, Any]:
    def grade(facts: dict[str, str]) -> dict[str, Any]:
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
        return {
            "status": status,
            "reason": reason,
            "runningKernel": running,
            "minimum": "host-kernel-fix",
            "localKernelStatus": status,
            "virtualization": facts.get("WORKER_VIRT_TYPE", "unknown"),
            "livepatch": "unknown",
            "exposed": exposed,
            "cpuVirtualizationExposed": facts.get("WORKER_NESTED_CPU_EXPOSED", "unknown"),
            "kvmDeviceExposed": facts.get("WORKER_KVM_DEVICE", "unknown"),
            "module": facts.get("WORKER_NESTED_MODULE", "none"),
            "nestedEnabled": facts.get("WORKER_NESTED_ENABLED", "unknown"),
        }

    return _entry(host, grade)


def grade_fleet(
    hosts: list[dict[str, Any]],
    control_plane: dict[str, Any],
    fragnesia_abi_floor: str = "unknown",
    fragnesia_grace: bool = False,
) -> dict[str, Any]:
    pwn = pwnescape.grade_fleet(hosts, control_plane)
    sctp_entries = [_sctp_host(host) for host in hosts]
    sctp = _fleet(
        sctp_entries,
        control_plane,
        label="SCTP SCTP_SENDALL",
        pass_statuses={"pass"},
        fail_statuses={"fail"},
        clean="Every audited worker and control-plane host meets the SCTP SCTP_SENDALL minimum.",
    )
    sctp.update(
        {
            "cve": sctp_sendall.CVE,
            "advisory": sctp_sendall.ADVISORY,
            "cnaRecord": sctp_sendall.CNA_RECORD,
            "minimumsReviewedAt": "2026-10-21",
            "fixSubject": sctp_sendall.FIX_SUBJECT,
        }
    )

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
        entry for entry in jan_entries if entry["checked"] and entry["facts"].get("exposed") == "true"
    ]
    unknown_entries = [
        entry for entry in jan_entries if entry["checked"] and entry["facts"].get("exposed") == "unknown"
    ]
    if exposed_entries:
        jan["exposed"] = True
    elif unknown_entries or not jan["coverageComplete"]:
        jan["exposed"] = "unknown"
    else:
        jan["exposed"] = False
    jan["cve"] = "CVE-2026-53359"

    kvm_entries = [_entry(host, kvm_svm.grade) for host in hosts]
    kvm = _fleet(
        kvm_entries,
        control_plane,
        label=kvm_svm.CVE,
        pass_statuses={"pass", "not-applicable"},
        fail_statuses={"fail"},
        clean="Every audited host meets the minimum or is outside the scope of this CVE.",
    )
    unknown = [entry for entry in kvm_entries if entry["status"] == "unknown"]
    kvm["cve"] = kvm_svm.CVE
    kvm["unknownNodes"] = [entry["node"] for entry in unknown]
    if kvm["status"] == "unknown":
        kvm["reason"] = (
            f"The audit could not verify CVE evidence on {_names(unknown)}. "
            "Request the physical host nesting state and running kernel build."
        ) if unknown else "The audit could not verify CVE evidence."
    elif kvm["status"] == "pass":
        passing = next((entry for entry in kvm_entries if entry["status"] == "pass"), None)
        if passing is None:
            kvm["status"] = "not-applicable"
            kvm["reason"] = "Every audited host is outside the scope of this CVE."
        else:
            for key in ("runningKernel", "minimum", "localKernelStatus", "virtualization", "livepatch"):
                kvm[key] = passing[key]
    return {
        "pwnescape": pwn,
        "sctpSendall": sctp,
        "fragnesia": frag,
        "januscape": jan,
        "kvmSvm": kvm,
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
