"""Grade the AMD KVM host configuration and kernel for CVE-2026-99312."""

from __future__ import annotations

import json
import re
import sys

import minimum_versions

CVE = "CVE-2026-99312"
COMPONENT = "linuxKvmSvm"
RELEASE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?(?:-rc([1-9]\d*))?")


def _release(value: object) -> tuple[int, int, int, int] | None:
    match = RELEASE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    major, minor, patch, rc = match.groups()
    # An RC precedes the final release on the same branch.
    return int(major), int(minor), int(patch or 0), int(rc) if rc else sys.maxsize


def _kernel_grade(running: str) -> tuple[str, str, str]:
    observed = _release(running)
    if observed is None:
        return "unknown", "unknown", "Obtain the vendor patch status for the running kernel build."
    try:
        entry = minimum_versions.component(COMPONENT)
        branches = entry["branches"]
        affected_from = entry["affectedFrom"]
        affected_since = _release(entry["affectedSince"])
        mainline = _release(entry["mainline"])
        if not isinstance(branches, dict) or not isinstance(affected_from, dict):
            raise ValueError("invalid CVE branch table")
        if entry.get("cve") != CVE or affected_since is None or mainline is None:
            raise ValueError("invalid CVE policy")
    except (minimum_versions.MinimumDataError, KeyError, OSError, TypeError, ValueError):
        return "unknown", "unknown", "The minimum table has no usable policy for this CVE."

    branch = f"{observed[0]}.{observed[1]}"
    first_on_branch = _release(affected_from.get(branch))
    if branch in affected_from and (first_on_branch is None or first_on_branch[:2] != observed[:2]):
        return "unknown", "unknown", "The minimum table has an invalid affected range for this branch."
    if first_on_branch is not None and observed < first_on_branch and observed < affected_since:
        # The bug reached this older branch in a backport. A release before that
        # backport is not affected, even when the branch also has a fixed release.
        return "not-applicable", "unknown", "The running upstream kernel predates the affected releases."
    floor_text = entry["mainline"] if observed[:2] >= mainline[:2] else branches.get(branch)
    if floor_text is not None:
        floor = _release(floor_text)
        if floor is None or (branch in branches and floor[:2] != observed[:2]):
            return "unknown", "unknown", "The minimum table has an invalid floor for this branch."
        if observed >= floor:
            return "pass", floor_text, f"The running upstream kernel meets the {floor_text} minimum."
        return "fail", floor_text, f"The running upstream kernel is below the {floor_text} minimum."

    if observed[-1] != sys.maxsize:
        return "unknown", "unknown", "The minimum table does not grade this release candidate."
    if observed >= affected_since or (first_on_branch is not None and observed >= first_on_branch):
        return "fail", "unknown", "This upstream branch is affected and has no listed fixed release."
    return "not-applicable", "unknown", "The running upstream kernel predates the affected releases."


def grade(facts: dict[str, str]) -> dict[str, str | bool]:
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    virt = facts.get("WORKER_VIRT_TYPE", "unknown")
    livepatch = facts.get("WORKER_PWNESCAPE_LIVEPATCH", "unknown")
    cpu = facts.get("WORKER_CPU_VENDOR", "unknown")
    module = facts.get("WORKER_NESTED_MODULE", "unknown")
    nested = facts.get("WORKER_NESTED_ENABLED", "unknown")
    physical = facts.get("WORKER_VIRT_GUEST") == "false" and virt == "none"
    status, local, minimum = "unknown", "unknown", "unknown"
    if cpu == "GenuineIntel" and module == "kvm_intel":
        # kvm_intel loads only on Intel VMX, which an AMD host cannot give to a
        # guest. The answer holds when the audit cannot prove bare metal.
        status, reason = "not-applicable", "The host has an Intel CPU and the Intel KVM module."
    elif not physical:
        reason = "The physical host is unverified. Request its CPU, nesting state, and running kernel build."
    elif cpu == "GenuineIntel" and module == "kvm_amd":
        reason = "The CPU vendor and the KVM module do not agree. Obtain host configuration evidence."
    elif cpu == "GenuineIntel":
        status, reason = "not-applicable", "The physical host has an Intel CPU."
    elif module == "kvm_amd" and nested == "false":
        status, reason = "not-applicable", "The AMD KVM module reports nested virtualization disabled."
    elif (
        cpu == "AuthenticAMD"
        and module == "none"
        and facts.get("WORKER_KVM_AMD_LOADED") == "false"
        and facts.get("WORKER_KVM_DEVICE") == "false"
    ):
        status, reason = "not-applicable", "The AMD KVM module and device are absent on the physical host."
    elif module != "kvm_amd" or nested != "true":
        reason = "The audit could not verify the AMD KVM nesting state."
    elif facts.get("WORKER_PWNESCAPE_PACKAGE", "unknown") != "unknown" or (
        facts.get("WORKER_PWNESCAPE_SIGNATURE", "unknown").startswith("Ubuntu ")
    ):
        reason = "Obtain the vendor patch status for the running distribution kernel build."
    else:
        status, minimum, reason = _kernel_grade(running)
        local = status
        if status == "fail" and livepatch not in {"none", "not-supported"}:
            status = "unknown"
            reason = "The kernel is below the upstream minimum. Obtain evidence about the running livepatch state."

    return {
        "cve": CVE,
        "status": status,
        "reason": reason,
        "runningKernel": running,
        "minimum": minimum,
        "localKernelStatus": local,
        "virtualization": virt,
        "cpuVendor": cpu,
        "module": module,
        "nestedEnabled": nested,
        "livepatch": livepatch,
        "scope": "physical-host" if physical else "unverified-host",
        "exploitTested": False,
    }


if __name__ == "__main__":
    facts = {}
    for line in sys.stdin:
        key, separator, value = line.rstrip("\n").partition("=")
        if separator and key.startswith("WORKER_"):
            facts[key] = "unknown" if key in facts and facts[key] != value else value
    print(json.dumps(grade(facts)))
