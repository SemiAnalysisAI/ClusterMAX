"""Grade passive evidence for CVE-2026-99999 without sending probe traffic."""

from __future__ import annotations

import json
import re
import sys


CVE = "CVE-2026-99999"
ADVISORY = "https://nvd.nist.gov/vuln/detail/CVE-2026-99999"
CNA_RECORD = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/99xxx/CVE-2026-99999.json"
FIX_COMMIT = "6785011f8b16abf40b1e9d8b2e332232b3e68822"
# These are upstream releases, not distribution package versions. The kernel
# CNA record lists each stable branch separately. Never compare across trains.
FIXED_RELEASES = {
    "5.10": "5.10.272",
    "5.15": "5.15.223",
    "6.1": "6.1.190",
    "6.6": "6.6.159",
    "6.12": "6.12.113",
    "6.18": "6.18.57",
    "7.2": "7.2.11",
}


def grade(facts: dict[str, str]) -> dict:
    """Keep the observed worker kernel separate from a hidden outer host."""
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    guest = facts.get("WORKER_VIRT_GUEST", "unknown")
    technology = facts.get("WORKER_VIRT_TYPE", "unknown")
    livepatch = facts.get("WORKER_PWNESCAPE_LIVEPATCH", "unknown")
    local_status = "unknown"
    minimum = "unknown"
    reason = (
        "The distribution or custom kernel needs vendor evidence for this CVE. "
        "Upstream versions do not establish distribution backport status."
    )
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", running)
    if match:
        branch = ".".join(match.groups()[:2])
        minimum = FIXED_RELEASES.get(branch, "unknown")
        if minimum != "unknown":
            observed = tuple(map(int, match.groups()))
            fixed = tuple(map(int, minimum.split(".")))
            local_status = "pass" if observed >= fixed else "fail"
            reason = (
                f"The observed upstream release {running} "
                f"{'meets' if local_status == 'pass' else 'is below'} "
                f"the {minimum} minimum for its branch."
            )
    if livepatch not in {"none", "not-supported"} and local_status != "unknown":
        local_status = "unknown"
        reason = (
            "Livepatch state is active or unreadable. "
            "CVE-specific evidence for the running kernel is required."
        )

    status = local_status
    # The existing detector classifies containers as guests too. A container
    # can share the visible kernel, but cannot establish the outer host model.
    if guest != "false" or technology != "none":
        status = "host-version-required"
        reason += (
            " The physical host is not established at this scope. "
            "Request its running-kernel build and CVE-specific patch evidence."
        )
    return {
        "cve": CVE,
        "advisory": ADVISORY,
        "cnaRecord": CNA_RECORD,
        "minimumsReviewedAt": "2026-10-17",
        "fixCommit": FIX_COMMIT,
        "status": status,
        "reason": reason,
        "scope": "sampled-worker",
        "runningKernel": running,
        "localKernelStatus": local_status,
        "minimum": minimum,
        "virtualization": technology,
        "livepatch": livepatch,
        "tunDevicePresent": facts.get("WORKER_PWNESCAPE_TUN_PRESENT", "unknown"),
        "virtioNetObserved": facts.get("WORKER_PWNESCAPE_VIRTIO_NET", "unknown"),
        "maxUserNamespaces": facts.get("WORKER_PWNESCAPE_USERNS_MAX", "unknown"),
        "exploitTested": False,
    }


def main() -> None:
    facts = {}
    for line in sys.stdin:
        key, separator, value = line.rstrip("\n").partition("=")
        if separator and key.startswith("WORKER_"):
            # Multiple conflicting samples must not establish a fixed host.
            if key in facts and facts[key] != value:
                facts[key] = "unknown"
            else:
                facts[key] = value
    print(json.dumps(grade(facts), sort_keys=True))


if __name__ == "__main__":
    main()
