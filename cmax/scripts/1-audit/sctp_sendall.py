"""Grade passive evidence for CVE-2026-46227 without sending probe traffic.

CVE-2026-46227 is a stale list-cursor use-after-free in the Linux SCTP
``SCTP_SENDALL`` path (``sctp_sendmsg``). It is reachable from an unprivileged
container and was used to escape to the host kernel. This grader reads only the
running kernel release and passive sysfs facts; it never opens an SCTP socket
or sends SCTP traffic.
"""

from __future__ import annotations

import json
import re
import sys


CVE = "CVE-2026-46227"
ADVISORY = "https://ubuntu.com/security/CVE-2026-46227"
CNA_RECORD = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/46xxx/CVE-2026-46227.json"
FIX_SUBJECT = "sctp: revalidate list cursor after sctp_sendmsg_to_asoc() in SCTP_SENDALL"

# Upstream stable releases that carry the fix. These are upstream numbers, not
# distribution package versions. The kernel CNA record lists each stable branch
# separately. Never compare across trains.
FIXED_RELEASES = {
    "6.6": "6.6.140",
    "6.12": "6.12.90",
    "6.18": "6.18.32",
    "7.0": "7.0.9",
}

# Ubuntu generic kernels carry their own fixed ABI. The key is the
# "major.minor.micro" upload and the value is the first fixed ABI integer, taken
# from the Ubuntu security tracker. 22.04 (jammy) linux 5.15 and 24.04 (noble)
# linux 6.8 are the trains ClusterMAX fleets run; other source packages are not
# listed here and fall through to the vendor-evidence path.
UBUNTU_FIXED = {
    "5.15.0": 186,  # jammy linux generic/-64k: 5.15.0-186.196
    "6.8.0": 136,  # noble linux generic/-64k: 6.8.0-136.136
}

# A distribution kernel release is <upstream>-<ABI>-<flavor>, for example
# 6.17.0-1021-nvidia-64k. The generic flavors belong to the Ubuntu ABI ladder
# in UBUNTU_FIXED. Every other flavor is a vendor kernel, and its backport state
# cannot be read from the upstream base version alone.
DISTRIBUTION_RELEASE = re.compile(
    r"^(?P<upstream>\d+\.\d+\.\d+)-(?P<abi>\d+)-(?P<flavor>[a-z0-9][a-z0-9-]*)$"
)
GENERIC_FLAVORS = {"generic", "generic-64k"}


def _vendor_kernel(facts: dict[str, str]) -> dict[str, str] | None:
    """Return the vendor kernel identity, or None for an upstream or generic release."""
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    match = DISTRIBUTION_RELEASE.fullmatch(running)
    if match is None or match.group("flavor") in GENERIC_FLAVORS:
        return None
    return {
        "running": running,
        "distribution": facts.get("WORKER_KERNEL_DISTRIBUTION", "unknown"),
        "flavor": match.group("flavor"),
        "abi": match.group("abi"),
        "sourcePackage": facts.get("WORKER_KERNEL_SOURCE_PACKAGE", "unknown"),
        "livepatch": facts.get("WORKER_SCTP_SENDALL_LIVEPATCH", "unknown"),
    }


def _vendor_reason(identity: dict[str, str]) -> str:
    """Name the evidence the provider must send for a vendor kernel."""
    source = identity["sourcePackage"]
    if source in {"", "unknown"}:
        source_phrase = "the source package version that built the kernel"
    else:
        source_phrase = f"the source package version that built the kernel ({source})"
    distribution = identity["distribution"]
    origin = (
        f"the {distribution} vendor kernel"
        if distribution not in {"", "unknown"}
        else "a vendor kernel"
    )
    return (
        f"The running kernel {identity['running']} is {origin} with flavor "
        f"{identity['flavor']} and ABI {identity['abi']}. The audit grades the "
        "generic distribution ABI ladder, so this release establishes neither a "
        f"pass nor a fail. Request from the provider: {source_phrase}, "
        f"confirmation that the upstream fix titled '{FIX_SUBJECT}' is in that "
        "source, and the livepatch state (the audit reads "
        f"{identity['livepatch']}). Until the provider answers, {CVE} is "
        "unverified for this kernel, not unpatched."
    )


def _vendor_evidence(identity: dict[str, str]) -> list[str]:
    """List the requested provider evidence in the order a reviewer needs it."""
    return [
        f"distribution ({identity['distribution']})",
        f"kernel flavor ({identity['flavor']})",
        f"kernel ABI ({identity['abi']})",
        f"source package version ({identity['sourcePackage']})",
        f"upstream fix ('{FIX_SUBJECT}') present in that source",
        f"livepatch state ({identity['livepatch']})",
    ]


def grade(facts: dict[str, str]) -> dict:
    """Keep the observed worker kernel separate from a hidden outer host."""
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    guest = facts.get("WORKER_VIRT_GUEST", "unknown")
    technology = facts.get("WORKER_VIRT_TYPE", "unknown")
    livepatch = facts.get("WORKER_SCTP_SENDALL_LIVEPATCH", "unknown")
    local_status = "unknown"
    minimum = "unknown"
    reason = (
        "The distribution or custom kernel needs vendor evidence for this CVE. "
        "Upstream versions do not establish distribution backport status."
    )
    ubuntu = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)-(\d+)-generic(?:-64k)?", running)
    upstream = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", running)
    if ubuntu:
        upload = ".".join(ubuntu.group(1, 2, 3))
        fixed_abi = UBUNTU_FIXED.get(upload)
        if fixed_abi is not None:
            abi = int(ubuntu.group(4))
            minimum = f"{upload}-{fixed_abi}"
            local_status = "pass" if abi >= fixed_abi else "fail"
            reason = (
                f"The running Ubuntu kernel {running} "
                f"{'meets' if local_status == 'pass' else 'is below'} "
                f"the {minimum} fixed ABI for its train."
            )
    elif upstream:
        branch = ".".join(upstream.groups()[:2])
        minimum = FIXED_RELEASES.get(branch, "unknown")
        if minimum != "unknown":
            observed = tuple(map(int, upstream.groups()))
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

    vendor = _vendor_kernel(facts)
    vendor_fields = {}
    if vendor is not None:
        # The upstream base version cannot settle a vendor kernel, because the
        # vendor backports into its own release. Keep the verdict at unknown and
        # ask for the exact facts that settle it instead.
        if local_status == "unknown":
            reason = _vendor_reason(vendor)
        vendor_fields = {
            "kernelDistribution": vendor["distribution"],
            "kernelFlavor": vendor["flavor"],
            "kernelAbi": vendor["abi"],
            "kernelSourcePackage": vendor["sourcePackage"],
            "providerEvidence": _vendor_evidence(vendor),
        }

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
        "minimumsReviewedAt": "2026-10-21",
        "fixSubject": FIX_SUBJECT,
        "status": status,
        "reason": reason,
        "scope": "sampled-worker",
        "runningKernel": running,
        "localKernelStatus": local_status,
        "minimum": minimum,
        "virtualization": technology,
        "livepatch": livepatch,
        "sctpModuleLoaded": facts.get("WORKER_SCTP_SENDALL_SCTP_LOADED", "unknown"),
        "maxUserNamespaces": facts.get("WORKER_SCTP_SENDALL_USERNS_MAX", "unknown"),
        "exploitTested": False,
        **vendor_fields,
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
