#!/usr/bin/env python3
"""Read-only CVE-2026-46242 grading from the audited worker's kernel evidence.

Only Ubuntu 24.04 GA and 22.04 HWE 6.8 generic packages are mapped initially.
Never compare cloud-flavor ABIs, mainline kernels, or container image versions
against a generic-kernel minimum. This is a package advisory check, not an
exploit test or cryptographic attestation of a provider's kernel.
"""

from __future__ import annotations

import argparse
import json
import re

import minimum_versions

CVE = "CVE-2026-46242"
ADVISORY = f"https://ubuntu.com/security/{CVE}"
MAPPINGS = {
    "24.04": ("ubuntuNoble", "linux", {"linux", "linux-signed"}, ""),
    "22.04": (
        "ubuntuJammy", "linux-hwe-6.8",
        {"linux-hwe-6.8", "linux-signed-hwe-6.8"}, "~22.04.",
    ),
}


def evaluate(
    os_id: str = "unknown",
    release: str = "unknown",
    running: str = "unknown",
    signature: str = "unknown",
    package: str = "unknown",
    livepatch: str = "unknown",
) -> dict:
    result = {
        "cve": CVE, "advisory": ADVISORY, "status": "unknown",
        "running": running, "minimum": "unknown",
        "osId": os_id, "release": release, "signature": signature,
        "packageEvidence": package, "livepatch": livepatch,
        "detail": "Kernel package identity or advisory mapping is unverified; "
                  "requires provider patch evidence.",
    }
    kernel = re.fullmatch(r"6\.8\.0-([1-9][0-9]*)-generic", running)
    if os_id != "ubuntu" or release not in MAPPINGS or kernel is None:
        return result
    component, source, accepted_sources, suffix = MAPPINGS[release]
    # dpkg evidence must refer to the exact RUNNING image, not the newest
    # installed image. A container's own package database is not host proof.
    fields = package.split("|")
    if len(fields) != 3:
        return result
    state, source_name, version = fields
    if state.strip() != "ii" or source_name not in accepted_sources:
        return result
    pattern = r"6\.8\.0-([1-9][0-9]*)\.([1-9][0-9]*)"
    if suffix:
        pattern += r"~22\.04\.([1-9][0-9]*)"
    installed = re.fullmatch(pattern, version)
    signature_fields = signature.split()
    if (
        installed is None
        or installed.group(1) != kernel.group(1)
        or len(signature_fields) != 3
        or signature_fields[0] != "Ubuntu"
        or signature_fields[1] != f"{version}-generic"
    ):
        return result
    try:
        entry = minimum_versions.get(
            f"components.{component}.packages.linuxBadEpoll"
        )
    except (minimum_versions.MinimumDataError, OSError, ValueError):
        entry = None
    if not isinstance(entry, dict):
        result["detail"] = "Bad Epoll minimum is unavailable; cannot verify patch status."
        return result
    fixed = entry.get("fixed", "")
    minimum = re.fullmatch(pattern, fixed) if isinstance(fixed, str) else None
    if (
        entry.get("cve") != CVE or entry.get("package") != source
        or entry.get("status") != "released" or minimum is None
    ):
        result["detail"] = "Bad Epoll minimum is unverified for this kernel package."
        return result
    result["minimum"] = fixed
    result["sourcePackage"] = source
    # An enabled patch may cover another CVE. Do not claim this CVE is patched
    # or vulnerable without patch-specific evidence from the provider.
    if livepatch != "none":
        result["detail"] = "Livepatch state is active or unreadable; requires CVE-specific patch evidence."
        return result
    patched = tuple(map(int, installed.groups())) >= tuple(map(int, minimum.groups()))
    result["status"] = "pass" if patched else "fail"
    result["detail"] = (
        "The running distribution kernel meets the Bad Epoll fixed package minimum."
        if patched else
        "The running distribution kernel is below the Bad Epoll fixed package minimum; "
        "update the host kernel and reboot into it."
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("os-id", "release", "running", "signature", "package", "livepatch"):
        parser.add_argument(f"--{field}", default="unknown")
    print(json.dumps(evaluate(**vars(parser.parse_args()))))


if __name__ == "__main__":
    main()
