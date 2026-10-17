#!/usr/bin/env python3
"""Read-only CVE-2026-46242 grading from the audited worker's kernel evidence.

Maps Ubuntu 24.04 GA/22.04 HWE 6.8 generic and Ubuntu 24.04 NVIDIA 6.17.
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
    ("24.04", "6.8.0", "generic"): (
        "ubuntuNoble", "linuxBadEpoll", "linux", {"linux", "linux-signed"}, "",
    ),
    ("22.04", "6.8.0", "generic"): (
        "ubuntuJammy", "linuxBadEpoll", "linux-hwe-6.8",
        {"linux-hwe-6.8", "linux-signed-hwe-6.8"}, "~22.04.",
    ),
    **{
        ("24.04", "6.17.0", flavor): (
            "ubuntuNoble", "linuxBadEpollNvidia617", "linux-nvidia-6.17",
            {"linux-nvidia-6.17", "linux-signed-nvidia-6.17"}, "",
        )
        for flavor in ("nvidia", "nvidia-64k")
    },
}


def evaluate(
    os_id: str = "unknown",
    release: str = "unknown",
    running: str = "unknown",
    signature: str = "unknown",
    package: str = "unknown",
    livepatch: str = "unknown",
    advisory: str = "bad-epoll",
) -> dict:
    cve = CVE if advisory == "bad-epoll" else "CVE-2026-46300"
    label = "Bad Epoll" if advisory == "bad-epoll" else "Fragnesia / Dirty Frag"
    result = {
        "cve": cve, "advisory": f"https://ubuntu.com/security/{cve}", "status": "unknown",
        "running": running, "minimum": "unknown",
        "osId": os_id, "release": release, "signature": signature,
        "packageEvidence": package, "livepatch": livepatch,
        "detail": "Kernel package identity or advisory mapping is unverified; "
                  "requires provider patch evidence.",
    }
    kernel = re.fullmatch(
        r"(6\.8\.0|6\.17\.0)-([1-9][0-9]*)-(generic|nvidia|nvidia-64k)", running
    )
    if os_id != "ubuntu" or kernel is None:
        return result
    family, abi, flavor = kernel.groups()
    mapping = MAPPINGS.get((release, family, flavor))
    if mapping is None:
        return result
    component, entry_key, source, accepted_sources, suffix = mapping
    if advisory == "fragnesia":
        entry_key = entry_key.replace("BadEpoll", "Fragnesia")
        result["relatedCves"] = ["CVE-2026-43284", "CVE-2026-43500"]
    # dpkg evidence must refer to the exact RUNNING image, not the newest
    # installed image. A container's own package database is not host proof.
    fields = package.split("|")
    if len(fields) != 3:
        return result
    state, source_name, version = fields
    # The first dpkg character is the requested selection, not installation
    # state. Held or removal-selected images still describe a running kernel.
    # Require installed state and no error flag, regardless of that selection.
    if re.fullmatch(r"[uihrp]i", state.strip()) is None or source_name not in accepted_sources:
        return result
    pattern = re.escape(family) + r"-([1-9][0-9]*)\.([1-9][0-9]*)"
    if suffix:
        pattern += r"~22\.04\.([1-9][0-9]*)"
    installed = re.fullmatch(pattern, version)
    signature_fields = signature.split()
    if (
        installed is None
        or installed.group(1) != abi
        or len(signature_fields) != 3
        or signature_fields[0] != "Ubuntu"
        or signature_fields[1] != f"{version}-{flavor}"
    ):
        return result
    try:
        entry = minimum_versions.get(
            f"components.{component}.packages.{entry_key}"
        )
    except (minimum_versions.MinimumDataError, OSError, ValueError):
        entry = None
    if not isinstance(entry, dict):
        result["detail"] = f"{label} minimum is unavailable; cannot verify patch status."
        return result
    fixed = entry.get("fixed", "")
    minimum = re.fullmatch(pattern, fixed) if isinstance(fixed, str) else None
    if (
        entry.get("cve") != cve or entry.get("package") != source
        or entry.get("status") != "released" or minimum is None
    ):
        result["detail"] = f"{label} minimum is unverified for this kernel package."
        return result
    if advisory == "fragnesia":
        coverage = {entry.get("cve"), *(entry.get("relatedCves") or [])}
        if not {cve, *result["relatedCves"]}.issubset(coverage):
            result["detail"] = "Fragnesia minimum lacks coverage for all related fixes."
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
        f"The running distribution kernel meets the {label} fixed package minimum."
        if patched else
        f"The running distribution kernel is below the {label} fixed package minimum; "
        "update the host kernel and reboot into it."
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("os-id", "release", "running", "signature", "package", "livepatch"):
        parser.add_argument(f"--{field}", default="unknown")
    parser.add_argument("--advisory", choices=("bad-epoll", "fragnesia"), default="bad-epoll")
    print(json.dumps(evaluate(**vars(parser.parse_args()))))


if __name__ == "__main__":
    main()
