"""Grade passive evidence for CVE-2026-99999 without sending probe traffic."""

from __future__ import annotations

import json
import re
import sys

import minimum_versions


CVE = "CVE-2026-99999"
ADVISORY = "https://nvd.nist.gov/vuln/detail/CVE-2026-99999"
CNA_RECORD = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/99xxx/CVE-2026-99999.json"
FIX_COMMIT = "6785011f8b16abf40b1e9d8b2e332232b3e68822"
MINIMUMS_REVIEWED_AT = "2026-10-23"
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

# Only these Ubuntu GA/HWE image and source-package pairs can be matched to
# the CVE-specific Ubuntu tracker entry. Other flavors need their own mapping.
UBUNTU_KERNELS = {
    ("24.04", "6.8.0", "generic"): ("ubuntuNoble", "linux", {"linux", "linux-signed"}, ""),
    ("26.04", "7.0.0", "generic"): ("ubuntuResolute", "linux", {"linux", "linux-signed"}, ""),
    ("22.04", "6.8.0", "generic"): (
        "ubuntuJammy", "linux-hwe-6.8",
        {"linux-hwe-6.8", "linux-signed-hwe-6.8"}, "~22.04.",
    ),
}


def _ubuntu_grade(facts: dict[str, str], running: str) -> tuple[str, str, str, str]:
    """Use a verified running Ubuntu image and its CVE-specific vendor state."""
    unknown = ("unknown", "unknown", "unknown", "unknown")
    match = re.fullmatch(r"(6\.8\.0|7\.0\.0)-([1-9][0-9]*)-(generic)", running)
    if facts.get("WORKER_OS_ID") != "ubuntu" or match is None:
        return unknown
    family, abi, flavor = match.groups()
    mapping = UBUNTU_KERNELS.get((facts.get("WORKER_OS_VERSION_ID"), family, flavor))
    if mapping is None:
        return unknown
    component, source, accepted, suffix = mapping
    package = facts.get("WORKER_PWNESCAPE_PACKAGE", "").split("|")
    signature = facts.get("WORKER_PWNESCAPE_SIGNATURE", "").split()
    if len(package) != 3:
        return unknown
    state, source_name, version = package
    pattern = re.escape(family) + r"-([1-9][0-9]*)\.([1-9][0-9]*)"
    if suffix:
        pattern += re.escape(suffix) + r"([1-9][0-9]*)"
    installed = re.fullmatch(pattern, version)
    if (
        re.fullmatch(r"[uihrp]i", state.strip()) is None
        or source_name not in accepted
        or installed is None
        or installed.group(1) != abi
        or len(signature) != 3
        or signature[0] != "Ubuntu"
        or signature[1] != f"{version}-{flavor}"
    ):
        return unknown
    try:
        entry = minimum_versions.get(f"components.{component}.packages.linuxPwnescape")
    except (minimum_versions.MinimumDataError, OSError, ValueError):
        return unknown
    if not isinstance(entry, dict) or entry.get("cve") != CVE or entry.get("package") != source:
        return unknown
    vendor_status = entry.get("status")
    minimum = entry.get("fixed")
    if vendor_status == "released":
        fixed = re.fullmatch(pattern, minimum) if isinstance(minimum, str) else None
        if fixed is None:
            return unknown
        # A confirmed Ubuntu release can be compared within its own exact
        # source-package train; never compare a generic ABI with another flavor.
        patched = tuple(map(int, installed.groups())) >= tuple(map(int, fixed.groups()))
        status = "pass" if patched else "fail"
        return (
            status, minimum, vendor_status,
            f"The running Ubuntu {source} image {version} "
            f"{'meets' if patched else 'is below'} the released {CVE} fix {minimum}.",
        )
    if vendor_status in ("needed", "pending"):
        # "pending" descriptions are builds in progress, not fixed floors.
        return (
            "fail", "unknown", vendor_status,
            f"Ubuntu marks {source} on this release as vulnerable to {CVE}; "
            "no fixed package has been released. Request CVE-specific evidence "
            "if the provider has applied a private backport.",
        )
    return unknown


def grade(facts: dict[str, str]) -> dict:
    """Keep the observed worker kernel separate from a hidden outer host."""
    running = facts.get("WORKER_GUEST_KERNEL_RUNNING", "unknown")
    guest = facts.get("WORKER_VIRT_GUEST", "unknown")
    technology = facts.get("WORKER_VIRT_TYPE", "unknown")
    livepatch = facts.get("WORKER_PWNESCAPE_LIVEPATCH", "unknown")
    local_status = "unknown"
    minimum = "unknown"
    vendor_status = "unknown"
    reason = (
        "The distribution or custom kernel needs vendor evidence for this CVE. "
        "Upstream versions do not establish distribution backport status."
    )
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", running)
    if match:
        branch = ".".join(match.groups()[:2])
        observed = tuple(map(int, match.groups()))
        minimum = FIXED_RELEASES.get(branch, "unknown")
        if minimum != "unknown":
            fixed = tuple(map(int, minimum.split(".")))
            local_status = "pass" if observed >= fixed else "fail"
            reason = (
                f"The observed upstream release {running} "
                f"{'meets' if local_status == 'pass' else 'is below'} "
                f"the {minimum} minimum for its branch."
            )
        elif observed >= (7, 3, 0):
            local_status = "pass"
            minimum = "7.3.0"
            reason = "The observed upstream release includes the mainline PwnEscape fix in 7.3."
        elif observed >= (2, 6, 27):
            # The CNA's default status is affected. This is not a comparison
            # with another stable branch's fix, and applies only to an exact
            # upstream release, never to an Ubuntu signature's third field.
            local_status = "fail"
            reason = (
                f"The upstream CNA record marks {running} as affected. "
                "No fixed stable release is listed for this branch."
            )
    else:
        local_status, minimum, vendor_status, ubuntu_reason = _ubuntu_grade(facts, running)
        if local_status != "unknown":
            reason = ubuntu_reason
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
        "minimumsReviewedAt": MINIMUMS_REVIEWED_AT,
        "fixCommit": FIX_COMMIT,
        "status": status,
        "reason": reason,
        "scope": "sampled-worker",
        "runningKernel": running,
        "localKernelStatus": local_status,
        "minimum": minimum,
        "vendorStatus": vendor_status,
        "osId": facts.get("WORKER_OS_ID", "unknown"),
        "release": facts.get("WORKER_OS_VERSION_ID", "unknown"),
        "signature": facts.get("WORKER_PWNESCAPE_SIGNATURE", "unknown"),
        "packageEvidence": facts.get("WORKER_PWNESCAPE_PACKAGE", "unknown"),
        "sourcePackage": (
            facts.get("WORKER_PWNESCAPE_PACKAGE", "").split("|")[1]
            if local_status != "unknown" and vendor_status != "unknown"
            else "unknown"
        ),
        "virtualization": technology,
        "livepatch": livepatch,
        "tunDevicePresent": facts.get("WORKER_PWNESCAPE_TUN_PRESENT", "unknown"),
        "virtioNetObserved": facts.get("WORKER_PWNESCAPE_VIRTIO_NET", "unknown"),
        "maxUserNamespaces": facts.get("WORKER_PWNESCAPE_USERNS_MAX", "unknown"),
        "exploitTested": False,
    }


def parse_facts(text: str) -> dict[str, str]:
    """Read WORKER_ facts and mark a conflicting repeat as unknown."""
    facts: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.startswith("WORKER_"):
            # Multiple conflicting samples must not establish a fixed host.
            if key in facts and facts[key] != value:
                facts[key] = "unknown"
            else:
                facts[key] = value
    return facts


def _names(entries: list[dict], limit: int = 10) -> str:
    names = [str(entry["node"]) for entry in entries]
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _host_entry(host: dict) -> dict:
    entry = {"node": str(host.get("node") or "unknown"), "role": str(host.get("role") or "worker")}
    facts = parse_facts(str(host.get("facts") or ""))
    if not host.get("checked") or "WORKER_GUEST_KERNEL_RUNNING" not in facts:
        entry.update(
            checked=False,
            status="unassessed",
            error=str(host.get("error") or "The host returned no PwnEscape facts."),
        )
        return entry
    value = grade(facts)
    entry.update(
        checked=True,
        status=value["status"],
        runningKernel=value["runningKernel"],
        minimum=value["minimum"],
        vendorStatus=value["vendorStatus"],
        sourcePackage=value["sourcePackage"],
        osId=value["osId"],
        release=value["release"],
        signature=value["signature"],
        packageEvidence=value["packageEvidence"],
        localKernelStatus=value["localKernelStatus"],
        virtualization=value["virtualization"],
        livepatch=value["livepatch"],
        reason=value["reason"],
    )
    return entry


def grade_fleet(hosts: list[dict], control_plane: dict) -> dict:
    """Grade every audited host, so that one unpatched host fails the check.

    A host that the audit could not reach, or a control plane that the audit
    could not find, blocks a pass. The provider must then supply the running
    kernel and patch evidence for those hosts.
    """
    entries = [_host_entry(host) for host in hosts]
    checked = [entry for entry in entries if entry["checked"]]
    unassessed = [entry for entry in entries if not entry["checked"]]
    failing = [entry for entry in checked if entry["status"] == "fail"]
    control_entries = [entry for entry in entries if entry["role"] == "control-plane"]
    control_discovered = bool(control_plane.get("discovered")) and bool(control_entries)
    control_complete = control_discovered and all(entry["checked"] for entry in control_entries)
    coverage_complete = bool(entries) and not unassessed and control_complete

    statuses = {entry["status"] for entry in checked}
    if failing:
        status = "fail"
    elif not coverage_complete:
        status = "coverage-incomplete"
    elif statuses == {"pass"}:
        status = "pass"
    elif "host-version-required" in statuses:
        status = "host-version-required"
    else:
        status = "unknown"

    worst = (failing or [entry for entry in checked if entry["status"] != "pass"] or checked or [{}])[0]
    reasons = []
    if failing:
        reasons.append(
            f"{len(failing)} host(s) do not meet the PwnEscape patch requirements: {_names(failing)}."
        )
        reasons.append(f"{worst['node']}: {worst['reason']}")
    elif worst.get("status", "pass") != "pass":
        reasons.append(f"{worst['node']}: {worst['reason']}")
    if unassessed:
        reasons.append(
            f"The audit could not read {len(unassessed)} host(s): {_names(unassessed)}. "
            "Request the running-kernel build and CVE-specific patch evidence for each one."
        )
    if not control_discovered:
        reasons.append(
            str(control_plane.get("detail") or "The audit could not find the control-plane hosts.")
            + " Request the running-kernel build and CVE-specific patch evidence for every control-plane host."
        )
    if not reasons:
        reasons.append("Every audited worker and control-plane host meets the PwnEscape minimum.")

    roles: dict[str, dict[str, int]] = {}
    for entry in entries:
        counts = roles.setdefault(entry["role"], {"total": 0, "checked": 0, "failing": 0})
        counts["total"] += 1
        counts["checked"] += int(entry["checked"])
        counts["failing"] += int(entry["status"] == "fail")
    return {
        "cve": CVE,
        "advisory": ADVISORY,
        "cnaRecord": CNA_RECORD,
        "minimumsReviewedAt": MINIMUMS_REVIEWED_AT,
        "fixCommit": FIX_COMMIT,
        "status": status,
        "reason": " ".join(reasons),
        "scope": "fleet",
        "runningKernel": worst.get("runningKernel", "unknown"),
        "runningKernels": sorted({entry["runningKernel"] for entry in checked}),
        "localKernelStatus": worst.get("localKernelStatus", "unknown"),
        "minimum": worst.get("minimum", "unknown"),
        "vendorStatus": worst.get("vendorStatus", "unknown"),
        "sourcePackage": worst.get("sourcePackage", "unknown"),
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
            "coverageComplete": control_complete,
            "hosts": [entry["node"] for entry in control_entries],
            "detail": str(control_plane.get("detail") or ""),
        },
        "hosts": entries,
        "exploitTested": False,
    }


def main() -> None:
    if sys.argv[1:] == ["--fleet"]:
        # stdin is {"hosts": [...], "controlPlane": {...}} from the security collector.
        document = json.load(sys.stdin)
        print(json.dumps(
            grade_fleet(document.get("hosts") or [], document.get("controlPlane") or {}),
            sort_keys=True,
        ))
        return
    print(json.dumps(grade(parse_facts(sys.stdin.read())), sort_keys=True))


if __name__ == "__main__":
    main()
