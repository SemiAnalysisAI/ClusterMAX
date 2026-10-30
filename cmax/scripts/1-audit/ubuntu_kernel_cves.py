#!/usr/bin/env python3
"""Grade a running Ubuntu kernel against the per-kernel CVE rows of the minimum table.

Usage: ubuntu_kernel_cves.py OS_ID VERSION_ID RUNNING_RELEASE

Prints three lines: the status (pass, fail, unknown, or not-applicable), the
JSON list of vulnerable CVEs, and the JSON list of active grace records.

The CVE groups come from the table: a named group (for example
`linuxSctpSendall`) or a group that the refresh discovered on the tracker
(`linuxCve<year>_<number>`). The client has no CVE list of its own.

Each CVE group in the table has one row per Ubuntu kernel source package. A
row names the kernel family (`kernelFamily`, major.minor) and the release
string flavors (`kernelFlavors`) of that package. Older rows have no such
metadata and describe the GA generic kernel of the release. The running
release string `<x.y.z>-<abi>-<flavor>` selects at most one row per group.

- No row for the GA generic kernel: unknown, because that row is required.
- No row in a group that has per-kernel rows (`kernelGroup`): unknown. The
  tracker lists every Ubuntu kernel package, so a kernel with no row is a
  custom or mainline build, a package newer than the table, or a flavor name
  the table does not know. The audit cannot check it.
- No row in a group with only the GA row: that group checks only the GA
  kernel, so other kernels are outside it.
- More than one row: unknown, because the table cannot name the package.
- A kernel family with no row at all in the reported release, but with a
  per-kernel row for its flavor in exactly one other release, is graded
  against that other release. This covers a container image release that
  differs from the host release.
- `released`: compare the running ABI with the fixed ABI, with bulletin grace.
- `needed`, `pending`, `deferred`, `ignored`: vulnerable. Ubuntu has not
  shipped a fix for that kernel, or will not ship one (end of life).
- `not-affected`, `DNE`: checked and safe.
- Any other state (for example `needs-triage`): unknown.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import minimum_versions  # noqa: E402

# VERSION_ID -> (minimum table component, GA kernel family). The CVE groups
# come from the table itself (see `groups`), so a CVE that the refresh
# discovers is graded without a client change.
RELEASES: dict[str, tuple[str, str]] = {
    "22.04": ("ubuntuJammy", "5.15"),
    "24.04": ("ubuntuNoble", "6.8"),
    "26.04": ("ubuntuResolute", "7.0"),
}
GA_FLAVORS = ("generic", "generic-64k")
RUNNING = re.compile(r"(\d+)\.(\d+)\.\d+-(\d+)-([a-z][a-z0-9-]*)")
VULNERABLE_STATES = {"needed", "pending", "deferred", "ignored"}
SAFE_STATES = {"not-affected", "dne"}


def groups(packages: dict[str, Any]) -> tuple[str, ...]:
    """Return every kernel CVE group in one release block of the table.

    A per-kernel group is named by the `kernelGroup` of its rows. A GA-only
    group is one `linux` row that may carry an unfixed tracker state
    (`allowUnfixed`) and has no `kernelGroup`. Other package rows (named
    advisories with their own check, package-wide floors) are not groups.
    """
    found: set[str] = set()
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        group = entry.get("kernelGroup")
        if isinstance(group, str) and group:
            found.add(group)
        elif entry.get("allowUnfixed") is True and entry.get("package") == "linux":
            found.add(key)
    return tuple(sorted(found))


def _rows(packages: dict[str, Any], group: str, ga_family: str) -> list[tuple[str, dict, str, list[str]]]:
    rows = []
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("kernelGroup") == group:
            family = str(entry.get("kernelFamily") or "")
            flavors = [str(value) for value in entry.get("kernelFlavors") or []]
        elif key == group and "kernelGroup" not in entry:
            family, flavors = ga_family, list(GA_FLAVORS)
        else:
            continue
        rows.append((key, entry, family, flavors))
    return rows


def _family_rows(
    packages: dict[str, Any], names: tuple[str, ...], ga_family: str, family: str
) -> list[tuple[str, dict, str, list[str]]]:
    return [
        row
        for group in names
        for row in _rows(packages, group, ga_family)
        if row[2] == family
    ]


def _release_for_kernel(
    release: str, family: str, flavor: str
) -> tuple[str, str, tuple[str, ...], dict[str, Any]] | None:
    """Return the one other release whose tracker rows list this kernel."""
    found = []
    for other, (component, ga_family) in RELEASES.items():
        if other == release:
            continue
        try:
            packages = minimum_versions.component(component).get("packages") or {}
        except minimum_versions.MinimumDataError:
            continue
        other_groups = groups(packages)
        # Only per-kernel rows come from the full tracker package list. A
        # GA-only row does not prove which releases ship a kernel family.
        if any(
            "kernelGroup" in row[1] and flavor in row[3]
            for row in _family_rows(packages, other_groups, ga_family, family)
        ):
            found.append((component, ga_family, other_groups, packages))
    return found[0] if len(found) == 1 else None


def grade(os_id: str, release: str, running: str) -> tuple[str, list[str], list[dict]]:
    if os_id != "ubuntu" or release not in RELEASES:
        return "not-applicable", [], []
    component, ga_family = RELEASES[release]
    match = RUNNING.fullmatch(running)
    if match is None:
        # A Ubuntu host with a release string the audit cannot read.
        return "unknown", [], []
    family = f"{match.group(1)}.{match.group(2)}"
    running_abi = int(match.group(3))
    flavor = match.group(4)
    is_ga = family == ga_family and flavor in GA_FLAVORS

    try:
        packages = minimum_versions.component(component).get("packages") or {}
    except minimum_versions.MinimumDataError:
        return "unknown", [], []
    release_groups = groups(packages)
    if not release_groups:
        # The table carries no kernel CVE group for this release.
        return "unknown", [], []
    if not is_ga and not _family_rows(packages, release_groups, ga_family, family):
        # A container reports its own image release, not the release of the
        # host that built the kernel (for example a 22.04 Slurm container on a
        # 24.04 host with linux-nvidia-6.17). The reported release ships no
        # kernel of this family, so use the one other release whose tracker
        # rows list this kernel. If none or more than one does, keep the
        # reported release.
        other = _release_for_kernel(release, family, flavor)
        if other is not None:
            component, ga_family, release_groups, packages = other

    vulnerable: list[str] = []
    grace_periods: list[dict] = []
    unknown = checked = 0
    for group in release_groups:
        rows = _rows(packages, group, ga_family)
        per_kernel = any("kernelGroup" in row[1] for row in rows)
        matches = [row for row in rows if row[2] == family and flavor in row[3]]
        if len(matches) != 1:
            if matches or is_ga or per_kernel:
                unknown += 1
            continue
        key, entry, _, _ = matches[0]
        cve = str(entry.get("cve") or group)
        state = str(entry.get("status") or "").lower()
        if state in VULNERABLE_STATES:
            vulnerable.append(cve)
            checked += 1
        elif state == "released":
            checked += 1
            fixed_abi = entry.get("abi")
            if isinstance(fixed_abi, str) and fixed_abi.isdigit():
                fixed_abi = int(fixed_abi)
            if isinstance(fixed_abi, bool) or not isinstance(fixed_abi, int):
                unknown += 1
            elif running_abi < fixed_abi:
                grace = minimum_versions.active_grace_period(component, key)
                if grace is None:
                    vulnerable.append(cve)
                else:
                    grace_periods.append({"cve": cve, "policy": grace})
        elif state in SAFE_STATES:
            checked += 1
        else:
            unknown += 1

    if vulnerable:
        status = "fail"
    elif unknown:
        status = "unknown"
    elif not checked:
        status = "not-applicable"
    else:
        status = "pass"
    return status, sorted(set(vulnerable)), grace_periods


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.splitlines()[2], file=sys.stderr)
        return 2
    status, vulnerable, grace_periods = grade(*argv)
    compact = {"separators": (",", ":"), "sort_keys": True}
    print(status)
    print(json.dumps(vulnerable, **compact))
    print(json.dumps(grace_periods, **compact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
