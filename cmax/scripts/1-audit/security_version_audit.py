#!/usr/bin/env python3
"""Evaluate container-host security versions without exercising vulnerabilities.

The audit is intentionally version-only. It never sends crafted GPU, runtime,
or RDMA commands. A version that is hidden by a tenant boundary is reported as
``unknown`` so an operator can request host attestation from the provider.

No minimum is written in this file. Every minimum, advisory URL, and CVE list comes
from the generated table ``minimum-versions.json``, read through
``minimum_versions.py``, so a daily refresh of that table changes the grading
with no code change. When the table cannot be read, every check reports
``unknown`` instead of a false ``pass``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable

WORKLOAD_DIR = str(Path(__file__).resolve().parent)
if WORKLOAD_DIR not in sys.path:
    sys.path.insert(0, WORKLOAD_DIR)

import minimum_versions  # noqa: E402
from minimum_versions import MinimumDataError  # noqa: E402


UNKNOWN_VALUES = {"", "none", "not-found", "unknown", "n/a"}
NOT_INSTALLED_VALUES = {"not-installed"}

# Reported as the minimum when the minimum table itself is unreadable. The status
# is always "unknown" in that case, so no version can grade as a pass.
MINIMUMS_UNAVAILABLE = "unavailable"

_PRERELEASE_RE = re.compile(r"(?:^|[-.~+])rc[.-]?(\d+)", re.IGNORECASE)

# NVIDIA Linux driver branches are three-digit numbers: R535, R580, R610. That
# is a property of NVIDIA's numbering rather than of the minimum table, so the
# upper bound is a literal here. The lower bound is read from the table.
MAX_DRIVER_BRANCH = 999


@dataclass(frozen=True)
class Verdict:
    version: str
    status: str
    minimum: str
    advisory: str
    detail: str


def _verdict_record(
    verdict: Verdict,
    component: str | None = None,
    selector: str | Iterable[str] | None = None,
    *,
    minimum_failure: bool = False,
) -> dict[str, object]:
    """Serialize a comparison and apply the audit enforcement window.

    The Verdict stays the factual version comparison. Only its audit record
    becomes a temporary pass, which keeps the below-minimum fact available for
    exposure and recommendation logic.
    """
    record = asdict(verdict)
    if (verdict.status != "fail" and not minimum_failure) or component is None:
        return record
    try:
        grace = minimum_versions.active_grace_period(component, selector)
    except MinimumDataError:
        return record
    if grace is None:
        return record
    record["status"] = "pass"
    record["gracePeriod"] = grace
    return record


def numeric_version(value: str, *, parts: int = 4) -> tuple[int, ...] | None:
    """Extract a comparable numeric prefix from distro and CLI versions."""
    if value.strip().lower() in UNKNOWN_VALUES:
        return None
    # Debian package versions may start with an epoch, such as 1:1.17.8-1.
    # The epoch controls package ordering but is not the upstream version.
    value = re.sub(r"^\s*\d+:", "", value)
    match = re.search(r"\d+(?:\.\d+){0,3}", value)
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group(0).split("."))
    return (numbers + (0,) * parts)[:parts]


def _unknown(version: str, minimum: str, advisory: str, detail: str) -> Verdict:
    return Verdict(version or "unknown", "unknown", minimum, advisory, detail)


def _not_installed(version: str, minimum: str, advisory: str, component: str) -> Verdict:
    return Verdict(
        version or "not-installed",
        "not_applicable",
        minimum,
        advisory,
        f"{component} is not installed on the inspected host",
    )


def _minimums_unavailable(version: str, exc: MinimumDataError) -> Verdict:
    """Grade a component as unknown when its minimum cannot be read.

    A missing or unreadable table must never produce a pass: the operator has
    to know the audit graded nothing, not that the host is clean.
    """
    return _unknown(version, MINIMUMS_UNAVAILABLE, "", f"Minimum version table is unusable: {exc}")


def _advisory(block: dict[str, Any]) -> str:
    value = block.get("advisory")
    return value if isinstance(value, str) else ""


def _component_advisory(name: str) -> str:
    try:
        return _advisory(minimum_versions.component(name))
    except MinimumDataError:
        return ""


def _cve_detail(block: dict[str, Any], fallback: str) -> str:
    """Name the advisories the minimum came from, so the finding is actionable."""
    listed = block.get("cves") or block.get("advisories") or []
    names = [str(item).strip() for item in listed if str(item).strip()]
    if not names:
        return fallback
    return f"{', '.join(names)} minimum version"


def _semver_key(value: str) -> tuple:
    """Order versions numerically and rank a release above its own candidate.

    Mirrors ``cmax.minimum_refresh.version_key`` for the subset of comparisons
    the applicability check needs: (release numbers, stable flag, rc number).
    A value with no digits orders lowest, which reads OSV's \"0\" introduced
    marker as the beginning of every range.
    """
    marker = _PRERELEASE_RE.search(value)
    release_text = value[: marker.start()] if marker else value
    release = tuple(int(part) for part in re.findall(r"\d+", release_text))
    if marker is None:
        return (release, 1, 0)
    return (release, 0, int(marker.group(1) or 0))


def _observed_key(version: str) -> tuple | None:
    """The comparable form of an observed version string.

    Observed values arrive decorated: ``runc version 1.3.3``, Debian epochs,
    and distro suffixes such as ``1.3.3-0ubuntu1~22.04.3``. The release part
    is read through ``numeric_version``, which strips all of that, so a distro
    rebuild of 1.3.3 compares equal to upstream 1.3.3 instead of above it.
    """
    release = numeric_version(version, parts=3)
    if release is None:
        return None
    prerelease = _prerelease(version)
    if prerelease is None:
        return (release, 1, 0)
    return (release, 0, prerelease)


def _version_in_range(key: tuple, entry: dict[str, Any]) -> bool:
    """Whether one observed version key sits inside one OSV affected range.

    The range is affected from ``introduced`` (inclusive) up to ``fixed``
    (exclusive) or through ``lastAffected`` (inclusive). A range that names
    neither bound is refused rather than read as open-ended: the table is
    generated, and a malformed entry must not fail every version on its own.
    """
    if key < _semver_key(str(entry.get("introduced") or "0")):
        return False
    fixed = entry.get("fixed")
    if fixed:
        return key < _semver_key(str(fixed))
    last_affected = entry.get("lastAffected")
    if last_affected:
        return key <= _semver_key(str(last_affected))
    return False


def _applicable_advisories(block: dict[str, Any], version: str) -> list[str] | None:
    """Name only the advisories whose affected ranges hold the observed version.

    Each entry reads ``GHSA-... (fixed in X)``, where X is that advisory's own
    smallest fix above the observed version, not the branch minimum. An advisory
    can apply to a host whose branch minimum does not fix it: GHSA-xjvp-4fhw-gc47
    affects everything below 1.3.6, so a 1.2.7 host is affected, and 1.2.8
    does not resolve it. Claiming the branch minimum as its fix would tell a
    provider they are clear while they stay exposed.

    Returns ``None`` when the table carries no ``advisoryRanges`` evidence, so
    the caller can fall back to the advisory that set the branch minimum instead
    of listing the component's whole advisory history. Listing every advisory
    ever published against the package told a provider on runc 1.3.3 to act on
    findings fixed in 0.1.0, which discredits the one finding that is real.
    """
    ranges = block.get("advisoryRanges")
    if not isinstance(ranges, dict) or not ranges:
        return None
    key = _observed_key(version)
    if key is None:
        return None
    applicable: list[str] = []
    for vuln_id, entries in sorted(ranges.items()):
        if not isinstance(entries, list):
            continue
        if not any(
            isinstance(entry, dict) and _version_in_range(key, entry)
            for entry in entries
        ):
            continue
        fixes = [
            str(entry["fixed"])
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("fixed")
            and key < _semver_key(str(entry["fixed"]))
        ]
        if fixes:
            fix = min(fixes, key=_semver_key)
            applicable.append(f"{vuln_id} (fixed in {fix})")
        else:
            applicable.append(f"{vuln_id} (no fixed release)")
    return applicable


def _minimum_minimum(name: str) -> tuple[dict[str, Any], str, tuple[int, ...]]:
    """Return the component block, its published minimum, and the comparable form."""
    block = minimum_versions.component(name)
    minimum = block.get("minimum")
    if not isinstance(minimum, str) or not minimum.strip():
        raise MinimumDataError(f"minimum version table has no minimum for {name!r}")
    parsed = numeric_version(minimum)
    if parsed is None:
        raise MinimumDataError(f"minimum version {minimum!r} for {name!r} is not a version")
    return block, minimum, parsed


def _prerelease(value: str) -> int | None:
    """Return the release-candidate number in a version string, if any."""
    match = _PRERELEASE_RE.search(value)
    return int(match.group(1)) if match else None


def nvidia_driver_verdict(version: str) -> Verdict:
    try:
        block = minimum_versions.component("nvidiaDriver")
        branches = block.get("branches") or {}
        minimums = {int(branch): minimum for branch, minimum in branches.items()}
        if not minimums:
            raise MinimumDataError("minimum version table has no NVIDIA driver branches")
    except (MinimumDataError, TypeError, ValueError) as exc:
        return _minimums_unavailable(version, MinimumDataError(str(exc)))

    advisory = _advisory(block)
    listed = " / ".join(minimums[branch] for branch in sorted(minimums))
    parsed = numeric_version(version)
    if parsed is None:
        return _unknown(version, "branch-specific", advisory, "GPU driver version is unavailable")

    branch = parsed[0]
    if branch not in minimums:
        latest_branch = max(minimums)
        lowest_branch = min(minimums)
        # Domain guard, checked before the newer-than-newest rule can fire. A
        # value that does not look like an NVIDIA driver branch must never
        # reach that rule, because it would turn a foreign or malformed reading
        # into a confident pass on a security check. The vendor-neutral
        # gpus.driverVersion field carries the amdgpu version on AMD clusters
        # (6.16.13 on oracle-mi355x), so a value like that does reach here
        # whenever the gpu_vendor gate is bypassed. The gate is the real
        # defense; this is the second one, and it fails towards unknown.
        if not lowest_branch <= branch <= MAX_DRIVER_BRANCH:
            return _unknown(
                version,
                listed,
                advisory,
                f"{version} does not look like an NVIDIA Linux driver version: "
                f"branch {branch} is outside R{lowest_branch} to R{MAX_DRIVER_BRANCH}, "
                f"the range the bulletin table can assess. It may be another "
                f"vendor's driver or a malformed reading",
            )
        if branch > latest_branch:
            # A branch newer than the newest branch assessed by the current
            # bulletin cannot be below any published minimum version, because no
            # minimum for it has been disclosed yet. That is a clean pass, not a
            # provisional one: the audit grades against published minimums, and
            # there is nothing here for an operator to act on. The daily refresh
            # regrades the same reading as soon as a minimum is published.
            return Verdict(
                version,
                "pass",
                f"newer than R{latest_branch} baseline",
                advisory,
                f"R{branch} postdates the current NVIDIA Linux driver bulletin table "
                f"(newest assessed branch R{latest_branch}), so no published "
                f"minimum version applies to it",
            )
        return _unknown(
            version,
            listed,
            advisory,
            f"R{branch} is not assessed by the current NVIDIA Linux driver bulletin table",
        )

    minimum = minimums[branch]
    parsed_minimum = numeric_version(minimum)
    if parsed_minimum is None:
        return _minimums_unavailable(
            version, MinimumDataError(f"NVIDIA driver minimum {minimum!r} is not a version")
        )
    passed = parsed >= parsed_minimum
    return Verdict(
        version,
        "pass" if passed else "fail",
        minimum,
        advisory,
        "Meets the published NVIDIA Linux driver minimum version"
        if passed
        else "Below the published NVIDIA Linux driver minimum version",
    )


def nvidia_container_toolkit_verdict(version: str) -> Verdict:
    try:
        block, minimum, parsed_minimum = _minimum_minimum("nvidiaContainerToolkit")
    except MinimumDataError as exc:
        return _minimums_unavailable(version, exc)
    advisory = _advisory(block)
    if version.strip().lower() in NOT_INSTALLED_VALUES:
        return _not_installed(version, minimum, advisory, "NVIDIA Container Toolkit")
    parsed = numeric_version(version)
    if parsed is None:
        return _unknown(
            version,
            minimum,
            advisory,
            "Host NVIDIA Container Toolkit version is unavailable",
        )
    passed = parsed >= parsed_minimum
    cited = _cve_detail(block, "NVIDIA Container Toolkit minimum version")
    return Verdict(
        version,
        "pass" if passed else "fail",
        minimum,
        advisory,
        f"Meets the {cited} ({minimum})" if passed else f"Below the {cited} ({minimum})",
    )


def cuda_toolkit_verdict(version: str) -> Verdict:
    """Check the CUDA Toolkit minimum published in NVIDIA's current bulletin."""
    try:
        block, minimum, parsed_minimum = _minimum_minimum("cudaToolkit")
    except MinimumDataError as exc:
        return _minimums_unavailable(version, exc)
    advisory = _advisory(block)
    if version.strip().lower() in NOT_INSTALLED_VALUES | {"not-found"}:
        return _not_installed(version, minimum, advisory, "CUDA Toolkit")
    parsed = numeric_version(version)
    if parsed is None:
        return _unknown(version, minimum, advisory, "CUDA Toolkit version is unavailable")
    passed = parsed >= parsed_minimum
    return Verdict(
        version,
        "pass" if passed else "fail",
        minimum,
        advisory,
        "Meets the published CUDA Toolkit minimum version"
        if passed
        else "Below the published CUDA Toolkit minimum version",
    )


def docker_verdict(version: str) -> Verdict:
    try:
        block, minimum, _ = _minimum_minimum("docker")
    except MinimumDataError as exc:
        return _minimums_unavailable(version, exc)
    advisory = _advisory(block)
    if version.strip().lower() in NOT_INSTALLED_VALUES:
        return _not_installed(version, minimum, advisory, "Docker Engine")
    parsed = _observed_key(version)
    parsed_minimum = _observed_key(minimum)
    if parsed is None or parsed_minimum is None:
        return _unknown(version, minimum, advisory, "Host Docker version is unavailable")
    passed = parsed >= parsed_minimum
    return Verdict(
        version,
        "pass" if passed else "fail",
        minimum,
        advisory,
        f"Meets the ClusterMAX Docker Engine minimum version ({minimum})"
        if passed
        else f"Below the ClusterMAX Docker Engine minimum version ({minimum})",
    )


def _minimum_kind_verdict(version: str, component: str, *, label: str) -> Verdict:
    """Grade a component whose minimum is a single published minimum.

    This is the same path `cuda_toolkit_verdict` and `docker_verdict` take,
    factored out for the components that need nothing more than it. The detail
    names the CVEs the table publishes, so a finding points at the bulletin
    without this file restating either the minimum or the CVE list.
    """
    try:
        block, minimum, parsed_minimum = _minimum_minimum(component)
    except MinimumDataError as exc:
        return _minimums_unavailable(version, exc)
    advisory = _advisory(block)
    if version.strip().lower() in NOT_INSTALLED_VALUES:
        return _not_installed(version, minimum, advisory, label)
    parsed = numeric_version(version)
    if parsed is None:
        return _unknown(version, minimum, advisory, f"{label} version is unavailable")
    # The detail states which side of the minimum the host is on. A bare CVE
    # list read the same on a pass as on a fail, so a passing host looked like
    # it carried an open advisory.
    passed = parsed >= parsed_minimum
    cited = _cve_detail(block, f"{label} minimum version")
    return Verdict(
        version,
        "pass" if passed else "fail",
        minimum,
        advisory,
        f"Meets the {cited} ({minimum})" if passed else f"Below the {cited} ({minimum})",
    )


def dcgm_verdict(version: str) -> Verdict:
    """Check the DCGM host stack against its published minimum.

    DCGM and DCGM Exporter ship together in one container tag and both carry
    4.x versions, so the two minimums are close enough to look interchangeable.
    They are not: each is graded against its own component here.
    """
    return _minimum_kind_verdict(version, "dcgm", label="DCGM")


def dcgm_exporter_verdict(version: str) -> Verdict:
    """Check DCGM Exporter against its own minimum, which differs from DCGM's."""
    return _minimum_kind_verdict(version, "dcgmExporter", label="DCGM Exporter")


def _meets_ladder_minimum(version: str, observed: tuple[int, ...], minimum_version: str) -> bool:
    """Compare one observed release against its branch minimum in the ladder.

    The ladder holds one fixed release per ``major.minor`` branch. A minimum may
    itself be a release candidate (for example ``1.5.0-rc.3``), in which case
    the stable release of the same patch, and any newer candidate, both clear
    it. When the minimum is a stable release, a candidate of that same patch is
    still below it.
    """
    minimum = numeric_version(minimum_version, parts=3)
    if minimum is None:
        return False
    if observed[:3] != minimum:
        return observed[:3] > minimum
    minimum_rc = _prerelease(minimum_version)
    observed_rc = _prerelease(version)
    if minimum_rc is None:
        return observed_rc is None
    return observed_rc is None or observed_rc >= minimum_rc


def runc_verdict(version: str) -> Verdict:
    try:
        block = minimum_versions.component("runc")
        ladder = block.get("ladder") or {}
        branches = {}
        for key, minimum_version in ladder.items():
            major, _, minor = str(key).partition(".")
            branches[(int(major), int(minor))] = str(minimum_version)
        if not branches:
            raise MinimumDataError("minimum version table has no runc ladder")
    except (MinimumDataError, TypeError, ValueError) as exc:
        return _minimums_unavailable(version, MinimumDataError(str(exc)))

    advisory = _advisory(block)
    listed = " or ".join(
        branches[branch] for branch in sorted(branches, reverse=True)
    )
    if version.strip().lower() in NOT_INSTALLED_VALUES:
        return _not_installed(version, listed, advisory, "runc")
    parsed = numeric_version(version)
    if parsed is None:
        return _unknown(version, listed, advisory, "Host runc version is unavailable")

    # The minimum names the one release that clears the observed branch, not
    # the whole ladder. "observed 1.3.3, minimum 0.1.0 or 1.0.3 or ... or
    # 1.5.0-rc.3" asked a provider to decode the ladder themselves; the
    # actionable minimum for a 1.3 host is 1.3.6 alone.
    branch = (parsed[0], parsed[1])
    branch_name = f"{branch[0]}.{branch[1]}"
    if branch in branches:
        passed = _meets_ladder_minimum(version, parsed, branches[branch])
        minimum = branches[branch]
    elif branch > max(branches):
        # A branch above every branch in the ladder postdates the fixed
        # releases and cannot be below them.
        newest = max(branches)
        return Verdict(
            version,
            "pass",
            f"newer than the {newest[0]}.{newest[1]} branch minimum",
            advisory,
            f"runc {branch_name} postdates every branch assessed by the "
            f"advisory table (newest {newest[0]}.{newest[1]}), so no published "
            f"minimum version applies to it",
        )
    else:
        # Anything below the ladder is an unmaintained branch that never
        # received the fixes. The nearest maintained branch is the way out.
        passed = False
        next_up = min(candidate for candidate in branches if candidate > branch)
        minimum = branches[next_up]

    if passed:
        return Verdict(
            version,
            "pass",
            minimum,
            advisory,
            f"Meets the runc {branch_name} branch minimum version ({minimum})",
        )

    # Name only the advisories that hold the observed version, never the
    # package's whole advisory history. runc 1.3.3 already carries the fixes
    # for every advisory patched at or below 1.3.3, so listing those seventeen
    # IDs buried the single advisory (the 1.3.6 fix) the fail was about.
    applicable = _applicable_advisories(block, version)
    minimum_label = (
        f"runc {branch_name} branch minimum version {minimum}"
        if branch in branches
        else f"nearest maintained runc branch minimum {minimum}"
    )
    if applicable:
        detail = f"Affected by {', '.join(applicable)}; {minimum_label}"
    elif applicable is None:
        # Older tables carry no advisoryRanges. The advisory that set the
        # branch minimum is the one finding known to apply at that boundary.
        minimum_source = (block.get("floorSources") or {}).get(branch_name)
        detail = (
            f"{minimum_source} minimum version ({minimum})"
            if isinstance(minimum_source, str) and minimum_source.strip()
            else _cve_detail(block, "runc minimum version")
        )
    else:
        detail = f"Below the runc {branch_name} branch minimum version ({minimum})"
    return Verdict(version, "fail", minimum, advisory, detail)


def _release_lines(block: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Split a releaseLines component into fixed versions and legacy thresholds."""
    fixed: dict[str, str] = {}
    legacy: dict[str, str] = {}
    for name, spec in (block.get("lines") or {}).items():
        if not isinstance(spec, dict):
            continue
        value = spec.get("fixed")
        if isinstance(value, str) and numeric_version(value, parts=3):
            fixed[name] = value
        retired = spec.get("legacyAffectedThrough")
        if isinstance(retired, str) and numeric_version(retired, parts=3):
            legacy[name] = retired
    if not fixed:
        raise MinimumDataError("minimum version table has no fixed release lines for virtioNetBluefield")
    return fixed, legacy


def _virtio_minimum_selectors(version: str, line: str | None) -> tuple[str, ...]:
    """Return each release line that can own the observed controller version."""
    try:
        block = minimum_versions.component("virtioNetBluefield")
        fixed, legacy = _release_lines(block)
    except MinimumDataError:
        return ()

    if line and line.strip().lower() not in UNKNOWN_VALUES:
        requested = line.strip().lower()
        selected = next((name for name in fixed if name.lower() == requested), None)
        return (selected,) if selected else ()

    parsed = numeric_version(version, parts=3)
    if parsed is None:
        return ()
    legacy_matches = tuple(
        sorted(
            name
            for name, value in legacy.items()
            if numeric_version(value, parts=3)[0] == parsed[0]
        )
    )
    if legacy_matches:
        return legacy_matches

    candidates = tuple(
        sorted(
            name
            for name, value in fixed.items()
            if numeric_version(value, parts=3)[:2] == parsed[:2]
        )
    )
    if candidates:
        return candidates
    return tuple(
        sorted(
            name
            for name, value in fixed.items()
            if numeric_version(value, parts=3)[0] == parsed[0]
        )
    )


def _line_listing(fixed: dict[str, str], names: Iterable[str]) -> str:
    return ", ".join(f"{name} {fixed[name]}" for name in sorted(names))


def _virtio_running_verdict(version: str, *, line: str | None = None) -> Verdict:
    """Grade BlueField VIRTIO-Net controller firmware against its release line.

    The release lines interleave: GA and the newest LTS both carry the same
    year.month prefix and are fixed at different patches, so the line cannot be
    recovered from the version string. When the collector reports the line, the
    grade is exact. When it does not, the observed version is compared against
    every line that could produce it: clearing all of them passes, clearing
    none fails, and anything between is reported as ``unknown`` with both
    candidate minimums named, because guessing either way would be wrong for half
    the fleet.

    There is deliberately no "newer than the newest line" pass rule here. The
    lines do not order cleanly the way driver branches and firmware trains do,
    and a version above every candidate minimum already passes on its own.
    """
    try:
        block = minimum_versions.component("virtioNetBluefield")
        fixed, legacy = _release_lines(block)
    except MinimumDataError as exc:
        return _minimums_unavailable(version, exc)

    advisory = _advisory(block)
    listing = _line_listing(fixed, fixed)
    cves = _cve_detail(block, "BlueField VIRTIO-Net controller minimum version")

    if version.strip().lower() in NOT_INSTALLED_VALUES:
        return _not_installed(version, listing, advisory, "BlueField VIRTIO-Net controller")
    parsed = numeric_version(version, parts=3)
    if parsed is None:
        return _unknown(
            version,
            listing,
            advisory,
            "BlueField VIRTIO-Net controller firmware version is unavailable",
        )

    # 1. The collector knows the line: grade against that line and nothing else.
    if line and line.strip().lower() not in UNKNOWN_VALUES:
        requested = line.strip()
        name = next((key for key in fixed if key.lower() == requested.lower()), None)
        if name is None:
            return _unknown(
                version,
                listing,
                advisory,
                f"Release line {requested} is not assessed by the current bulletin",
            )
        passed = parsed >= numeric_version(fixed[name], parts=3)
        return Verdict(
            version,
            "pass" if passed else "fail",
            fixed[name],
            advisory,
            f"{cves} for release line {name} (fixed in {fixed[name]})",
        )

    # 2. The retired versioning scheme. The bulletin lists it as affected up to
    # a stated version; above that the scheme carries no minimum of its own.
    thresholds = {numeric_version(value, parts=3): value for value in legacy.values()}
    same_scheme = [numbers for numbers in thresholds if numbers[0] == parsed[0]]
    if same_scheme:
        highest = max(same_scheme)
        if parsed <= highest:
            return Verdict(
                version,
                "fail",
                thresholds[highest],
                advisory,
                f"{cves}; the retired {highest[0]}.x scheme is affected through "
                f"{thresholds[highest]}",
            )
        return _unknown(
            version,
            listing,
            advisory,
            f"The retired {highest[0]}.x versioning scheme is above the affected range "
            f"(through {thresholds[highest]}) and carries no published minimum; the "
            f"release line is required to grade this controller",
        )

    # 3. and 4. Every line the observed version could belong to, by year.month
    # first and by year alone as a fallback.
    candidates = {
        name: numeric_version(value, parts=3)
        for name, value in fixed.items()
        if numeric_version(value, parts=3)[:2] == parsed[:2]
    }
    scope = f"{parsed[0]}.{parsed[1]}"
    if not candidates:
        candidates = {
            name: numeric_version(value, parts=3)
            for name, value in fixed.items()
            if numeric_version(value, parts=3)[0] == parsed[0]
        }
        scope = str(parsed[0])
    # 5. Nothing in the bulletin could have produced this version.
    if not candidates:
        return _unknown(
            version,
            listing,
            advisory,
            "Release line is not assessed by the current bulletin",
        )

    applicable = _line_listing(fixed, candidates)
    highest_name = max(candidates, key=lambda name: candidates[name])
    lowest_name = min(candidates, key=lambda name: candidates[name])
    if parsed >= candidates[highest_name]:
        return Verdict(
            version,
            "pass",
            fixed[highest_name],
            advisory,
            f"{cves}; at or above every release line that shares {scope} ({applicable})",
        )
    if parsed < candidates[lowest_name]:
        return Verdict(
            version,
            "fail",
            fixed[lowest_name],
            advisory,
            f"{cves}; below every release line that shares {scope} ({applicable})",
        )
    return _unknown(
        version,
        applicable,
        advisory,
        f"{applicable} share {scope} and this firmware clears only some of them; "
        f"the release line is required to decide",
    )


# Platform modes the collector can report for a BlueField, and the exposure
# states the values file records. "latent" is the case a BlueField in NIC mode
# creates: no controller is running, so nothing is exposed right now, but the
# installed firmware is unpatched and an mlxconfig mode change would run it
# unchanged. A dashboard has to tell that apart from "vulnerable now" and from
# "does not apply", so a consumer can filter on it without parsing the detail.
VIRTIO_MODES = ("dpu", "nic", "absent")
EXPOSURE_LIVE = "live"
EXPOSURE_LATENT = "latent"
EXPOSURE_NONE = "none"
EXPOSURE_UNKNOWN = "unknown"

# Why a controller version could not be read. These are controlled values a
# dashboard can filter on; the collector's free text stays in
# versionUnavailableDetail. "dpu-hardened" is the good case: RShim is enabled by
# default and the out-of-box BlueField state assumes a trusted host, so
# restricting it is a deliberate operator step, and an unreadable version is the
# expected consequence rather than a gap in the cluster.
VERSION_REASON_HARDENED = "dpu-hardened"
# The rollup state answers two different questions and they have different
# answers, so it is read into two separate flags. Collapsing them into one was
# the whole defect: the wider set was applied to the narrower question, and one
# patched reading cleared a fleet that still held an unread card.
#
# VIRTIO_COMPLETE_STATES: every host was REACHED and settled on an answer. The
# check clamps every rung below its gap rung down to "incomplete" when the
# fan-out misses a host (apply_coverage_gap / CONTROLLER_LADDER in
# checks/fabric/virtio-net-check.py), so these three can only arrive settled
# from a fully scanned fleet. "unknown" and "incomplete" are the two states a
# gap can produce. Treating anything but "version" as a gap claimed hosts went
# unassessed on a fully scanned no-BlueField or all-NIC fleet.
VIRTIO_COMPLETE_STATES = frozenset({"version", "not_running", "not_applicable"})
# VIRTIO_EVERY_BLUEFIELD_READ_STATES: every host that carries a BlueField also
# produced a controller version, so a reading speaks for the whole fleet. Only
# "version" qualifies. It is the least severe rung above "not_applicable", so
# the rollup lands there only when every host is either "version" or
# "not_applicable" (a completed scan that found no BlueField-3, which therefore
# has no controller firmware to read). A settled "not_running" rollup is the
# opposite case: the fleet was fully reached, and at least one host carries
# installed controller firmware that nobody read, so no reading may clear it.
#
# This mirrors the split the check already documents for DPU host isolation,
# where selection (`_isolation_rung`) and the coverage clamp
# (`_isolation_proof_rung`) ask deliberately different questions off the same
# records.
VIRTIO_EVERY_BLUEFIELD_READ_STATES = frozenset({"version"})
# Worst-verdict ordering when several hosts report different controllers. A
# proven failure outranks an unresolved host, which outranks a clean one.
_VIRTIO_SEVERITY = {"fail": 3, "unknown": 2, "not_applicable": 1, "pass": 0}
# Tie-break among readings that already agree on the status, so the reading that
# owns the reported detail is the one making the least permissive claim about
# the fleet. A DPU-mode grade says a controller is running; a NIC-mode grade
# says none is. Only the second is a softening claim, so it may never speak for
# a fleet where another host answered "dpu". An unrecognised or absent mode sits
# between the two, because it asserts neither.
_VIRTIO_MODE_SEVERITY = {"dpu": 2, "nic": 0}
# How well the reading is proven against its own minimum, before the platform mode
# softens anything. A reading proven below its minimum outranks one that could not
# be graded, which outranks one proven patched. This is ranked ahead of the mode
# because the winning entry supplies `floorStatus` and `exposure`, so losing it
# loses a proven finding rather than a sentence of detail.
_VIRTIO_MINIMUM_SEVERITY = {"fail": 2, "unknown": 1, "pass": 0}
VERSION_REASON_NOT_OBSERVED = "not-observed"

# mlxprivhost applies zero-trust mode, which is what stops the host system
# administrator from reaching the BlueField.
MLXPRIVHOST_REMEDIATION = (
    "mlxprivhost -d <device> r --disable_rshim --disable_tracer "
    "--disable_counter_rd --disable_port_owner"
)
DPU_ISOLATION_REQUIREMENT = (
    "RShim restricted (INTERNAL_CPU_RSHIM=1), no /dev/rshim0, no tmfifo_net0"
)


def virtio_net_verdict(
    version: str, *, line: str | None = None, mode: str | None = None
) -> Verdict:
    """Grade the controller firmware, taking the BlueField platform mode into account.

    In DPU mode the controller runs and the minimum applies directly. In NIC mode
    no controller runs, so there is no exposure today, but the firmware is still
    installed on the card and NIC versus DPU mode is an mlxconfig setting a
    provider can flip. Reporting that as ``not_applicable`` would hide a real
    finding, so unpatched or unreadable firmware in NIC mode is reported as a
    warning instead. The module's status vocabulary has no warning member, so
    that case uses ``unknown``, which the security CLI already renders as a
    non-critical warning, and the latent-exposure wording lives in the detail.
    A mode the collector could not read falls back to the running grade, because
    an unproven idle controller cannot be assumed idle.
    """
    normalized = (mode or "").strip().lower() or None
    if normalized == "absent":
        return Verdict(
            version or "not-installed",
            "not_applicable",
            "NVIDIA BlueField only",
            _component_advisory("virtioNetBluefield"),
            "No BlueField DPU is present on the inspected host",
        )

    running = _virtio_running_verdict(version, line=line)
    if normalized != "nic":
        return running

    if running.status == "pass":
        return Verdict(
            version,
            "pass",
            running.minimum,
            running.advisory,
            f"{running.detail}; the BlueField is in NIC mode, so the virtio-net "
            f"controller is not currently running",
        )
    if running.status == "fail":
        reason = "the installed controller firmware is below the published minimum"
    elif running.minimum == MINIMUMS_UNAVAILABLE:
        # The minimum table itself could not be read, so nothing was compared. The
        # release-line wording below would send an operator to attest a release
        # line when the fault is on our side, in the table the audit ships.
        reason = (
            "the minimum version table is unusable, so the installed controller "
            "firmware was not compared against any minimum"
        )
    elif numeric_version(version, parts=3) is None:
        reason = "the installed controller firmware version could not be read"
    else:
        # Read, but it shares a year.month prefix with more than one release
        # line, so it cannot be graded without knowing the line. Saying it could
        # not be read would misdescribe evidence we do hold.
        reason = (
            "the installed controller firmware version could not be graded "
            "against a single release line"
        )
    return Verdict(
        version or "unknown",
        "unknown",
        running.minimum,
        running.advisory,
        f"The virtio-net controller is not running because the BlueField is in "
        f"NIC mode, so there is no exposure right now. However {reason}. The "
        f"firmware stays installed on the card, and a change to DPU mode would "
        f"run it unchanged, so this is a latent exposure that a mode change "
        f"would activate with no firmware update.",
    )


def _virtio_exposure(status: str, mode: str | None, minimum_status: str) -> str:
    """Describe the firmware, not the fleet coverage.

    `minimum_status` is how the read version compares to its own minimum, taken
    before any coverage rule runs and independent of the platform mode. It has
    to be consulted here: the coverage rule withdraws a clean answer to
    `unknown`, so deciding "latent" from the status alone claimed a below-minimum
    controller for firmware that had been read and proved patched. Latent means
    there is something a mode change would activate, so it may only be reported
    when the firmware is proven below its minimum, or when the card is idle and
    the installed firmware was not proven patched.

    That second case covers two outcomes, not one. Either no version was read,
    or a version was read and could not be graded, because the release lines
    interleave and the line was not reported. Both leave firmware a mode change
    would run with nothing proven about it, so both are latent, and
    `audit_findings._virtio_latent_ungraded` keeps them apart in the report.
    """
    if mode == "absent" or status in {"pass", "not_applicable"}:
        return EXPOSURE_NONE
    if minimum_status == "fail":
        # Proven below minimum. Idle in NIC mode, running otherwise.
        return EXPOSURE_LATENT if mode == "nic" else EXPOSURE_LIVE
    if minimum_status == "pass":
        # Read and proved patched, so nothing to activate. The status is not a
        # pass only because a coverage gap withdrew it.
        return EXPOSURE_UNKNOWN
    if mode == "nic":
        # The minimum grade settled on neither pass nor fail and the card is
        # idle. Either no version was read, or one was read and could not be
        # graded against a single release line. Both are unproven firmware that
        # a mode change would run.
        return EXPOSURE_LATENT
    return EXPOSURE_UNKNOWN


# One wording for a coverage gap, used by every path that can hit one, so the
# firmware verdict, the fleet rollup, and the DPU isolation verdict all read the
# same way in a report.
COVERAGE_GAP_FAIL_CAVEAT = (
    "The finding is confirmed on at least one host. Other hosts could not be "
    "assessed, so the cluster may carry further affected controllers, and this "
    "fail already stands on the host that was read."
)
# "Assessed" is deliberately about this criterion and not about reachability. A
# host the fan-out never reached could not be assessed, and so could a host that
# answered with its platform mode while its controller firmware stayed unread.
# Both leave installed firmware nobody graded, which is what "an unexamined host
# can run a vulnerable controller" states, so the sentence stays true when it is
# used beside coverageComplete = true.
COVERAGE_GAP_CLEAN_CAVEAT = (
    "This covers only the hosts that could be assessed. At least one host could "
    "not be, and an unexamined host can run a vulnerable controller, so the "
    "cluster is not cleared."
)


def _with_caveat(verdict: Verdict, caveat: str) -> Verdict:
    """Append a caveat to a detail. The status is never touched here."""
    return replace(verdict, detail=f"{verdict.detail.rstrip('.')}. {caveat}")


def _weigh_coverage_gap(verdict: Verdict, *, withdraw: tuple[str, ...]) -> Verdict:
    """Weigh one grade against the hosts that could not be assessed.

    One rule, applied wherever a gap exists, and deliberately asymmetric. A
    coverage gap may weaken a clean answer and may never weaken a proven one. A
    fail keeps its status and gains the fail caveat, because a host proven to
    run a below-minimum controller stays proven whatever happened elsewhere. A
    status in `withdraw` becomes unknown, because it speaks only for the hosts
    that answered and an unexamined host can run a vulnerable controller. Any
    other status keeps its grade and gains the caveat.

    `withdraw` differs between the two callers below, and that difference is
    the only thing that differs.
    """
    if verdict.status == "fail":
        return _with_caveat(verdict, COVERAGE_GAP_FAIL_CAVEAT)
    if verdict.status in withdraw:
        return Verdict(
            verdict.version,
            "unknown",
            verdict.minimum,
            verdict.advisory,
            f"{verdict.detail.rstrip('.')}. {COVERAGE_GAP_CLEAN_CAVEAT}",
        )
    return _with_caveat(verdict, COVERAGE_GAP_CLEAN_CAVEAT)


def _apply_rollup_coverage_gap(verdict: Verdict) -> Verdict:
    """Weigh the fleet rollup grade, used when no host produced a version.

    Only a pass is withdrawn here. An unknown is already the weakest answer, and
    a not_applicable on this path is a fleet-wide claim ("no BlueField anywhere",
    "no controller installed") that the check itself withdraws when coverage is
    partial, by no longer reporting mode "absent". Re-deriving that here would
    duplicate a decision that belongs upstream and would fight it if the two ever
    disagreed.
    """
    return _weigh_coverage_gap(verdict, withdraw=("pass",))


def _apply_partial_coverage(verdict: Verdict) -> Verdict:
    """Weigh a per-host grade, used when a reading exists for some hosts.

    Every non-fail answer is withdrawn here, a pass included. The grade came
    from one host's reading, so "no controller installed" or "could not be read"
    on that host says nothing at all about the hosts that never answered.
    """
    return _weigh_coverage_gap(
        verdict, withdraw=("pass", "unknown", "not_applicable")
    )


def _worst_observed_verdict(
    entries: Iterable[dict[str, Any]]
) -> tuple[Verdict, dict[str, Any]] | None:
    """Grade every host reading and return the worst, with the reading behind it.

    The check leaves ``worstObserved`` empty when its readings are not mutually
    comparable, because a bare numeric minimum across release lines or across
    versioning schemes picks the milder finding and would re-open the defect
    this path exists to close. It also leaves it empty when the readings
    disagree about the platform mode, because pairing one host's version with
    another host's mode invents a host. So each reading is graded here and the
    worst verdict wins, which needs no ordering between incomparable versions.

    Ties break on the minimum grade first, then on the platform mode, then on
    insertion order.

    The minimum grade has to come first. The winning entry supplies more than the
    status: `virtio_net_result` derives `floorStatus` and `exposure` from it,
    and the latent rules in `audit_findings.py` key on those. So handing
    the record to a less-proven reading erases a proven finding. A NIC-mode host
    proven below its minimum and a DPU-mode host whose version cannot be graded
    both grade `unknown`, and ranking mode first gave the record to the DPU
    reading, dropping `floorStatus: fail` and with it the below-minimum latent
    finding. An earlier version of this docstring claimed the tie-break "can
    never move a grade", which was true of `status` alone and had already
    stopped being true of the record.

    The mode tie-break then decides between readings that are equally proven. A
    NIC-mode grade carries the softening clause "the BlueField is in NIC mode,
    so the virtio-net controller is not currently running", so when another host
    answered in DPU mode the DPU reading owns the detail.
    """
    ranked: list[tuple[int, int, int, int, Verdict, dict[str, Any]]] = []
    for index, entry in enumerate(entries or []):
        version = str(entry.get("version") or "")
        if numeric_version(version, parts=3) is None:
            continue
        mode = str(entry.get("mode") or "").strip().lower()
        verdict = virtio_net_verdict(
            version, line=entry.get("line"), mode=entry.get("mode")
        )
        minimum = _virtio_running_verdict(version, line=entry.get("line")).status
        ranked.append((
            _VIRTIO_SEVERITY.get(verdict.status, 2),
            _VIRTIO_MINIMUM_SEVERITY.get(minimum, 1),
            _VIRTIO_MODE_SEVERITY.get(mode, 1),
            -index,
            verdict,
            entry,
        ))
    if not ranked:
        return None
    _, _, _, _, verdict, entry = max(ranked, key=lambda item: item[:4])
    return verdict, entry


def _flag_unassessed_dpu_host(
    verdict: Verdict,
    *,
    graded_version: str,
    graded_line: str | None,
    graded_mode: str | None,
    fleet_mode: str | None,
    every_host_reached: bool,
) -> tuple[Verdict, bool]:
    """Note that a host nobody could read may be running the same firmware, live.

    Platform mode is read from the host with mlxconfig and the controller
    version is read on the DPU with virtnet, so the ordinary fleet reads modes
    everywhere and versions almost nowhere. A below-minimum controller proven on a
    NIC-mode host, beside DPU-mode hosts that could not be assessed, is
    therefore a common shape rather than a corner case, and it is the most
    likely form of a real live exposure: in a homogeneous cluster the unread
    hosts probably run the same controller, and on those hosts it is running.

    The two mode signals are what make this visible. The fleet mode is the worst
    mode across all hosts including the ones that produced no reading, while the
    graded mode is the worst mode across readings only. When they disagree, a
    host exists whose mode is more severe than anything that could be graded.

    This adds evidence and never moves a grade. The status and the exposure stay
    exactly what they were: the firmware is proven, where it runs is not, and
    calling a host we never read an active exposure would be the same unproven
    claim this module refuses to make everywhere else. A later change must not
    turn this into a grading input.

    Of the two coverage flags this takes the reachability one, because the host
    it describes is one that never settled on an answer at all. A DPU-mode host
    that was reached and could not be read reports the check's "unknown" state,
    which is not a complete-coverage state, so `every_host_reached` is already
    false there. A fleet where every host settled has no such host: a settled
    host in DPU mode either read its version, which makes it assessed, or it
    would not have settled.
    """
    if every_host_reached or fleet_mode != "dpu" or graded_mode != "nic":
        return verdict, False
    if _virtio_running_verdict(graded_version, line=graded_line).status != "fail":
        return verdict, False
    return (
        replace(
            verdict,
            detail=(
                f"{verdict.detail.rstrip('.')}. The below-minimum controller was proven "
                f"on a host where it is not currently running, because that host is in "
                f"NIC mode. At least one host in DPU mode could not be assessed, and if "
                f"it runs this same controller then it is actively exposed there. "
                f"Request provider attestation of the controller version on every "
                f"DPU-mode host."
            ),
        ),
        True,
    )


def virtio_net_result(
    version: str,
    *,
    line: str | None = None,
    mode: str | None = None,
    version_source: str | None = None,
    version_reason: str | None = None,
    worst_version: str | None = None,
    worst_line: str | None = None,
    worst_mode: str | None = None,
    worst_host: str | None = None,
    observed: Iterable[dict[str, Any]] | None = None,
    coverage_complete: bool = True,
    every_bluefield_host_read: bool | None = None,
) -> dict[str, object]:
    """The values-file record: the verdict plus the facts that justify it.

    A consumer filters on ``exposure`` rather than parsing the detail, so
    "not exposed now, fix at the next maintenance window" is a state the
    dashboard can render distinctly from "vulnerable now" and "does not apply".

    A fleet rolls up to one state, and a rollup that ranks an unresolved host
    above a host whose version was read would let one unreadable node soften a
    proven finding on another. So when any host produced a version, that worst
    observed version is what gets graded, with the release line and platform
    mode of the host it came from, and the rollup state is read only for the two
    coverage questions below.

    The two coverage flags answer different questions and must stay separate:

    * ``coverage_complete``: was every host REACHED? It drives the rollup gap,
      the unassessed-DPU-host evidence, and the ``coverageComplete`` field.
    * ``every_bluefield_host_read``: did every host that carries a BlueField
      also produce a controller version? Only then may one reading clear the
      fleet. A fully reached fleet whose rollup is "not_running" holds a card
      with installed firmware that nobody read, so a patched reading beside it
      must still have its pass withdrawn.

    It defaults to ``coverage_complete``, which is the single-flag behavior a
    caller that cannot tell the two apart already expects. Only a caller holding
    the rollup state can separate them, and ``evaluate`` does.
    """
    if every_bluefield_host_read is None:
        every_bluefield_host_read = coverage_complete
    readings = list(observed or [])
    if numeric_version(worst_version or "", parts=3):
        # The check compared its readings and named one worst.
        source_entry = {
            "version": str(worst_version),
            "line": worst_line,
            "mode": worst_mode,
            "host": worst_host,
        }
        ranked = _worst_observed_verdict([source_entry])
    else:
        # Either no single worst was nameable (incomparable readings) or the
        # check reported none; grade every reading and take the worst verdict.
        ranked = _worst_observed_verdict(readings)

    if ranked is not None:
        verdict, source_entry = ranked
        graded_version = str(source_entry.get("version"))
        graded_line = source_entry.get("line")
        graded_mode = source_entry.get("mode")
        graded_host = source_entry.get("host")
        graded_from = "worst-observed-host"
        normalized = (graded_mode or "").strip().lower()
        normalized = normalized if normalized in VIRTIO_MODES else None
        if not every_bluefield_host_read:
            # This reading speaks only for the host it came from unless every
            # BlueField in the fleet was read. A reached host whose firmware
            # went unread is as unassessed, for this criterion, as a host the
            # fan-out never touched.
            verdict = _apply_partial_coverage(verdict)
    else:
        graded_version, graded_line, graded_mode, graded_host = version, line, mode, None
        graded_from = "cluster-rollup"
        normalized = (graded_mode or "").strip().lower()
        normalized = normalized if normalized in VIRTIO_MODES else None
        verdict = virtio_net_verdict(graded_version, line=graded_line, mode=normalized)
        if not coverage_complete:
            # No host produced a controller version, which is the ordinary fleet
            # outcome because reading one needs a route to the DPU. The same
            # rule applies as on the observed path: the gap is named, and a
            # clean answer that speaks only for the hosts that answered is
            # withdrawn rather than allowed to clear the fleet.
            verdict = _apply_rollup_coverage_gap(verdict)

    # The cluster-wide mode, which covers hosts that produced no reading.
    fleet_mode = (mode or "").strip().lower()
    fleet_mode = fleet_mode if fleet_mode in VIRTIO_MODES else None
    verdict, unassessed_dpu_host = _flag_unassessed_dpu_host(
        verdict,
        graded_version=graded_version,
        graded_line=graded_line,
        graded_mode=normalized,
        fleet_mode=fleet_mode,
        every_host_reached=coverage_complete,
    )

    # How the read version compares to its own minimum, before any coverage rule
    # and independent of the platform mode. Recorded so a consumer never has to
    # infer "below minimum" from a status the coverage rule may have moved.
    minimum_status = (
        _virtio_running_verdict(graded_version, line=graded_line).status
        if numeric_version(graded_version, parts=3)
        else "unknown"
    )
    running = {"dpu": True, "nic": False, "absent": False}.get(normalized)
    graded = numeric_version(graded_version, parts=3) is not None
    grace_component = (
        "virtioNetBluefield"
        if coverage_complete and every_bluefield_host_read
        else None
    )
    grace_selectors = _virtio_minimum_selectors(graded_version, graded_line)
    grace_selector: str | tuple[str, ...] | None = None
    if len(grace_selectors) == 1:
        grace_selector = grace_selectors[0]
    elif grace_selectors:
        grace_selector = grace_selectors
    return {
        **_verdict_record(
            verdict,
            grace_component,
            grace_selector,
            minimum_failure=minimum_status == "fail",
        ),
        "platformMode": normalized or "unknown",
        "controllerRunning": running,
        "releaseLine": graded_line,
        "versionSource": version_source,
        "versionUnavailableReason": None if graded else VERSION_REASON_NOT_OBSERVED,
        "versionUnavailableDetail": None if graded else (version_reason or None),
        "exposure": _virtio_exposure(verdict.status, normalized, minimum_status),
        "floorStatus": minimum_status,
        "gradedVersion": graded_version,
        "gradedFrom": graded_from,
        "gradedHost": graded_host,
        "fleetMode": fleet_mode or "unknown",
        # True when a below-minimum controller is proven on a host where it is
        # idle, while a DPU-mode host that could not be assessed may be running
        # it live. Evidence for the report, never an input to the grade.
        "unassessedDpuHostRisk": unassessed_dpu_host,
        "observedControllers": len(readings) or (1 if ranked is not None else 0),
        # Two coverage answers, never one. `coverageComplete` says every host
        # was reached and settled. `everyBluefieldHostRead` says every host
        # carrying a BlueField also produced a controller version, which is the
        # stricter claim a clean fleet verdict needs. True beside false is the
        # fully scanned fleet that still holds an unread card: the status is
        # withdrawn and the detail carries the gap caveat, while no host is
        # claimed unreachable.
        "coverageComplete": bool(coverage_complete),
        "everyBluefieldHostRead": bool(every_bluefield_host_read),
    }


def explain_unreadable_virtio_version(
    virtio: dict[str, object], isolation: dict[str, object]
) -> dict[str, object]:
    """Explain a virtio-net unknown using the DPU isolation evidence.

    An unreadable controller version has two opposite meanings that a bare
    ``unknown`` cannot separate. On a hardened DPU the version is unreadable
    *because* the provider restricted RShim and closed every host-side path, so
    the right follow-up is to ask the provider to attest the version and nothing
    is wrong with the cluster. Otherwise the check simply could not look, which
    says nothing good and nothing bad about the DPU. The same evaluate() call
    already holds both sets of evidence, so the two are told apart here instead
    of asking the collector for another field.

    This explains a status. It never changes one. The controller minimum and DPU
    host isolation stay independent criteria, and a later change must not grade
    either one from the other's result: a hardened DPU does not make unpatched
    firmware safe, and an unreadable version is not an isolation finding.
    """
    if virtio.get("status") != "unknown" or virtio.get("versionUnavailableReason") is None:
        return virtio
    hardened = (
        isolation.get("rshimRestricted") is True
        and isolation.get("rshimDeviceNode") is False
        and isolation.get("tmfifoNet0") is False
    )
    if not hardened:
        return virtio
    explained = dict(virtio)
    explained["versionUnavailableReason"] = VERSION_REASON_HARDENED
    base = str(virtio.get("detail", "")).strip().rstrip(".")
    explained["detail"] = (
        f"{base}. The controller version is not readable "
        f"because the DPU is correctly isolated from the host: RShim is "
        f"restricted and neither /dev/rshim0 nor tmfifo_net0 is present. RShim "
        f"is enabled by default and the out-of-box BlueField state assumes a "
        f"trusted host, so this is a deliberate hardening step and the expected "
        f"result on a hardened cluster. Request provider attestation of the "
        f"controller version; this is not a gap in the cluster."
    ).strip()
    return explained


def _isolation_coverage_caveat(verdict: Verdict, unassessed: Any) -> Verdict:
    """Name the hosts that could not be assessed beside a proven isolation failure.

    Same shape as the firmware caveat in `_apply_partial_coverage`, so the two
    criteria read consistently. A host that still carries a path to the DPU
    control plane is a proven finding and an unassessed host elsewhere cannot
    weaken it, so the gap is recorded rather than allowed to soften the grade.
    The status is never changed here, and a fully assessed fleet gets exactly
    the detail it got before.
    """
    names = [str(host).strip() for host in (unassessed or []) if str(host).strip()]
    if verdict.status != "fail" or not names:
        return verdict
    return _with_caveat(
        verdict,
        f"The finding is confirmed on at least one host. Other hosts could not be "
        f"assessed ({', '.join(names)}), so the cluster may carry further reachable "
        f"DPU control planes, and this fail already stands on the host that was read.",
    )


def dpu_host_isolation_verdict(evidence: dict[str, Any] | None = None) -> Verdict:
    """Grade whether the tenant-visible host can reach the BlueField control plane.

    Zero-trust mode is the specialization of DPU mode whose whole purpose is to
    stop the host system administrator from reaching the BlueField. A host that
    still has the RShim device node, a tmfifo_net0 interface, or an unrestricted
    INTERNAL_CPU_RSHIM is not in zero-trust mode, and the tenant-visible side of
    the machine can reach the DPU control plane. That is a tenant isolation
    finding, so it is graded and never inferred from silence: evidence the check
    could not collect (mlxconfig usually needs root) reports ``unknown``.

    Consumes the virtio-net check record shape (``checks/fabric/virtio-net-check.py``):
    ``scanComplete``, ``bluefield3Present``, ``scanError`` / ``modeError``, and
    ``rshimHostAccess.{rshimRestricted, rshimDeviceNode, tmfifoNet0, internalCpuRshim}``.
    """
    facts = evidence or {}
    rshim = facts.get("rshimHostAccess") or {}
    advisory = _component_advisory("virtioNetBluefield")
    requirement = DPU_ISOLATION_REQUIREMENT
    observed = str(rshim.get("internalCpuRshim", "unknown"))

    scan_complete = facts.get("scanComplete")
    present = facts.get("bluefield3Present")
    restricted = rshim.get("rshimRestricted")
    device_node = rshim.get("rshimDeviceNode")
    tmfifo = rshim.get("tmfifoNet0")
    reachable = [
        name
        for name, seen in (("/dev/rshim0", device_node), ("tmfifo_net0", tmfifo))
        if seen
    ]

    # The reachability proof is read before the scan gate below, because the two
    # facts are independent. `collect_rshim` stats /dev/rshim0 and
    # /sys/class/net/tmfifo_net0 and never runs lspci, so those flags are
    # populated and true even when the PCI scan found nothing. Gating them on
    # the scan let a missing lspci, the normal case in a minimal k8s driver pod,
    # turn a host proven to expose the DPU control plane into "could not be
    # assessed". A coverage gap may weaken a clean answer and must never erase a
    # proven failure.
    #
    # `restricted is False` is deliberately NOT part of that proof: it comes
    # from mlxconfig reading INTERNAL_CPU_RSHIM, which needs the device the scan
    # finds, so it cannot be trusted ahead of the scan. It keeps its place below.
    if reachable:
        verdict = Verdict(
            observed,
            "fail",
            requirement,
            advisory,
            f"The host side can reach the DPU control plane "
            f"({', '.join(reachable)}), so this cluster is not in zero-trust "
            f"mode and a host-side administrator, or a tenant with host access, "
            f"can reach the BlueField. Apply zero-trust mode with "
            f"`{MLXPRIVHOST_REMEDIATION}`.",
        )
        if not scan_complete:
            # Name the gap without weakening the grade. The path is proven; what
            # is unknown is whether other devices on this host share it.
            verdict = _with_caveat(
                verdict,
                "The BlueField inventory scan did not complete "
                f"({facts.get('scanError') or 'no scan evidence'}), so this host "
                "may carry further BlueField devices, and this fail already "
                "stands on the RShim path that was read.",
            )
        return _isolation_coverage_caveat(verdict, facts.get("unassessedHosts"))

    if not scan_complete or present is None:
        return _unknown(
            observed,
            requirement,
            advisory,
            "The BlueField inventory scan did not complete "
            f"({facts.get('scanError') or 'no scan evidence'}), and neither "
            f"/dev/rshim0 nor tmfifo_net0 is present, so DPU host isolation "
            f"could not be assessed",
        )
    if not present:
        return Verdict(
            "not-present",
            "not_applicable",
            "NVIDIA BlueField only",
            advisory,
            "No BlueField DPU is present in the completed device scan",
        )

    if restricted is False:
        return _isolation_coverage_caveat(
            Verdict(
                observed,
                "fail",
                requirement,
                advisory,
                f"The host side can reach the DPU control plane "
                f"(INTERNAL_CPU_RSHIM=0), so this cluster is not in zero-trust "
                f"mode and a host-side administrator, or a tenant with host "
                f"access, can reach the BlueField. Apply zero-trust mode with "
                f"`{MLXPRIVHOST_REMEDIATION}`.",
            ),
            facts.get("unassessedHosts"),
        )
    if restricted is True and device_node is False and tmfifo is False:
        return Verdict(
            observed,
            "pass",
            requirement,
            advisory,
            "RShim is restricted and neither /dev/rshim0 nor tmfifo_net0 is "
            "present, so the tenant-visible host cannot reach the DPU control plane",
        )
    return _unknown(
        observed,
        requirement,
        advisory,
        "The RShim posture could not be read "
        f"({facts.get('modeError') or 'mlxconfig reported no INTERNAL_CPU_RSHIM'}); "
        "mlxconfig usually needs root, so a tenant-side run cannot settle DPU "
        "host isolation",
    )


def dpu_host_isolation_result(evidence: dict[str, Any] | None = None) -> dict[str, object]:
    """The values-file record: the isolation verdict plus its supporting evidence."""
    facts = evidence or {}
    rshim = facts.get("rshimHostAccess") or {}
    verdict = dpu_host_isolation_verdict(evidence)
    return {
        **asdict(verdict),
        "bluefieldPresent": facts.get("bluefield3Present"),
        "scanComplete": bool(facts.get("scanComplete")),
        "rshimRestricted": rshim.get("rshimRestricted"),
        "rshimDeviceNode": rshim.get("rshimDeviceNode"),
        "tmfifoNet0": rshim.get("tmfifoNet0"),
        "internalCpuRshim": rshim.get("internalCpuRshim", "unknown"),
        # Hosts the check could not assess. Recorded so a fail carries its
        # coverage gap as structured data that a consumer can filter on.
        "unassessedHosts": [
            str(host).strip()
            for host in (facts.get("unassessedHosts") or [])
            if str(host).strip()
        ],
        "remediation": MLXPRIVHOST_REMEDIATION,
    }


def connectx_firmware_verdict(version: str) -> Verdict:
    """Evaluate the release.patch suffix shared across ConnectX firmware families.

    NVIDIA firmware starts with a hardware-family component, for example
    40.47.2526 on ConnectX-8. The bulletin publishes one fixed patch per
    firmware train. A train above every assessed train postdates the bulletin
    and gives a clean pass, the same way a driver branch newer than the newest
    assessed branch does. An older train the bulletin does not list
    is reported as ``unknown`` rather than failed, because it may well be
    unpatched and there is no minimum to grade it against.
    """
    try:
        block = minimum_versions.component("connectxFirmware")
        raw_trains = block.get("trains") or {}
        trains = {int(train): int(patch) for train, patch in raw_trains.items()}
        if not trains:
            raise MinimumDataError("minimum version table has no ConnectX firmware trains")
    except (MinimumDataError, TypeError, ValueError) as exc:
        return _minimums_unavailable(version, MinimumDataError(str(exc)))

    advisory = _advisory(block)
    minimum = ", ".join(f"{train}.{trains[train]}" for train in sorted(trains))
    observed = re.search(r"\d+(?:\.\d+){0,3}", version)
    if observed is None or len(observed.group(0).split(".")) < 3:
        return _unknown(version, minimum, advisory, "NIC firmware version is unavailable")
    parsed = numeric_version(version, parts=3)
    if parsed is None:
        return _unknown(version, minimum, advisory, "NIC firmware version is unavailable")
    _, train, patch = parsed
    if train not in trains:
        newest_train = max(trains)
        if train > newest_train:
            # Shipping firmware runs ahead of the bulletin table: ConnectX-8
            # ships train 47 while the current bulletin assesses up to train
            # 46. Such a train cannot be below a published minimum, because none
            # is published for it yet. That is a clean pass, the same as a
            # driver branch newer than the newest assessed branch, instead of
            # flagging a whole fleet as unverifiable with no new evidence.
            return Verdict(
                version,
                "pass",
                f"newer than train {newest_train} baseline",
                advisory,
                f"Train {train} postdates the current NVIDIA networking bulletin "
                f"table (newest assessed train {newest_train}), so no published "
                f"minimum version applies to it",
            )
        return _unknown(
            version,
            minimum,
            advisory,
            f"Firmware train {train} is not assessed by the current bulletin",
        )
    # The bulletin covers the observed train, so the minimum names that
    # train's fixed patch alone. Listing every train's minimum asked a reader
    # to work out which one applied to their card.
    train_minimum = f"{train}.{trains[train]}"
    passed = patch >= trains[train]
    return Verdict(
        version,
        "pass" if passed else "fail",
        train_minimum,
        advisory,
        f"Meets the firmware train {train} minimum version ({train_minimum})"
        if passed
        else f"Below the firmware train {train} minimum version ({train_minimum})",
    )


def aggregate_connectx(
    entries: Iterable[str], *, inventory_complete: bool = False
) -> dict[str, object]:
    advisory = _component_advisory("connectxFirmware")
    devices: list[dict[str, object]] = []
    verdicts: list[Verdict] = []
    records: list[dict[str, object]] = []
    for entry in entries:
        if "=" in entry:
            device, version = entry.split("=", 1)
        else:
            device, version = "unknown", entry
        verdict = connectx_firmware_verdict(version)
        verdicts.append(verdict)
        parsed = numeric_version(version, parts=3)
        selector = str(parsed[1]) if parsed and len(parsed) >= 3 else None
        record = _verdict_record(verdict, "connectxFirmware", selector)
        records.append(record)
        devices.append({"device": device, **record})
    if not verdicts:
        if inventory_complete:
            return {
                "status": "not_applicable",
                "minimum": "NVIDIA ConnectX/BlueField only",
                "advisory": advisory,
                "devices": [],
            }
        verdict = connectx_firmware_verdict("unknown")
        verdicts = [verdict]
        record = _verdict_record(verdict, "connectxFirmware")
        records = [record]
        devices = [{"device": "unknown", **record}]
    statuses = {str(record["status"]) for record in records}
    status = "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
    if status == "pass" and not inventory_complete:
        status = "unknown"
    minimum_record = next(
        (record for record in records if str(record["status"]) == status),
        None,
    )
    if minimum_record is None:
        minimum_record = _verdict_record(
            connectx_firmware_verdict("unknown"), "connectxFirmware"
        )
    result: dict[str, object] = {
        "status": status,
        "minimum": minimum_record["minimum"],
        "advisory": advisory,
        "devices": devices,
    }
    grace = next(
        (record.get("gracePeriod") for record in records if record.get("gracePeriod")),
        None,
    )
    if status == "pass" and grace:
        result["gracePeriod"] = grace
    return result


def minimums_metadata() -> dict[str, object]:
    """Return the provenance of the minimum table the verdicts were graded against."""
    try:
        return minimum_versions.metadata()
    except MinimumDataError as exc:
        return {"error": str(exc)}


def evaluate(
    *,
    driver: str,
    nct: str,
    runc: str,
    connectx_firmware: Iterable[str],
    gpu_vendor: str = "nvidia",
    docker: str = "unknown",
    cuda: str = "unknown",
    connectx_inventory_complete: bool = False,
    virtio_net: str = "unknown",
    virtio_net_line: str | None = None,
    virtio_net_mode: str | None = None,
    virtio_net_source: str | None = None,
    virtio_net_reason: str | None = None,
    dpu_isolation: dict[str, Any] | None = None,
    dcgm: str = "unknown",
    dcgm_exporter: str = "unknown",
    virtio_net_worst: str | None = None,
    virtio_net_worst_line: str | None = None,
    virtio_net_worst_mode: str | None = None,
    virtio_net_worst_host: str | None = None,
    virtio_net_observed: Iterable[dict[str, Any]] | None = None,
    virtio_net_state: str | None = None,
    nvidia_gpu_present: bool | None = None,
) -> dict[str, object]:
    if gpu_vendor.lower() == "nvidia":
        driver_result = nvidia_driver_verdict(driver)
        # A completed device scan that positively found no NVIDIA GPU takes
        # the driver minimum out of scope: there is no driver to grade and no
        # attestation a provider could give. Only an unreadable version defers
        # to the scan. A readable driver version is direct evidence an NVIDIA
        # stack is deployed, so it grades normally even when the scan claims
        # absence, because a wrong "absent" must never mask a below-minimum
        # driver. `None` means the collector made no claim either way, which
        # keeps the pre-existing unknown-and-attest behavior.
        if nvidia_gpu_present is False and numeric_version(driver) is None:
            driver_result = Verdict(
                "not-present",
                "not_applicable",
                "NVIDIA GPUs only",
                driver_result.advisory,
                "No NVIDIA GPU is present in the completed device scan, so "
                "the NVIDIA driver minimum does not apply to this target",
            )
        nct_result = nvidia_container_toolkit_verdict(nct)
        dcgm_result = dcgm_verdict(dcgm)
        dcgm_exporter_result = dcgm_exporter_verdict(dcgm_exporter)
    else:
        driver_result = Verdict(
            driver,
            "not_applicable",
            "NVIDIA only",
            _component_advisory("nvidiaDriver"),
            f"NVIDIA driver policy does not apply to {gpu_vendor} GPUs",
        )
        nct_result = Verdict(
            nct,
            "not_applicable",
            "NVIDIA only",
            _component_advisory("nvidiaContainerToolkit"),
            f"NVIDIA Container Toolkit policy does not apply to {gpu_vendor} GPUs",
        )
        dcgm_result = Verdict(
            dcgm,
            "not_applicable",
            "NVIDIA only",
            _component_advisory("dcgm"),
            f"DCGM policy does not apply to {gpu_vendor} GPUs",
        )
        dcgm_exporter_result = Verdict(
            dcgm_exporter,
            "not_applicable",
            "NVIDIA only",
            _component_advisory("dcgmExporter"),
            f"DCGM Exporter policy does not apply to {gpu_vendor} GPUs",
        )
    # The rollup state answers the two coverage questions separately. Coverage
    # is complete only when the check's rollup says every host resolved, and a
    # reading may clear the fleet only when every BlueField was read. An absent
    # state fails both: that can only weaken a clean reading, never a proven
    # failure.
    state = str(virtio_net_state or "")
    coverage_complete = state in VIRTIO_COMPLETE_STATES
    every_bluefield_host_read = state in VIRTIO_EVERY_BLUEFIELD_READ_STATES
    virtio_record = virtio_net_result(
        virtio_net,
        line=virtio_net_line,
        mode=virtio_net_mode,
        version_source=virtio_net_source,
        version_reason=virtio_net_reason,
        worst_version=virtio_net_worst,
        worst_line=virtio_net_worst_line,
        worst_mode=virtio_net_worst_mode,
        worst_host=virtio_net_worst_host,
        observed=virtio_net_observed,
        coverage_complete=coverage_complete,
        every_bluefield_host_read=every_bluefield_host_read,
    )
    isolation_record = dpu_host_isolation_result(dpu_isolation)
    driver_parsed = numeric_version(driver, parts=1)
    runc_parsed = numeric_version(runc, parts=2)
    return {
        "nvidiaDriver": _verdict_record(
            driver_result,
            "nvidiaDriver",
            str(driver_parsed[0]) if driver_parsed else None,
        ),
        "nvidiaContainerToolkit": _verdict_record(
            nct_result, "nvidiaContainerToolkit"
        ),
        "cudaToolkit": _verdict_record(
            cuda_toolkit_verdict(cuda), "cudaToolkit"
        ),
        "docker": _verdict_record(docker_verdict(docker), "docker"),
        "runc": _verdict_record(
            runc_verdict(runc),
            "runc",
            ".".join(str(part) for part in runc_parsed[:2]) if runc_parsed else None,
        ),
        "connectxFirmware": aggregate_connectx(
            connectx_firmware, inventory_complete=connectx_inventory_complete
        ),
        "virtioNetBluefield": explain_unreadable_virtio_version(
            virtio_record, isolation_record
        ),
        "dpuHostIsolation": isolation_record,
        "dcgm": _verdict_record(dcgm_result, "dcgm"),
        "dcgmExporter": _verdict_record(
            dcgm_exporter_result, "dcgmExporter"
        ),
        "floorsMetadata": minimums_metadata(),
    }


def _parse_isolation_json(raw: str | None) -> dict[str, Any] | None:
    """Read the check record the collector passes on the command line.

    Unreadable evidence stays unreadable: a malformed blob produces the same
    ``unknown`` verdict as no blob at all, never a pass.
    """
    if not raw or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"scanComplete": False, "scanError": "DPU isolation evidence was not valid JSON"}
    return parsed if isinstance(parsed, dict) else None


def _parse_observed_json(raw: str | None) -> list[dict[str, Any]]:
    """Read virtioNetObservedJson. Unreadable evidence yields no readings."""
    if not raw or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [entry for entry in parsed if isinstance(entry, dict)] if isinstance(parsed, list) else []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", default="unknown")
    parser.add_argument("--nct", default="unknown")
    parser.add_argument("--runc", default="unknown")
    parser.add_argument("--docker", default="unknown")
    parser.add_argument("--cuda", default="unknown")
    parser.add_argument("--gpu-vendor", default="nvidia")
    parser.add_argument("--connectx-firmware", action="append", default=[])
    parser.add_argument("--connectx-inventory-complete", action="store_true")
    parser.add_argument(
        "--nvidia-gpu-absent",
        action="store_true",
        help="every host completed a PCI device scan and none carried an "
        "NVIDIA GPU; omitted when any host could not read its bus",
    )
    parser.add_argument("--virtio-net", default="unknown")
    parser.add_argument("--virtio-net-line", default=None)
    parser.add_argument(
        "--virtio-net-mode",
        default=None,
        help="BlueField platform mode reported by the check: dpu, nic, or absent",
    )
    parser.add_argument(
        "--dcgm",
        default="unknown",
        help="DCGM host stack version, already separated from the exporter image tag",
    )
    parser.add_argument(
        "--dcgm-exporter",
        default="unknown",
        help="DCGM Exporter version, already separated from the image tag",
    )
    parser.add_argument(
        "--virtio-net-worst",
        default=None,
        help="virtioNetWorstObserved: the worst controller version any host actually read",
    )
    parser.add_argument("--virtio-net-worst-line", default=None)
    parser.add_argument("--virtio-net-worst-mode", default=None)
    parser.add_argument("--virtio-net-worst-host", default=None)
    parser.add_argument(
        "--virtio-net-observed-json",
        default=None,
        help="virtioNetObservedJson: every distinct host reading, graded when the "
        "check could not name one worst",
    )
    parser.add_argument(
        "--virtio-net-state",
        default=None,
        help="the check rollup state; every host counts as reached at "
        f"{sorted(VIRTIO_COMPLETE_STATES)}, and a reading may clear the fleet "
        f"only at {sorted(VIRTIO_EVERY_BLUEFIELD_READ_STATES)}",
    )
    parser.add_argument("--virtio-net-source", default=None)
    parser.add_argument("--virtio-net-reason", default=None)
    parser.add_argument(
        "--dpu-isolation-json",
        default=None,
        help="virtio-net check record JSON carrying scanComplete, bluefield3Present, "
        "and rshimHostAccess",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            evaluate(
                driver=args.driver,
                nct=args.nct,
                runc=args.runc,
                connectx_firmware=args.connectx_firmware,
                gpu_vendor=args.gpu_vendor,
                docker=args.docker,
                cuda=args.cuda,
                connectx_inventory_complete=args.connectx_inventory_complete,
                virtio_net=args.virtio_net,
                virtio_net_line=args.virtio_net_line,
                virtio_net_mode=args.virtio_net_mode,
                virtio_net_source=args.virtio_net_source,
                virtio_net_reason=args.virtio_net_reason,
                dpu_isolation=_parse_isolation_json(args.dpu_isolation_json),
                virtio_net_worst=args.virtio_net_worst,
                virtio_net_worst_line=args.virtio_net_worst_line,
                virtio_net_worst_mode=args.virtio_net_worst_mode,
                virtio_net_worst_host=args.virtio_net_worst_host,
                virtio_net_observed=_parse_observed_json(args.virtio_net_observed_json),
                virtio_net_state=args.virtio_net_state,
                nvidia_gpu_present=False if args.nvidia_gpu_absent else None,
                dcgm=args.dcgm,
                dcgm_exporter=args.dcgm_exporter,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
