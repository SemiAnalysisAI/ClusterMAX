#!/usr/bin/env python3
"""Read the generated minimum version table.

`minimum-versions.json` holds every published minimum version the audit grades
against. A daily GitHub Actions workflow regenerates it from upstream feeds
(NVIDIA CSAF, OSV, and the Ubuntu security API) and opens a pull request. The
security audit fetches the published copy of this table on startup; a cluster
with no outbound network prints one warning, grades against the installed
table, and stays reproducible with `--no-fetch-minimums`.

This module is the only reader. It is import-safe from the workload Python
checks and callable from the collector shell scripts:

    python3 minimum_versions.py --get components.nvidiaDriver.branches.595
    python3 minimum_versions.py --stale && echo "minimum table is old"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

MINIMUMS_ENV = "CLUSTERMAX_MINIMUM_VERSIONS"
DEFAULT_PATH = Path(__file__).resolve().parent / "minimum-versions.json"
DEFAULT_MAX_AGE_DAYS = 10
DEFAULT_GRACE_PERIOD_DAYS = 3
GRACE_REMINDER = "(passes as bulletin released within past 3 days)"
FIX_GRACE_REMINDER = "(passes as fix became available within past 3 days)"
FIX_UNCONFIRMED_REMINDER = (
    "(passes because fixed release availability is not yet confirmed)"
)
MINIMUM_NOT_EFFECTIVE_REMINDER = (
    "(passes because the minimum version is not yet effective)"
)

_CACHE: dict[str, Any] | None = None


class MinimumDataError(RuntimeError):
    """The minimum table is missing, unreadable, or the wrong schema version."""


def minimums_path() -> Path:
    override = os.environ.get(MINIMUMS_ENV, "").strip()
    return Path(override).expanduser() if override else DEFAULT_PATH


def load(path: Path | None = None, *, refresh: bool = False) -> dict[str, Any]:
    """Return the parsed minimum table, cached after the first successful read."""
    global _CACHE
    if _CACHE is not None and path is None and not refresh:
        return _CACHE
    target = path or minimums_path()
    try:
        data = json.loads(target.read_text())
    except FileNotFoundError as exc:
        raise MinimumDataError(f"minimum version table is missing: {target}") from exc
    except json.JSONDecodeError as exc:
        raise MinimumDataError(f"minimum version table is not valid JSON: {target}") from exc
    if data.get("schemaVersion") != 1:
        raise MinimumDataError(
            f"unsupported minimum version schema version {data.get('schemaVersion')!r} in {target}"
        )
    if path is None:
        _CACHE = data
    return data


def component(name: str, path: Path | None = None) -> dict[str, Any]:
    """Return one component block, such as ``nvidiaDriver``."""
    components = load(path).get("components", {})
    if name not in components:
        raise MinimumDataError(f"minimum version table has no component {name!r}")
    return components[name]


def get(dotted: str, path: Path | None = None, default: Any = None) -> Any:
    """Return a value by dotted path, for shell callers and checks."""
    node: Any = load(path)
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


def generated_at(path: Path | None = None) -> datetime | None:
    raw = load(path).get("generated")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def max_age_days(path: Path | None = None) -> int:
    value = load(path).get("maxAgeDays", DEFAULT_MAX_AGE_DAYS)
    return value if isinstance(value, int) and value > 0 else DEFAULT_MAX_AGE_DAYS


def grace_period_days(path: Path | None = None) -> int:
    value = load(path).get("gracePeriodDays", DEFAULT_GRACE_PERIOD_DAYS)
    return value if isinstance(value, int) and value > 0 else DEFAULT_GRACE_PERIOD_DAYS


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _source_timestamp(source: Any) -> datetime | None:
    if not isinstance(source, dict):
        return None
    return _parse_timestamp(source.get("released") or source.get("published"))


def minimum_released_at(
    name: str, selector: str | None = None, path: Path | None = None
) -> datetime | None:
    """Return the bulletin timestamp for one exact minimum.

    Keyed minimum tables can merge several bulletins. Their selector-to-source
    map prevents a new minimum on one branch from granting a grace period to an
    older minimum on another branch.
    """
    block = component(name, path)
    availability = minimum_fix_availability(name, selector, path)
    exact_release = _parse_timestamp((availability or {}).get("bulletinReleased"))
    if exact_release is not None:
        return exact_release
    kind = block.get("kind")
    source: Any = None
    if kind == "branchMap" and selector is not None:
        source_id = (block.get("branchSources") or {}).get(str(selector))
        source = next(
            (
                item
                for item in block.get("sources") or []
                if isinstance(item, dict) and str(item.get("aId")) == str(source_id)
            ),
            None,
        )
    elif kind == "ladder" and selector is not None:
        source_id = (block.get("floorSources") or {}).get(str(selector))
        source = next(
            (
                item
                for item in block.get("sources") or []
                if isinstance(item, dict) and str(item.get("id")) == str(source_id)
            ),
            None,
        )
    elif kind == "distroPackages" and selector is not None:
        package = (block.get("packages") or {}).get(str(selector))
        if isinstance(package, dict):
            stamp = _parse_timestamp(package.get("released") or package.get("published"))
            if stamp is not None:
                return stamp
            source = package.get("source")
    else:
        source = block.get("source")
    return _source_timestamp(source)


def minimum_fix_availability(
    name: str, selector: str | None = None, path: Path | None = None
) -> dict[str, Any] | None:
    """Return availability evidence for the exact fixed release of one minimum."""
    block = component(name, path)
    kind = block.get("kind")
    availability: Any = None
    if kind in {"branchMap", "trainMap", "ladder", "releaseLines"}:
        if selector is not None:
            availability = (block.get("floorAvailability") or {}).get(str(selector))
    elif kind == "distroPackages" and selector is not None:
        package = (block.get("packages") or {}).get(str(selector))
        if isinstance(package, dict):
            availability = package.get("fixAvailability")
    else:
        availability = block.get("fixAvailability")
    return availability if isinstance(availability, dict) else None


def active_grace_period(
    name: str,
    selector: str | Iterable[str] | None = None,
    path: Path | None = None,
    *,
    today: date | None = None,
) -> dict[str, Any] | None:
    """Return the active vendor window for one minimum or possible minimum set.

    The grace clock starts on the later of bulletin publication and confirmed
    fixed-release availability. That date is calendar day zero. The next three
    UTC calendar dates remain in the window, so enforcement starts on the
    fourth date after the clock starts. A minimum with a bulletin but no confirmed
    fix availability remains a pass until the refresh records availability.

    A version can be below every possible minimum while its exact release line is
    unavailable. In that case, enforcement waits for confirmed availability on
    every candidate and uses the candidate with the latest grace start.
    """
    if selector is None or isinstance(selector, str):
        selectors: tuple[str | None, ...] = (selector,)
    else:
        selectors = tuple(dict.fromkeys(str(value) for value in selector))
        if not selectors:
            selectors = (None,)

    bulletins = [minimum_released_at(name, value, path) for value in selectors]
    if any(stamp is None for stamp in bulletins):
        return None
    bulletin_stamps = [stamp for stamp in bulletins if stamp is not None]
    reference = today or datetime.now(timezone.utc).date()
    days = grace_period_days(path)
    availability_records = [
        minimum_fix_availability(name, value, path) for value in selectors
    ]
    parsed_availability = [
        _parse_timestamp((availability or {}).get("available"))
        for availability in availability_records
    ]
    unconfirmed = next(
        (
            availability
            for availability, available in zip(
                availability_records, parsed_availability, strict=True
            )
            if (availability or {}).get("status") != "confirmed" or available is None
        ),
        None,
    )
    if unconfirmed is not None or any(
        availability is None for availability in availability_records
    ):
        bulletin_released = max(bulletin_stamps)
        return {
            "active": True,
            "released": bulletin_released.isoformat().replace("+00:00", "Z"),
            "bulletinReleased": bulletin_released.isoformat().replace("+00:00", "Z"),
            "fixAvailable": None,
            "fixAvailabilityStatus": (unconfirmed or {}).get("status", "unconfirmed"),
            "gracePeriodDays": days,
            "graceStart": None,
            "enforcementDate": None,
            "message": FIX_UNCONFIRMED_REMINDER,
        }

    candidates = [
        (bulletin, available)
        for bulletin, available in zip(
            bulletin_stamps, parsed_availability, strict=True
        )
        if available is not None
    ]
    bulletin_released, available = max(
        candidates, key=lambda item: max(item[0], item[1])
    )
    grace_started = max(bulletin_released, available)
    grace_date = grace_started.astimezone(timezone.utc).date()
    elapsed = (reference - grace_date).days
    if elapsed < 0:
        return {
            "active": True,
            "released": bulletin_released.isoformat().replace("+00:00", "Z"),
            "bulletinReleased": bulletin_released.isoformat().replace("+00:00", "Z"),
            "fixAvailable": available.isoformat().replace("+00:00", "Z"),
            "fixAvailabilityStatus": "confirmed",
            "gracePeriodDays": days,
            "graceStart": grace_started.isoformat().replace("+00:00", "Z"),
            "enforcementDate": (grace_date + timedelta(days=days + 1)).isoformat(),
            "message": MINIMUM_NOT_EFFECTIVE_REMINDER,
        }
    if elapsed > days:
        return None
    return {
        "active": True,
        "released": bulletin_released.isoformat().replace("+00:00", "Z"),
        "bulletinReleased": bulletin_released.isoformat().replace("+00:00", "Z"),
        "fixAvailable": available.isoformat().replace("+00:00", "Z"),
        "fixAvailabilityStatus": "confirmed",
        "gracePeriodDays": days,
        "graceStart": grace_started.isoformat().replace("+00:00", "Z"),
        "enforcementDate": (grace_date + timedelta(days=days + 1)).isoformat(),
        "message": (
            FIX_GRACE_REMINDER if available > bulletin_released else GRACE_REMINDER
        ),
    }


def age_days(path: Path | None = None, *, now: datetime | None = None) -> float | None:
    stamp = generated_at(path)
    if stamp is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (reference - stamp).total_seconds() / 86400.0


def is_stale(path: Path | None = None, *, now: datetime | None = None) -> bool:
    age = age_days(path, now=now)
    return age is not None and age > max_age_days(path)


def remedy(path: Path | None = None) -> str:
    """Return the action that gets the current minimums for this installation.

    The daily workflow lands new minimums on `master`, so a git checkout gets
    them with `git pull`. A pip installation carries the table inside the
    installed package, and `git pull` does nothing there, so it reads the
    published table instead.
    """
    target = path or minimums_path()
    # A bare `.git` is not proof of this checkout. A virtual environment inside
    # another project, and a cache under a home directory that is itself a git
    # repository, both carry one. Only the ClusterMAX checkout holds
    # `cmax/scripts/1-audit` below the repository root.
    for parent in [target.parent, *target.parent.parents]:
        audit_dir = parent / "cmax" / "scripts" / "1-audit"
        if (parent / ".git").exists() and audit_dir.is_dir():
            return "Run `git pull` to get the current minimums"
    return (
        "Run `cmax audit security` to fetch the published minimums"
    )


def staleness_message(path: Path | None = None, *, now: datetime | None = None) -> str | None:
    """Return the operator-facing reminder, or None when the table is current.

    The reminder names the action that fits the installation. A checkout that
    is behind, and a pip installation that carries an old table, both grade
    against retired minimums.
    """
    age = age_days(path, now=now)
    if age is None or age <= max_age_days(path):
        return None
    stamp = generated_at(path)
    stamped = stamp.strftime("%Y-%m-%d") if stamp else "unknown"
    return (
        f"Minimum version data is {age:.0f} days old (generated {stamped}, "
        f"limit {max_age_days(path)} days). {remedy(path)}, then run the audit "
        f"again. A stale table can grade a vulnerable version as a pass."
    )


def metadata(path: Path | None = None, *, now: datetime | None = None) -> dict[str, Any]:
    """Return the provenance block the audit embeds in its values file."""
    age = age_days(path, now=now)
    return {
        "schemaVersion": load(path).get("schemaVersion"),
        "generated": load(path).get("generated"),
        "ageDays": round(age, 2) if age is not None else None,
        "maxAgeDays": max_age_days(path),
        "gracePeriodDays": grace_period_days(path),
        "stale": is_stale(path, now=now),
        "sources": {
            name: block.get("source", {})
            for name, block in load(path).get("components", {}).items()
        },
        "fixAvailability": {
            name: (
                block.get("floorAvailability")
                or block.get("fixAvailability")
                or {
                    key: package.get("fixAvailability")
                    for key, package in (block.get("packages") or {}).items()
                    if isinstance(package, dict) and package.get("fixAvailability")
                }
            )
            for name, block in load(path).get("components", {}).items()
            if (
                block.get("floorAvailability")
                or block.get("fixAvailability")
                or any(
                    isinstance(package, dict) and package.get("fixAvailability")
                    for package in (block.get("packages") or {}).values()
                )
            )
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", help="read an explicit minimum table instead of the default")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--get", metavar="DOTTED", help="print one value by dotted path")
    group.add_argument("--age-days", action="store_true", help="print the table age in days")
    group.add_argument("--stale", action="store_true", help="exit 0 when the table is stale")
    group.add_argument("--reminder", action="store_true", help="print the staleness reminder")
    group.add_argument("--metadata", action="store_true", help="print the provenance block")
    group.add_argument(
        "--grace-period",
        metavar="COMPONENT",
        help="print the active grace period for one minimum",
    )
    parser.add_argument("--selector", help="select one branch, train, release line, or package")
    args = parser.parse_args()
    path = Path(args.path) if args.path else None
    try:
        if args.get:
            value = get(args.get, path)
            if value is None:
                return 1
            print(value if not isinstance(value, (dict, list)) else json.dumps(value, sort_keys=True))
        elif args.age_days:
            age = age_days(path)
            print(f"{age:.2f}" if age is not None else "unknown")
        elif args.stale:
            return 0 if is_stale(path) else 1
        elif args.reminder:
            message = staleness_message(path)
            if not message:
                return 1
            print(message)
        elif args.metadata:
            print(json.dumps(metadata(path), sort_keys=True))
        elif args.grace_period:
            grace = active_grace_period(args.grace_period, args.selector, path)
            if grace is None:
                return 1
            print(json.dumps(grace, sort_keys=True))
    except MinimumDataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
