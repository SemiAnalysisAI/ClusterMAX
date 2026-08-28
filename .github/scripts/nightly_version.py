#!/usr/bin/env python3
"""Create a PEP 440 development version for a ClusterMAX nightly."""

from __future__ import annotations

import argparse
import datetime as dt
import re


RELEASE_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){2}")
DATE_PATTERN = re.compile(r"[0-9]{8}")


def nightly_version(release_version: str, date_utc: str, run_number: int) -> str:
    if RELEASE_VERSION_PATTERN.fullmatch(release_version) is None:
        raise ValueError("release version must have the X.Y.Z format")
    if DATE_PATTERN.fullmatch(date_utc) is None:
        raise ValueError("date must have the YYYYMMDD format")
    try:
        dt.datetime.strptime(date_utc, "%Y%m%d")
    except ValueError as exc:
        raise ValueError("date must be a valid UTC calendar date") from exc
    if run_number < 1:
        raise ValueError("run number must be a positive integer")

    sequence = f"{run_number:02d}"
    return f"{release_version}.dev{date_utc}{sequence}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--date", required=True, dest="date_utc")
    parser.add_argument("--run-number", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        print(nightly_version(args.release_version, args.date_utc, args.run_number))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
