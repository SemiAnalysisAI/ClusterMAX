#!/usr/bin/env python3
"""Validate raw per-harness audit JSON before publishing output."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def nested_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def first_known(*values: Any) -> Any:
    missing = {"", "unknown", "not-found", "none", "N/A", "n/a"}
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text.lower() in missing:
            continue
        return value
    return None


def gpu_driver_known(audit: dict[str, Any]) -> bool:
    check = audit.get("hostCheck")
    host_check = check if isinstance(check, dict) else {}
    driver = first_known(
        nested_get(audit, "gpus", "driverVersion"),
        host_check.get("WORKER_DRIVER_VERSION"),
    )
    return driver is not None


def validate_worker_check(audit: dict[str, Any], harness: str, audit_path: Path) -> bool:
    if harness == "k8s":
        total_gpus = as_int(nested_get(audit, "gpus", "total"))
        if total_gpus <= 0:
            return True
        if gpu_driver_known(audit):
            return True
        worker_check_ok = nested_get(audit, "software", "workerCheckOk", default=False)
        if worker_check_ok is True:
            return True
        print("", file=sys.stderr)
        print("ERROR: k8s audit incomplete (no GPU driver/CUDA facts collected)", file=sys.stderr)
        print("  GPU Operator labels and host-level checks both failed.", file=sys.stderr)
        print(f"  Audit raw JSON saved at: {audit_path}", file=sys.stderr)
        print("  Investigate GPU node access and re-run; not publishing.", file=sys.stderr)
        return False

    worker_check_ok = nested_get(audit, "software", "workerCheckOk", default=False)
    if worker_check_ok is True:
        return True

    print("", file=sys.stderr)
    print(f"ERROR: audit incomplete (software.workerCheckOk={str(worker_check_ok).lower()})", file=sys.stderr)
    print("  GPU / driver / NCCL fields would be 'unknown' or missing.", file=sys.stderr)
    print(f"  Audit raw JSON saved at: {audit_path}", file=sys.stderr)
    print("  Investigate worker reachability and re-run; not publishing.", file=sys.stderr)
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: validate_audit.py <audit.json> <harness>", file=sys.stderr)
        return 2

    audit_path = Path(argv[1])
    harness = argv[2]
    with audit_path.open() as f:
        audit = json.load(f)

    return 0 if validate_worker_check(audit, harness, audit_path) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
