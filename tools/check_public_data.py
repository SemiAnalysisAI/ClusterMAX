#!/usr/bin/env python3
"""Check the public source tree without printing suspect data into CI logs."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = {".notes", "runs", "results", "audit-results", "provider-data"}
PRIVATE_SUFFIXES = {".log", ".jsonl", ".pcap", ".pcapng", ".har", ".pem", ".key"}
RULES = (
    (
        "provider-attributed evidence",
        re.compile(
            r"(?<![a-z0-9])(?:gmi|nebius|firmus|hyperstack|gcore|crusoe|runpod|"
            r"voltage[ _-]?park|fluidstack)(?![a-z0-9])"
            r"|\b(?:azure|oci|oracle)\s+(?:gb300|mi355x)"
            r"|\boracle-(?:gb\d+|mi\d+)",
            re.IGNORECASE,
        ),
    ),
    (
        "private evidence provenance",
        re.compile(
            r"\bobserved on\b"
            r"|\bmirrors?\s+(?:the\s+)?(?:shape of\s+)?(?:the\s+)?(?:committed audit|real .* run)"
            r"|\breal\s+[`'\"]?(?:sinfo|ibnetdiscover|mlxlink|lldp|scheduler|provider|audit)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "deployment identifier",
        re.compile(
            r"\b(?:np-[0-9a-f]{6,}|ccw-(?:gpu|hpc|htc)|cluster\d+)\b"
            r"|\b[a-z]+-(?:b\d{3}|gb\d{3})-slurm\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unmarked hardware serial fixture",
        re.compile(r"^\s*Vendor Serial Number\s*:\s*(?!(?:TEST|SYNTHETIC)-)\S+", re.IGNORECASE),
    ),
)


def check_text(path: str, text: str) -> list[str]:
    if path == "tools/check_public_data.py":
        return []
    failures = []
    for number, line in enumerate(text.splitlines(), 1):
        for label, pattern in RULES:
            if pattern.search(line):
                failures.append(f"{path}:{number}: {label}")
    return failures


def check_path(path: str) -> list[str]:
    candidate = Path(path)
    if PRIVATE_DIRS.intersection(candidate.parts) or candidate.suffix.lower() in PRIVATE_SUFFIXES:
        return [f"{path}: private artifact path"]
    return []


def check_repository(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    )
    failures = []
    for raw in sorted(set(result.stdout.split(b"\0")) - {b""}):
        path = raw.decode("utf-8")
        failures.extend(check_path(path))
        file = root / path
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"{path}: unreviewed binary artifact")
            continue
        failures.extend(check_text(path, text))
    return failures


def main() -> int:
    failures = check_repository()
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Public data checks passed. Provenance review is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
