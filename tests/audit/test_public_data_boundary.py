"""Tests for the public-data publication check. All examples are invented."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_data_check", ROOT / "tools/check_public_data.py")
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def test_public_tree_passes_the_data_check() -> None:
    assert CHECK.check_repository(ROOT) == []


def test_check_rejects_private_artifact_paths() -> None:
    for path in ("runs/example/result.json", "results/example.txt", "capture.pcap", "session.log", "id.key"):
        assert CHECK.check_path(path), path
    assert CHECK.check_path("tests/audit/fixtures/minimum_refresh/public-advisory.json") == []


def test_check_reports_locations_without_echoing_suspect_content() -> None:
    evidence = "# observed" + " on a private deployment"
    failures = CHECK.check_text("tests/example.py", evidence)
    assert failures == ["tests/example.py:1: private evidence provenance"]
    assert all(evidence not in failure for failure in failures)


def test_check_requires_invented_serials() -> None:
    field = "Vendor Serial Number"
    assert CHECK.check_text("tests/example.py", field + ": PRIVATE123")
    assert CHECK.check_text("tests/example.py", field + ": TEST-SERIAL-001") == []


def test_published_api_identifiers_remain_supported() -> None:
    text = "\n".join(
        (
            'resource = "vpc.amazonaws.com/efa"',
            'resource = "mrdma.google.com"',
            'label = "node.coreweave.cloud/class"',
            'label = "kubernetes.azure.com/cluster"',
            'runtime = "OCI runtime"',
        )
    )
    assert CHECK.check_text("cmax/example.py", text) == []
