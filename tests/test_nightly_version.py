import importlib.util
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "nightly_version.py"
SPEC = importlib.util.spec_from_file_location("nightly_version", SCRIPT_PATH)
assert SPEC and SPEC.loader
NIGHTLY_VERSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NIGHTLY_VERSION)


@pytest.mark.parametrize(
    ("run", "expected"),
    [(1, "0.3.0.dev2026082601"), (123, "0.3.0.dev20260826123")],
)
def test_formats_daily_sequence(run: int, expected: str) -> None:
    assert NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", run) == expected


@pytest.mark.parametrize(
    ("release", "date", "run", "message"),
    [
        ("0.2", "20260826", 1, "X.Y.Z"),
        ("0.3.0", "20260230", 1, "valid UTC calendar date"),
        ("0.3.0", "20260826", 0, "positive integer"),
    ],
)
def test_rejects_invalid_inputs(release: str, date: str, run: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        NIGHTLY_VERSION.nightly_version(release, date, run)
