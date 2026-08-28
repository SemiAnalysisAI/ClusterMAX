import importlib.util
from pathlib import Path
import unittest

from packaging.version import Version


SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "nightly_version.py"
SPEC = importlib.util.spec_from_file_location("nightly_version", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
NIGHTLY_VERSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NIGHTLY_VERSION)


class NightlyVersionTests(unittest.TestCase):
    def test_formats_the_first_daily_sequence_with_two_digits(self) -> None:
        self.assertEqual(
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", 1),
            "0.3.0.dev2026082601",
        )

    def test_keeps_a_run_number_longer_than_two_digits(self) -> None:
        self.assertEqual(
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", 123),
            "0.3.0.dev20260826123",
        )

    def test_next_release_nightly_is_newer_than_current_stable(self) -> None:
        nightly = NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", 1)

        self.assertGreater(Version(nightly), Version("0.2.1"))

    def test_rejects_an_invalid_release_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "X.Y.Z"):
            NIGHTLY_VERSION.nightly_version("0.2", "20260826", 1)

    def test_rejects_an_invalid_calendar_date(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid UTC calendar date"):
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260230", 1)

    def test_rejects_a_nonpositive_run_number(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", 0)


if __name__ == "__main__":
    unittest.main()
