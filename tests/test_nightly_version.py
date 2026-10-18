import importlib.util
from pathlib import Path

from packaging.version import Version
import yaml

from cmax import __version__


SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "nightly_version.py"
SPEC = importlib.util.spec_from_file_location("nightly_version", SCRIPT_PATH)
assert SPEC and SPEC.loader
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
        workflow = SCRIPT_PATH.parents[1] / "workflows" / "python-nightly.yml"
        configured_base = yaml.safe_load(workflow.read_text())["env"]["NIGHTLY_VERSION"]
        nightly = NIGHTLY_VERSION.nightly_version(configured_base, "20260826", 1)

        self.assertGreater(Version(nightly), Version(__version__))
        self.assertLess(Version(nightly), Version(configured_base))

    def test_rejects_an_invalid_release_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "X.Y.Z"):
            NIGHTLY_VERSION.nightly_version("0.2", "20260826", 1)

    def test_rejects_an_invalid_calendar_date(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid UTC calendar date"):
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260230", 1)

    def test_rejects_a_nonpositive_run_number(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            NIGHTLY_VERSION.nightly_version("0.3.0", "20260826", 0)


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
