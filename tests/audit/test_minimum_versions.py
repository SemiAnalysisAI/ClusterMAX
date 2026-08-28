#!/usr/bin/env python3
"""Tests for the generated minimum version table and its reader.

Two contracts live here:

1. The committed `minimum-versions.json` still carries a usable minimum for every
   component the version audit grades. A daily workflow regenerates that file,
   so a bad regeneration is the realistic failure mode. The generated policy
   self-test derives its samples from the table itself: for every published
   minimum, the exact minimum release must grade "pass" and the release
   immediately below it must compare as "fail". The reported audit result can
   be a temporary pass while that minimum's fix is in its grace period.
   Nothing here restates a minimum, so the tests cannot drift from the data.
2. `minimum_versions.py` reads that table the way the checks and the collector
   shell scripts do, including the environment override, the staleness rules,
   and the command-line interface.

Every test is offline. No test reaches an upstream advisory feed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory


WORKLOAD_DIR = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
MODULE_PATH = WORKLOAD_DIR / "security_version_audit.py"
READER_PATH = WORKLOAD_DIR / "minimum_versions.py"
SPEC = importlib.util.spec_from_file_location("security_version_audit", MODULE_PATH)
assert SPEC and SPEC.loader
security = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = security
SPEC.loader.exec_module(security)

# The audit module imports the reader, so this is the same module object the
# graded verdicts use. Sharing it keeps the cache handling in one place.
minimums = security.minimum_versions

# Every component the version audit grades against, with the evaluator that
# consumes it. A component that leaves this table cannot be graded at all. Each
# evaluator takes the sample keywords its component publishes, so a kind that
# needs more than a version string (the interleaved VIRTIO-Net release lines)
# is graded here rather than skipped.
EVALUATORS = {
    "nvidiaDriver": lambda version, **kwargs: security.nvidia_driver_verdict(version, **kwargs),
    "nvidiaContainerToolkit": (
        lambda version, **kwargs: security.nvidia_container_toolkit_verdict(version, **kwargs)
    ),
    "cudaToolkit": lambda version, **kwargs: security.cuda_toolkit_verdict(version, **kwargs),
    "dcgm": lambda version, **kwargs: security.dcgm_verdict(version, **kwargs),
    "dcgmExporter": lambda version, **kwargs: security.dcgm_exporter_verdict(version, **kwargs),
    "docker": lambda version, **kwargs: security.docker_verdict(version, **kwargs),
    "runc": lambda version, **kwargs: security.runc_verdict(version, **kwargs),
    "connectxFirmware": (
        lambda version, **kwargs: security.connectx_firmware_verdict(version, **kwargs)
    ),
    "virtioNetBluefield": lambda version, **kwargs: security.virtio_net_verdict(version, **kwargs),
}

_RC_RE = re.compile(r"^(?P<base>\d+(?:\.\d+)*)(?P<sep>[-.~+]rc[.-]?)(?P<rc>\d+)$", re.IGNORECASE)


def previous_release(version: str) -> str:
    """Return the release immediately below `version`.

    Used to derive the failing sample for a published minimum. A release
    candidate steps back one candidate; a numbered release steps back the
    last non-zero component, so `1.4.0` becomes `1.3.0` instead of a negative
    patch.
    """
    match = _RC_RE.match(version)
    if match:
        candidate = int(match.group("rc"))
        if candidate > 1:
            return f"{match.group('base')}{match.group('sep')}{candidate - 1}"
        version = match.group("base")
    parts = [int(part) for part in version.split(".")]
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] > 0:
            parts[index] -= 1
            return ".".join(str(part) for part in parts)
    raise ValueError(f"no release below {version!r}")


def minimum_samples(name: str, block: dict) -> list[tuple[str, str | None, str, str, dict]]:
    """Derive label, minimum selector, versions, and evaluator inputs."""
    kind = block.get("kind")
    if kind == "minimum":
        minimum = block["minimum"]
        return [(name, None, minimum, previous_release(minimum), {})]
    if kind == "branchMap":
        return [
            (f"{name}.{branch}", branch, minimum, previous_release(minimum), {})
            for branch, minimum in sorted(block["branches"].items())
        ]
    if kind == "ladder":
        return [
            (f"{name}.{branch}", branch, minimum, previous_release(minimum), {})
            for branch, minimum in sorted(block["ladder"].items())
        ]
    if kind == "trainMap":
        # ConnectX firmware carries a hardware-family prefix the policy ignores.
        return [
            (
                f"{name}.{train}",
                train,
                f"40.{train}.{patch}",
                f"40.{train}.{int(patch) - 1}",
                {},
            )
            for train, patch in sorted(block["trains"].items())
        ]
    if kind == "releaseLines":
        # The release lines interleave, so a minimum is only decidable when the
        # line is named. The samples name it, which is also the accurate path a
        # collector takes once it can report the line.
        return [
            (
                f"{name}.{line}",
                line,
                spec["fixed"],
                previous_release(spec["fixed"]),
                {"line": line},
            )
            for line, spec in sorted(block["lines"].items())
            if spec.get("fixed")
        ]
    raise AssertionError(f"component {name!r} has unsupported kind {kind!r}")


def _minimum_values(block: dict) -> object:
    """Return whatever minimum the component publishes, whatever its kind."""
    return (
        block.get("minimum")
        or block.get("branches")
        or block.get("ladder")
        or block.get("trains")
        or block.get("lines")
    )


def write_table(directory: Path, **overrides) -> Path:
    """Write a small, valid minimum table with the requested fields replaced."""
    table = {
        "schemaVersion": 1,
        "generated": "2026-07-01T00:00:00Z",
        "gracePeriodDays": 3,
        "maxAgeDays": 10,
        "components": {
            "docker": {
                "advisory": "https://example.invalid/docker",
                "fixAvailability": {
                    "status": "confirmed",
                    "available": "2026-06-30T00:00:00Z",
                    "feed": "example-release",
                },
                "kind": "minimum",
                "minimum": "30.1.2",
                "source": {"feed": "manual"},
            }
        },
    }
    table.update(overrides)
    path = directory / "minimum-versions.json"
    path.write_text(json.dumps(table))
    return path


@contextmanager
def minimums_env(path: Path):
    """Point the reader at `path` through the operator environment override."""
    previous = os.environ.get(minimums.MINIMUMS_ENV)
    os.environ[minimums.MINIMUMS_ENV] = str(path)
    minimums._CACHE = None
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(minimums.MINIMUMS_ENV, None)
        else:
            os.environ[minimums.MINIMUMS_ENV] = previous
        minimums._CACHE = None


def reader_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(READER_PATH), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class MinimumTableContractTests(unittest.TestCase):
    """The committed table still supports every check the audit publishes."""

    def test_every_evaluated_component_has_a_non_empty_minimum(self) -> None:
        for name in EVALUATORS:
            with self.subTest(component=name):
                block = minimums.component(name)
                self.assertTrue(
                    _minimum_values(block),
                    f"{name} carries no minimum the audit can grade against",
                )

    def test_every_evaluated_component_publishes_an_advisory_url(self) -> None:
        for name in EVALUATORS:
            with self.subTest(component=name):
                self.assertTrue(minimums.component(name).get("advisory", "").startswith("http"))

    def test_docker_grace_period_starts_on_release_note_publication(self) -> None:
        grace = minimums.active_grace_period("docker", today=date(2026, 7, 31))
        self.assertIsNotNone(grace)
        assert grace is not None
        self.assertEqual(grace["fixAvailable"], "2026-07-30T00:00:00Z")
        self.assertEqual(grace["graceStart"], "2026-07-30T21:33:46Z")
        self.assertEqual(grace["enforcementDate"], "2026-08-03")
        self.assertIsNone(
            minimums.active_grace_period("docker", today=date(2026, 8, 3))
        )

    def test_generated_policy_grades_each_published_minimum(self) -> None:
        """The regression that catches a bad regeneration of the table.

        Every minimum in the committed table is replayed through the real
        evaluator. The minimum release must pass and the release immediately
        below it must compare as unsafe. Its audit record fails after the
        grace period and passes with a reminder during that period.
        A minimum that regenerates into the wrong field, branch, or string cannot
        ship silently.
        """
        checked = 0
        for name, evaluate in EVALUATORS.items():
            block = minimums.component(name)
            for label, selector, passing, failing, keywords in minimum_samples(name, block):
                with self.subTest(minimum=label, version=passing):
                    self.assertEqual(evaluate(passing, **keywords).status, "pass")
                with self.subTest(minimum=label, version=failing):
                    verdict = evaluate(failing, **keywords)
                    self.assertEqual(verdict.status, "fail")
                    record = security._verdict_record(verdict, name, selector)
                    grace = minimums.active_grace_period(name, selector)
                    self.assertEqual(record["status"], "pass" if grace else "fail")
                    if grace:
                        self.assertEqual(record["gracePeriod"], grace)
                        self.assertIn(
                            record["gracePeriod"]["message"],
                            {
                                minimums.GRACE_REMINDER,
                                minimums.FIX_GRACE_REMINDER,
                                minimums.FIX_UNCONFIRMED_REMINDER,
                                minimums.MINIMUM_NOT_EFFECTIVE_REMINDER,
                            },
                        )
                checked += 1
        self.assertGreaterEqual(checked, len(EVALUATORS))

    def test_posture_checks_carry_no_minimum_and_are_absent_by_design(self) -> None:
        """DPU host isolation is graded, and it is not in the self-test above.

        It is a posture check: zero-trust mode either keeps the host away from
        the BlueField control plane or it does not, and there is no version to
        compare. Recording that here keeps the absence deliberate instead of a
        component the self-test skips without anyone noticing.
        """
        with self.assertRaises(minimums.MinimumDataError):
            minimums.component("dpuHostIsolation")
        self.assertNotIn("dpuHostIsolation", EVALUATORS)
        verdict = security.dpu_host_isolation_verdict(
            {"scanComplete": True, "bluefield3Present": False}
        )
        self.assertEqual(verdict.status, "not_applicable")

    def test_table_declares_the_supported_schema_and_a_parsable_stamp(self) -> None:
        self.assertEqual(minimums.load()["schemaVersion"], 1)
        self.assertIsNotNone(minimums.generated_at())
        self.assertGreater(minimums.max_age_days(), 0)
        self.assertEqual(minimums.grace_period_days(), 3)


class MinimumReaderTests(unittest.TestCase):
    def test_unsupported_schema_version_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp), schemaVersion=2)
            with self.assertRaises(minimums.MinimumDataError):
                minimums.load(path)

    def test_missing_table_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(minimums.MinimumDataError):
                minimums.load(Path(tmp) / "absent.json")

    def test_unparsable_table_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "minimum-versions.json"
            path.write_text("{not json")
            with self.assertRaises(minimums.MinimumDataError):
                minimums.load(path)

    def test_unknown_component_is_rejected(self) -> None:
        with self.assertRaises(minimums.MinimumDataError):
            minimums.component("noSuchComponent")

    def test_environment_override_selects_another_table(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp))
            with minimums_env(path):
                self.assertEqual(minimums.minimums_path(), path)
                self.assertEqual(minimums.get("components.docker.minimum"), "30.1.2")
        # The override is scoped: the committed table is in force again.
        self.assertNotEqual(minimums.get("components.docker.minimum"), "30.1.2")

    def test_staleness_uses_the_declared_age_limit(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp), generated="2026-07-01T00:00:00Z", maxAgeDays=10)
            stamp = datetime(2026, 7, 1, tzinfo=timezone.utc)
            self.assertFalse(minimums.is_stale(path, now=stamp + timedelta(days=10)))
            self.assertTrue(minimums.is_stale(path, now=stamp + timedelta(days=11)))
            self.assertAlmostEqual(
                minimums.age_days(path, now=stamp + timedelta(days=11)), 11.0, places=6
            )

    def test_staleness_message_names_the_action_for_this_installation(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp), generated="2026-07-01T00:00:00Z", maxAgeDays=10)
            stamp = datetime(2026, 7, 1, tzinfo=timezone.utc)
            self.assertIsNone(minimums.staleness_message(path, now=stamp + timedelta(days=10)))
            message = minimums.staleness_message(path, now=stamp + timedelta(days=40))
            self.assertIsNotNone(message)
            # The table is outside a git checkout here, which is the shape of a
            # pip installation. `git pull` cannot move that table.
            self.assertIn("`cmax audit security` to fetch", message)
            self.assertIn("2026-07-01", message)

    def test_the_remedy_follows_the_installation_shape(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_table(root, generated="2026-07-01T00:00:00Z")
            # A pip installation carries the table inside the package.
            self.assertIn("`cmax audit security` to fetch", minimums.remedy(path))
            # A `.git` alone is not this checkout. A virtual environment inside
            # another project sits under one, and `git pull` there moves
            # nothing.
            (root / ".git").mkdir()
            self.assertIn("`cmax audit security` to fetch", minimums.remedy(path))
            # A checkout gets new minimums from the daily refresh on master.
            (root / "cmax" / "scripts" / "1-audit").mkdir(parents=True)
            self.assertIn("git pull", minimums.remedy(path))

    def test_metadata_reports_provenance_and_staleness(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp), generated="2026-07-01T00:00:00Z", maxAgeDays=10)
            stamp = datetime(2026, 7, 1, tzinfo=timezone.utc)
            meta = minimums.metadata(path, now=stamp + timedelta(days=11))
            self.assertEqual(meta["schemaVersion"], 1)
            self.assertEqual(meta["generated"], "2026-07-01T00:00:00Z")
            self.assertEqual(meta["maxAgeDays"], 10)
            self.assertEqual(meta["gracePeriodDays"], 3)
            self.assertEqual(meta["ageDays"], 11.0)
            self.assertTrue(meta["stale"])
            self.assertEqual(meta["sources"]["docker"], {"feed": "manual"})
            self.assertEqual(
                meta["fixAvailability"]["docker"]["available"],
                "2026-06-30T00:00:00Z",
            )


class MinimumReaderCliTests(unittest.TestCase):
    """The shell collectors call the reader as a command, so its exits matter."""

    def test_get_prints_a_value_and_exits_zero(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp))
            result = reader_cli("--path", str(path), "--get", "components.docker.minimum")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "30.1.2")

    def test_get_exits_one_for_a_missing_path(self) -> None:
        with TemporaryDirectory() as tmp:
            path = write_table(Path(tmp))
            result = reader_cli("--path", str(path), "--get", "components.docker.absent")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout.strip(), "")

    def test_get_exits_two_when_the_table_is_unreadable(self) -> None:
        with TemporaryDirectory() as tmp:
            result = reader_cli(
                "--path",
                str(Path(tmp) / "absent.json"),
                "--get",
                "components.docker.minimum",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("error:", result.stderr)

    def test_stale_exit_code_reports_the_table_age(self) -> None:
        now = datetime.now(timezone.utc)
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "fresh").mkdir()
            fresh = write_table(
                Path(tmp) / "fresh", generated=now.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            old = write_table(
                Path(tmp),
                generated=(now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            self.assertEqual(reader_cli("--path", str(fresh), "--stale").returncode, 1)
            self.assertEqual(reader_cli("--path", str(old), "--stale").returncode, 0)

    def test_reminder_prints_only_when_the_table_is_stale(self) -> None:
        now = datetime.now(timezone.utc)
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "fresh").mkdir()
            fresh = write_table(
                Path(tmp) / "fresh", generated=now.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            old = write_table(
                Path(tmp),
                generated=(now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            quiet = reader_cli("--path", str(fresh), "--reminder")
            self.assertEqual(quiet.returncode, 1)
            self.assertEqual(quiet.stdout.strip(), "")
            loud = reader_cli("--path", str(old), "--reminder")
            self.assertEqual(loud.returncode, 0)
            # The temporary table is outside a git checkout, so the reminder
            # names the fetch instead of `git pull`.
            self.assertIn("`cmax audit security` to fetch", loud.stdout)


if __name__ == "__main__":
    unittest.main()
