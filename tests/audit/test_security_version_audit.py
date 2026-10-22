#!/usr/bin/env python3
"""Policy semantics after bulletin grace windows. Read floors from the generated table."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
MODULE_PATH = AUDIT_SCRIPTS / "security_version_audit.py"
SPEC = importlib.util.spec_from_file_location("security_version_audit", MODULE_PATH)
assert SPEC and SPEC.loader
security = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = security
SPEC.loader.exec_module(security)

minimums = security.minimum_versions
_ACTIVE_GRACE_PERIOD = minimums.active_grace_period


def setUpModule() -> None:
    """Keep comparison tests deterministic after every bulletin window."""

    def expired_grace(name, selector=None, path=None, *, today=None):
        return _ACTIVE_GRACE_PERIOD(
            name, selector, path, today=date(2100, 1, 1)
        )

    patcher = mock.patch.object(minimums, "active_grace_period", side_effect=expired_grace)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


def tearDownModule() -> None:
    unittest.doModuleCleanups()


def read_minimum(dotted: str):
    """Read one published minimum, so a test cannot drift from the table."""
    value = minimums.get(dotted)
    assert value is not None, f"minimum version table has no {dotted}"
    return value


def _just_below(version: str) -> str:
    """Return a release just below `version`: its last non-zero part minus one."""
    parts = list(security.numeric_version(version, parts=3))
    for index in reversed(range(len(parts))):
        if parts[index] > 0:
            parts[index] -= 1
            break
    return ".".join(str(part) for part in parts)


def _shift_patch(version: str, delta: int) -> str:
    """Return the release `delta` patches from `version`, using the real parser."""
    major, minor, patch = security.numeric_version(version, parts=3)
    return f"{major}.{minor}.{patch + delta}"


def newest_driver_minimum() -> str:
    """The minimum for the newest driver branch the bulletin assesses."""
    branches = read_minimum("components.nvidiaDriver.branches")
    return branches[str(max(int(key) for key in branches))]


@contextmanager
def unreadable_minimum_table():
    """Point the reader at a table that does not exist."""
    previous = os.environ.get(minimums.MINIMUMS_ENV)
    os.environ[minimums.MINIMUMS_ENV] = "/nonexistent/clustermax/minimum-versions.json"
    minimums._CACHE = None
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(minimums.MINIMUMS_ENV, None)
        else:
            os.environ[minimums.MINIMUMS_ENV] = previous
        minimums._CACHE = None


class NvidiaDriverPolicyTests(unittest.TestCase):
    def test_driver_below_its_branch_minimum_version_fails(self) -> None:
        minimum = read_minimum("components.nvidiaDriver.branches.580")
        parts = [int(part) for part in minimum.split(".")]
        parts[-1] -= 1
        verdict = security.nvidia_driver_verdict(".".join(map(str, parts)))
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, read_minimum("components.nvidiaDriver.branches.580"))
        self.assertEqual(verdict.advisory, read_minimum("components.nvidiaDriver.advisory"))

    def test_every_published_branch_minimum_passes_and_reports_its_minimum(self) -> None:
        for branch, minimum in read_minimum("components.nvidiaDriver.branches").items():
            with self.subTest(branch=branch):
                verdict = security.nvidia_driver_verdict(minimum)
                self.assertEqual(verdict.status, "pass")
                self.assertEqual(verdict.minimum, minimum)

    def test_unlisted_older_branch_requires_attestation(self) -> None:
        branches = {int(key) for key in read_minimum("components.nvidiaDriver.branches")}
        unlisted = next(
            branch
            for branch in range(max(branches) - 1, min(branches), -1)
            if branch not in branches
        )
        self.assertEqual(security.nvidia_driver_verdict(f"{unlisted}.48.01").status, "unknown")

    def test_unlisted_newer_branch_requires_attestation(self) -> None:
        newest = max(int(key) for key in read_minimum("components.nvidiaDriver.branches"))
        verdict = security.nvidia_driver_verdict(f"{newest + 5}.10.02")
        self.assertEqual(verdict.status, "unknown")
        self.assertIn(str(newest + 5), verdict.detail)

    def test_non_nvidia_driver_version_is_never_graded_as_a_pass(self) -> None:
        verdict = security.nvidia_driver_verdict("6.1.2")
        self.assertEqual(verdict.status, "unknown")
        self.assertNotEqual(verdict.status, "pass")
        self.assertIn("does not look like an NVIDIA Linux driver version", verdict.detail)

    def test_implausible_branch_above_the_newest_does_not_reach_the_pass_rule(self) -> None:
        newest = max(int(key) for key in read_minimum("components.nvidiaDriver.branches"))
        self.assertGreater(9999, newest)
        verdict = security.nvidia_driver_verdict("9999.1.1")
        self.assertEqual(verdict.status, "unknown")
        self.assertNotEqual(verdict.status, "pass")

    def test_amd_cluster_with_an_amdgpu_version_string_is_not_applicable(self) -> None:
        result = security.evaluate(
            driver="6.16.13",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            gpu_vendor="amd",
        )
        self.assertEqual(result["nvidiaDriver"]["status"], "not_applicable")
        self.assertEqual(result["nvidiaContainerToolkit"]["status"], "not_applicable")
        self.assertEqual(result["dcgm"]["status"], "not_applicable")
        self.assertEqual(result["dcgmExporter"]["status"], "not_applicable")

    def test_r570_fleet_below_the_newly_tracked_minimum_grades_fail(self) -> None:
        minimum = read_minimum("components.nvidiaDriver.branches.570")
        verdict = security.nvidia_driver_verdict("570.133.20")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, minimum)

class ContainerToolkitPolicyTests(unittest.TestCase):
    def test_minimum_and_cves_come_from_the_generated_table(self) -> None:
        minimum = read_minimum("components.nvidiaContainerToolkit.minimum")
        verdict = security.nvidia_container_toolkit_verdict(minimum)
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.minimum, minimum)
        self.assertEqual(verdict.advisory, read_minimum("components.nvidiaContainerToolkit.advisory"))
        for cve in read_minimum("components.nvidiaContainerToolkit.cves"):
            self.assertIn(cve, verdict.detail)

    def test_retired_1_17_8_minimum_no_longer_passes(self) -> None:
        self.assertEqual(security.nvidia_container_toolkit_verdict("1.17.8").status, "fail")

    def test_debian_epoch_and_revision_do_not_change_the_verdict(self) -> None:
        minimum = read_minimum("components.nvidiaContainerToolkit.minimum")
        self.assertEqual(
            security.nvidia_container_toolkit_verdict(f"{minimum}-1").status, "pass"
        )
        self.assertEqual(
            security.nvidia_container_toolkit_verdict(f"1:{minimum}-1").status, "pass"
        )


class CudaAndDockerPolicyTests(unittest.TestCase):
    def test_cuda_toolkit_minimum_comes_from_the_generated_table(self) -> None:
        minimum = read_minimum("components.cudaToolkit.minimum")
        verdict = security.cuda_toolkit_verdict(minimum)
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.minimum, minimum)
        self.assertEqual(verdict.advisory, read_minimum("components.cudaToolkit.advisory"))

    def test_docker_minimum_comes_from_the_generated_table(self) -> None:
        minimum = read_minimum("components.docker.minimum")
        verdict = security.docker_verdict(minimum)
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.minimum, minimum)
        self.assertEqual(verdict.advisory, read_minimum("components.docker.advisory"))

    def test_docker_release_below_the_published_minimum_fails(self) -> None:
        minimum = read_minimum("components.docker.minimum")
        self.assertEqual(security.docker_verdict(_just_below(minimum)).status, "fail")
        self.assertEqual(security.docker_verdict(f"{minimum}-rc.1").status, "fail")
        self.assertEqual(security.docker_verdict(minimum).status, "pass")
        self.assertEqual(security.docker_verdict(_shift_patch(minimum, 1)).status, "pass")


class DcgmPolicyTests(unittest.TestCase):
    """DCGM and DCGM Exporter, which ship in one image tag under two minimums."""

    def setUp(self) -> None:
        self.dcgm_minimum = read_minimum("components.dcgm.minimum")
        self.exporter_minimum = read_minimum("components.dcgmExporter.minimum")

    def test_each_component_passes_at_its_own_published_minimum(self) -> None:
        dcgm = security.dcgm_verdict(self.dcgm_minimum)
        exporter = security.dcgm_exporter_verdict(self.exporter_minimum)
        self.assertEqual(dcgm.status, "pass")
        self.assertEqual(dcgm.minimum, self.dcgm_minimum)
        self.assertEqual(dcgm.advisory, read_minimum("components.dcgm.advisory"))
        self.assertEqual(exporter.status, "pass")
        self.assertEqual(exporter.minimum, self.exporter_minimum)
        self.assertEqual(exporter.advisory, read_minimum("components.dcgmExporter.advisory"))
        for cve in read_minimum("components.dcgm.cves"):
            self.assertIn(cve, dcgm.detail)

    def test_transposing_the_two_versions_changes_the_verdicts(self) -> None:
        dcgm_minimum = security.numeric_version(self.dcgm_minimum)
        exporter_minimum = security.numeric_version(self.exporter_minimum)
        self.assertLess(
            dcgm_minimum,
            exporter_minimum,
            "the DCGM minimums no longer disagree, so this test cannot detect a transposition",
        )

        discriminator = "4.7.1"
        parsed = security.numeric_version(discriminator)
        self.assertGreaterEqual(parsed, dcgm_minimum)
        self.assertLess(parsed, exporter_minimum)
        self.assertEqual(security.dcgm_verdict(discriminator).status, "pass")
        self.assertEqual(security.dcgm_exporter_verdict(discriminator).status, "fail")

    def test_synthetic_old_versions_fail_for_both_components(self) -> None:
        self.assertEqual(security.dcgm_verdict("1.0.0").status, "fail")
        self.assertEqual(security.dcgm_exporter_verdict("1.0.0").status, "fail")

    def test_package_revision_suffix_does_not_change_the_verdict(self) -> None:
        self.assertEqual(security.dcgm_verdict(f"{self.dcgm_minimum}-1").status, "pass")


class ComponentPresenceTests(unittest.TestCase):
    def test_absent_and_hidden_component_conventions(self) -> None:
        for evaluator, missing_status in (
            (security.cuda_toolkit_verdict, "not_applicable"),
            (security.docker_verdict, "unknown"),
            (security.dcgm_verdict, "unknown"),
            (security.dcgm_exporter_verdict, "unknown"),
        ):
            for reported, expected in (
                ("not-installed", "not_applicable"),
                ("unknown", "unknown"),
                ("not-found", missing_status),
            ):
                with self.subTest(component=evaluator.__name__, reported=reported):
                    self.assertEqual(evaluator(reported).status, expected)


class RuncLadderPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ladder = read_minimum("components.runc.ladder")
        self.branches = sorted(
            tuple(int(part) for part in key.split(".")) for key in self.ladder
        )

    def test_every_ladder_rung_passes_at_its_own_minimum(self) -> None:
        for branch, minimum in self.ladder.items():
            with self.subTest(branch=branch):
                verdict = security.runc_verdict(minimum)
                self.assertEqual(verdict.status, "pass")
                self.assertEqual(verdict.minimum, minimum)

    def test_branch_above_the_ladder_passes(self) -> None:
        major, minor = self.branches[-1]
        self.assertEqual(security.runc_verdict(f"{major}.{minor + 1}.0").status, "pass")

    def test_branch_below_the_ladder_never_received_the_fix(self) -> None:
        major, minor = self.branches[0]
        verdict = security.runc_verdict(f"{major}.{minor - 1}.15")
        self.assertEqual(verdict.status, "fail")
        next_major, next_minor = self.branches[0]
        self.assertEqual(verdict.minimum, self.ladder[f"{next_major}.{next_minor}"])

    def test_a_failing_release_names_only_the_advisories_that_affect_it(self) -> None:
        verdict = security.runc_verdict("1.3.3")
        self.assertEqual(verdict.status, "fail")
        self.assertIn("GHSA-xjvp-4fhw-gc47", verdict.detail)
        self.assertEqual(verdict.minimum, self.ladder["1.3"])
        self.assertIn(self.ladder["1.3"], verdict.detail)
        # Fixed at exactly 1.3.3, so it does not affect 1.3.3.
        self.assertNotIn("GHSA-9493-h29p-rfm2", verdict.detail)
        # Fixed back in the 1.0 series, four branches below this host.
        self.assertNotIn("GHSA-v95c-p5hm-xq8f", verdict.detail)

    def test_each_advisory_names_its_own_fix_not_the_branch_minimum(self) -> None:
        verdict = security.runc_verdict("1.2.7")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, self.ladder["1.2"])
        self.assertIn("GHSA-xjvp-4fhw-gc47 (fixed in 1.3.6)", verdict.detail)
        self.assertIn("GHSA-9493-h29p-rfm2 (fixed in 1.2.8)", verdict.detail)
        self.assertNotIn("GHSA-xjvp-4fhw-gc47 (fixed in 1.2.8)", verdict.detail)

    def test_a_distro_rebuild_suffix_does_not_lift_the_version_above_its_fix(self) -> None:
        verdict = security.runc_verdict("1.3.3-0ubuntu1~22.04.3")
        self.assertEqual(verdict.status, "fail")
        self.assertNotIn("GHSA-9493-h29p-rfm2", verdict.detail)
        self.assertEqual(verdict.minimum, self.ladder["1.3"])
        self.assertIn("GHSA-xjvp-4fhw-gc47", verdict.detail)

    def test_a_passing_release_reports_no_advisory_finding(self) -> None:
        verdict = security.runc_verdict(self.ladder["1.3"])
        self.assertEqual(verdict.status, "pass")
        self.assertNotIn("GHSA-", verdict.detail)
        self.assertIn("Meets", verdict.detail)

    def test_debian_epoch_is_stripped_before_the_ladder_lookup(self) -> None:
        branch = ".".join(str(part) for part in self.branches[1])
        minimum = self.ladder[branch]
        self.assertEqual(security.runc_verdict(f"2:{minimum}-0ubuntu1").status, "pass")

    def test_release_candidate_rule_is_generic_over_the_ladder(self) -> None:
        cases = {
            ("1.9.0-rc.3", "1.9.0-rc.3"): True,
            ("1.9.0-rc.4", "1.9.0-rc.3"): True,
            ("1.9.0", "1.9.0-rc.3"): True,
            ("1.9.1-rc.1", "1.9.0-rc.3"): True,
            ("1.9.0-rc.2", "1.9.0-rc.3"): False,
            ("1.9.0~rc.2", "1.9.0-rc.3"): False,
            ("1.9.3", "1.9.3"): True,
            ("1.9.3-rc.9", "1.9.3"): False,
            ("1.9.2", "1.9.3"): False,
        }
        for (version, rung), expected in cases.items():
            with self.subTest(version=version, minimum=rung):
                self.assertEqual(
                    security._meets_ladder_minimum(
                        version, security.numeric_version(version), rung
                    ),
                    expected,
                )

    def test_prerelease_is_read_through_packaging_punctuation(self) -> None:
        self.assertEqual(security._prerelease("1:1.4.0~rc.2-0ubuntu1"), 2)
        self.assertEqual(security._prerelease("1.4.0-rc3"), 3)
        self.assertIsNone(security._prerelease("runc version 1.4.3"))


class ConnectxFirmwarePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trains = {int(key): int(value) for key, value in read_minimum(
            "components.connectxFirmware.trains"
        ).items()}

    def test_every_published_train_passes_at_its_patch(self) -> None:
        for train, patch in self.trains.items():
            with self.subTest(train=train):
                self.assertEqual(
                    security.connectx_firmware_verdict(f"40.{train}.{patch}").status, "pass"
                )
        with self.subTest(adapter="ConnectX-4"):
            self.assertEqual(
                security.connectx_firmware_verdict(f"12.28.{self.trains[28]}").status,
                "pass",
            )

    def test_a_graded_train_reports_its_own_minimum_as_the_minimum(self) -> None:
        train, patch = sorted(self.trains.items())[0]
        failing = security.connectx_firmware_verdict(f"40.{train}.{patch - 1}")
        self.assertEqual(failing.status, "fail")
        self.assertEqual(failing.minimum, f"{train}.{patch}")
        self.assertIn("Below", failing.detail)
        passing = security.connectx_firmware_verdict(f"40.{train}.{patch}")
        self.assertEqual(passing.minimum, f"{train}.{patch}")
        self.assertIn("Meets", passing.detail)

    def test_ga_range_covers_every_listed_nic_and_dpu_family(self) -> None:
        train = max(self.trains) + 1
        cases = {
            22: "pass", 24: "pass", 26: "pass", 28: "pass", 32: "pass", 40: "pass",
            20: "unknown",
        }
        for family, status in cases.items():
            with self.subTest(family=family):
                verdict = security.connectx_firmware_verdict(f"{family}.{train}.2526")
                self.assertEqual(verdict.status, status)
                if family == 40:
                    self.assertIn("explicit ConnectX-8 GA fixed range", verdict.detail)
                    self.assertIn(str(max(self.trains)), verdict.detail)

    def test_shared_family_needs_every_product_in_the_ga_row(self) -> None:
        component = minimums.component
        block = dict(component("connectxFirmware"))
        block["gaRanges"] = [{
            "product": "ConnectX GA", "architectures": "ConnectX-6 DX",
            "minimum": "46.3008", "relation": "or-newer",
        }]
        with mock.patch.object(
            minimums, "component",
            side_effect=lambda name: block if name == "connectxFirmware" else component(name),
        ):
            verdict = security.connectx_firmware_verdict(f"22.{max(self.trains) + 1}.2526")
        self.assertEqual(verdict.status, "unknown")

    def test_unlisted_train_without_explicit_ga_range_stays_unknown(self) -> None:
        component = minimums.component
        block = dict(component("connectxFirmware"))
        block.pop("gaRanges", None)
        with mock.patch.object(
            minimums, "component",
            side_effect=lambda name: block if name == "connectxFirmware" else component(name),
        ):
            verdict = security.connectx_firmware_verdict(f"40.{max(self.trains) + 1}.2526")
        self.assertEqual(verdict.status, "unknown")

    def test_older_unassessed_train_is_unknown_rather_than_failed(self) -> None:
        train = next(
            candidate
            for candidate in range(max(self.trains) - 1, min(self.trains), -1)
            if candidate not in self.trains
        )
        verdict = security.connectx_firmware_verdict(f"40.{train}.9999")
        self.assertEqual(verdict.status, "unknown")
        self.assertIn(str(train), verdict.detail)

    def test_short_firmware_strings_are_unverified(self) -> None:
        for version in ("46.3007", "35.8001"):
            with self.subTest(version=version):
                self.assertEqual(
                    security.connectx_firmware_verdict(version).status, "unknown"
                )

    def test_aggregate_names_the_failing_device(self) -> None:
        healthy_train, healthy_patch = sorted(self.trains.items())[-1]
        failing_train, failing_patch = sorted(self.trains.items())[0]
        result = security.aggregate_connectx(
            [
                f"mlx5_0=40.{healthy_train}.{healthy_patch}",
                f"mlx5_bond_0=32.{failing_train}.{failing_patch - 1}",
            ],
            inventory_complete=True,
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["devices"][1]["device"], "mlx5_bond_0")
        self.assertEqual(result["devices"][1]["status"], "fail")
        self.assertEqual(result["advisory"], read_minimum("components.connectxFirmware.advisory"))

    def test_passing_devices_require_a_complete_inventory(self) -> None:
        train, patch = sorted(self.trains.items())[-1]
        entries = [f"mlx5_0=40.{train}.{patch}"]
        self.assertEqual(security.aggregate_connectx(entries)["status"], "unknown")
        self.assertEqual(
            security.aggregate_connectx(entries, inventory_complete=True)["status"], "pass"
        )

    def test_complete_non_nvidia_nic_inventory_is_not_applicable(self) -> None:
        result = security.aggregate_connectx([], inventory_complete=True)
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["devices"], [])

    def test_unavailable_nic_inventory_requires_attestation(self) -> None:
        self.assertEqual(
            security.aggregate_connectx([], inventory_complete=False)["status"], "unknown"
        )


class VirtioNetReleaseLineTests(unittest.TestCase):
    """BlueField VIRTIO-Net controller firmware, whose release lines interleave."""

    def setUp(self) -> None:
        self.lines = read_minimum("components.virtioNetBluefield.lines")
        self.fixed = {
            name: spec["fixed"] for name, spec in self.lines.items() if spec.get("fixed")
        }
        self.legacy = {
            name: spec["legacyAffectedThrough"]
            for name, spec in self.lines.items()
            if spec.get("legacyAffectedThrough")
        }

    def shared_prefix_lines(self) -> dict[str, str]:
        """The lines whose fixed versions collide on year.month, GA and the newest LTS."""
        by_prefix: dict[tuple[int, int], dict[str, str]] = {}
        for name, fixed in self.fixed.items():
            prefix = security.numeric_version(fixed, parts=3)[:2]
            by_prefix.setdefault(prefix, {})[name] = fixed
        collisions = [group for group in by_prefix.values() if len(group) > 1]
        self.assertTrue(
            collisions,
            "the interleaving this policy exists for is gone from the minimum table",
        )
        return max(collisions, key=len)

    def test_interleaved_lines_cannot_be_decided_without_the_line(self) -> None:
        group = self.shared_prefix_lines()
        ordered = sorted(group.items(), key=lambda item: security.numeric_version(item[1], parts=3))
        lowest, highest = ordered[0][1], ordered[-1][1]
        between = _shift_patch(lowest, 1)
        self.assertLess(
            security.numeric_version(between, parts=3),
            security.numeric_version(highest, parts=3),
        )
        verdict = security.virtio_net_verdict(between)
        self.assertEqual(verdict.status, "unknown")
        for fixed in group.values():
            self.assertIn(fixed, verdict.detail)

    def test_clearing_every_candidate_line_passes_and_clearing_none_fails(self) -> None:
        group = self.shared_prefix_lines()
        ordered = sorted(group.values(), key=lambda fixed: security.numeric_version(fixed, parts=3))
        self.assertEqual(security.virtio_net_verdict(_shift_patch(ordered[-1], 1)).status, "pass")
        self.assertEqual(security.virtio_net_verdict(_shift_patch(ordered[0], -1)).status, "fail")

    def test_a_named_release_line_decides_the_same_version_both_ways(self) -> None:
        group = self.shared_prefix_lines()
        ordered = sorted(group.items(), key=lambda item: security.numeric_version(item[1], parts=3))
        lower_line, lower_fixed = ordered[0]
        higher_line, higher_fixed = ordered[-1]
        between = _shift_patch(lower_fixed, 1)

        cleared = security.virtio_net_verdict(between, line=lower_line)
        self.assertEqual(cleared.status, "pass")
        self.assertEqual(cleared.minimum, lower_fixed)

        exposed = security.virtio_net_verdict(between, line=higher_line)
        self.assertEqual(exposed.status, "fail")
        self.assertEqual(exposed.minimum, higher_fixed)

    def test_single_line_prefixes_grade_without_the_line(self) -> None:
        group = self.shared_prefix_lines()
        for name, fixed in self.fixed.items():
            if name in group:
                continue
            with self.subTest(line=name):
                self.assertEqual(security.virtio_net_verdict(fixed).status, "pass")
                self.assertEqual(
                    security.virtio_net_verdict(_shift_patch(fixed, -1)).status, "fail"
                )

    def test_retired_scheme_is_failed_through_the_affected_version(self) -> None:
        threshold = max(
            self.legacy.values(), key=lambda value: security.numeric_version(value, parts=3)
        )
        self.assertEqual(security.virtio_net_verdict(threshold).status, "fail")
        self.assertEqual(security.virtio_net_verdict(_shift_patch(threshold, -1)).status, "fail")
        self.assertEqual(security.virtio_net_verdict("1.6.0").status, "fail")

    def test_retired_scheme_above_the_affected_range_is_unknown(self) -> None:
        verdict = security.virtio_net_verdict("1.9.13")
        self.assertEqual(verdict.status, "unknown")
        self.assertIn("release line", verdict.detail)

    def test_unknown_line_name_and_unassessed_version_are_unknown(self) -> None:
        any_fixed = next(iter(self.fixed.values()))
        self.assertEqual(
            security.virtio_net_verdict(any_fixed, line="LTS99").status, "unknown"
        )
        oldest = min(
            security.numeric_version(fixed, parts=3)[0] for fixed in self.fixed.values()
        )
        verdict = security.virtio_net_verdict(f"{oldest - 1}.10.1")
        self.assertEqual(verdict.status, "unknown")
        self.assertIn("not assessed by the current bulletin", verdict.detail)

    def test_absent_controller_and_hidden_version(self) -> None:
        self.assertEqual(
            security.virtio_net_verdict("not-installed").status, "not_applicable"
        )
        self.assertEqual(security.virtio_net_verdict("unknown").status, "unknown")

    def test_verdict_carries_the_advisory_and_cves(self) -> None:
        verdict = security.virtio_net_verdict(
            next(iter(self.fixed.values())), line=next(iter(self.fixed))
        )
        self.assertEqual(verdict.advisory, read_minimum("components.virtioNetBluefield.advisory"))
        for cve in read_minimum("components.virtioNetBluefield.cves"):
            self.assertIn(cve, verdict.detail)


class VirtioNetPlatformModeTests(unittest.TestCase):
    """The BlueField platform mode decides whether the exposure is live or latent."""

    def setUp(self) -> None:
        self.lines = read_minimum("components.virtioNetBluefield.lines")
        self.fixed = {
            name: spec["fixed"] for name, spec in self.lines.items() if spec.get("fixed")
        }
        self.highest = max(
            self.fixed.values(), key=lambda value: security.numeric_version(value, parts=3)
        )

    def test_nic_mode_passes_current_exposure_without_certifying_stored_firmware(
        self,
    ) -> None:
        below = _shift_patch(min(
            self.fixed.values(), key=lambda value: security.numeric_version(value, parts=3)
        ), -1)
        record = security.virtio_net_result(below, mode="nic")

        self.assertEqual(record["status"], "pass")
        self.assertNotEqual(record["status"], "not_applicable")
        self.assertNotEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "none")
        self.assertEqual(record["floorStatus"], "fail")
        self.assertEqual(record["platformMode"], "nic")
        self.assertIs(record["controllerRunning"], False)
        detail = record["detail"]
        self.assertIn("NIC mode", detail)
        self.assertIn("does not certify stored", detail)
        self.assertIn("DPU mode", detail)
        self.assertIn("Reassess", detail)

    def test_nic_mode_with_unreadable_version_passes_current_exposure(self) -> None:
        record = security.virtio_net_result(
            "unknown", mode="nic", version_reason="virtnet is not installed on the host"
        )
        self.assertEqual(record["status"], "pass")
        self.assertEqual(record["exposure"], "none")
        self.assertIn("does not certify stored", record["detail"])
        self.assertEqual(record["versionUnavailableReason"], "not-observed")
        self.assertEqual(record["floorStatus"], "unknown")
        self.assertEqual(
            record["versionUnavailableDetail"], "virtnet is not installed on the host"
        )

    def test_nic_mode_at_the_minimum_passes_and_records_no_exposure(self) -> None:
        record = security.virtio_net_result(self.highest, mode="nic")
        self.assertEqual(record["status"], "pass")
        self.assertEqual(record["exposure"], "none")
        self.assertIn("disables the virtio-net controller", record["detail"])

    def test_patched_idle_firmware_beside_a_gap_is_not_a_latent_exposure(self) -> None:
        gapped = security.virtio_net_result(
            "unknown", worst_version=self.highest, worst_mode="nic", coverage_complete=False
        )
        self.assertEqual(gapped["floorStatus"], "pass")
        self.assertNotEqual(gapped["exposure"], "latent")
        self.assertEqual(gapped["exposure"], "unknown")
        self.assertEqual(gapped["status"], "unknown")

    def test_below_minimum_firmware_is_still_latent_when_idle(self) -> None:
        lowest = min(
            self.fixed.values(), key=lambda value: security.numeric_version(value, parts=3)
        )
        below = _shift_patch(lowest, -1)
        for coverage in (True, False):
            with self.subTest(coverage_complete=coverage):
                record = security.virtio_net_result(
                    "unknown",
                    worst_version=below,
                    worst_mode="nic",
                    coverage_complete=coverage,
                )
                self.assertEqual(record["floorStatus"], "fail")
                self.assertEqual(record["exposure"], "none" if coverage else "latent")

    def test_dpu_mode_below_the_minimum_is_a_live_exposure(self) -> None:
        below = _shift_patch(min(
            self.fixed.values(), key=lambda value: security.numeric_version(value, parts=3)
        ), -1)
        record = security.virtio_net_result(below, mode="dpu")
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "live")
        self.assertIs(record["controllerRunning"], True)

    def test_absent_bluefield_is_not_applicable_with_no_exposure(self) -> None:
        record = security.virtio_net_result("unknown", mode="absent")
        self.assertEqual(record["status"], "not_applicable")
        self.assertEqual(record["exposure"], "none")
        self.assertEqual(record["platformMode"], "absent")

    def test_unreported_mode_preserves_the_running_grade_exactly(self) -> None:
        samples = [
            *self.fixed.values(),
            *(_shift_patch(value, -1) for value in self.fixed.values()),
            "unknown",
            "not-installed",
        ]
        for version in samples:
            for line in (None, *sorted(self.fixed)):
                with self.subTest(version=version, line=line):
                    self.assertEqual(
                        security.virtio_net_verdict(version, line=line, mode=None),
                        security._virtio_running_verdict(version, line=line),
                    )

    def test_unreported_mode_records_an_unknown_platform_and_carries_provenance(self) -> None:
        record = security.virtio_net_result(
            self.highest, mode=None, version_source="virtnet-version"
        )
        self.assertEqual(record["platformMode"], "unknown")
        self.assertIsNone(record["controllerRunning"])
        self.assertEqual(record["versionSource"], "virtnet-version")
        self.assertEqual(record["exposure"], "none")


class VirtioNetFleetCoverageTests(unittest.TestCase):
    """A proven finding on one host survives an unreadable host elsewhere."""

    def setUp(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        fixed = [spec["fixed"] for spec in lines.values() if spec.get("fixed")]
        self.lowest = min(fixed, key=lambda value: security.numeric_version(value, parts=3))
        self.below = _shift_patch(self.lowest, -1)
        self.highest = max(fixed, key=lambda value: security.numeric_version(value, parts=3))

    def test_proven_vulnerable_host_plus_an_unresolved_host_still_fails(self) -> None:
        record = security.virtio_net_result(
            "unknown",
            mode=None,
            worst_version=self.below,
            worst_mode="dpu",
            coverage_complete=False,
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["gradedVersion"], self.below)
        self.assertEqual(record["gradedFrom"], "worst-observed-host")
        self.assertIs(record["coverageComplete"], False)
        self.assertIn("below every release line", record["detail"])
        self.assertIn("confirmed on at least one host", record["detail"])
        self.assertIn("could not be assessed", record["detail"])

    def test_partial_coverage_never_reports_a_clean_fleet_as_pass(self) -> None:
        record = security.virtio_net_result(
            "unknown",
            mode=None,
            worst_version=self.highest,
            worst_mode="dpu",
            coverage_complete=False,
        )
        self.assertNotEqual(record["status"], "pass")
        self.assertEqual(record["status"], "unknown")
        self.assertIn("not cleared", record["detail"])
        self.assertEqual(record["exposure"], "unknown")

    def test_complete_coverage_reproduces_the_single_host_grade_exactly(self) -> None:
        for version, expected in ((self.below, "fail"), (self.highest, "pass")):
            with self.subTest(version=version):
                direct = security.virtio_net_result(version, mode="dpu")
                fleet = security.virtio_net_result(
                    "unknown",
                    mode=None,
                    worst_version=version,
                    worst_mode="dpu",
                    coverage_complete=True,
                )
                self.assertEqual(direct["status"], expected)
                for key in ("status", "detail", "minimum", "exposure", "platformMode"):
                    self.assertEqual(fleet[key], direct[key], key)

    def test_partial_coverage_fail_stays_live_unless_the_mode_says_otherwise(self) -> None:
        exposed = security.virtio_net_result(
            "unknown", worst_version=self.below, worst_mode="dpu", coverage_complete=False
        )
        self.assertEqual(exposed["status"], "fail")
        self.assertEqual(exposed["exposure"], "live")

        idle = security.virtio_net_result(
            "unknown", worst_version=self.below, worst_mode="nic", coverage_complete=False
        )
        self.assertEqual(idle["exposure"], "latent")
        self.assertEqual(idle["status"], "unknown")

    def test_release_line_of_the_observed_host_decides_the_grade(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        by_prefix = {}
        for name, spec in lines.items():
            if spec.get("fixed"):
                by_prefix.setdefault(
                    security.numeric_version(spec["fixed"], parts=3)[:2], {}
                )[name] = spec["fixed"]
        group = max(by_prefix.values(), key=len)
        ordered = sorted(
            group.items(), key=lambda item: security.numeric_version(item[1], parts=3)
        )
        between = _shift_patch(ordered[0][1], 1)
        cleared = security.virtio_net_result(
            "unknown", worst_version=between, worst_line=ordered[0][0], worst_mode="dpu"
        )
        exposed = security.virtio_net_result(
            "unknown", worst_version=between, worst_line=ordered[-1][0], worst_mode="dpu"
        )
        self.assertEqual(cleared["status"], "pass")
        self.assertEqual(cleared["releaseLine"], ordered[0][0])
        self.assertEqual(exposed["status"], "fail")

    def test_incomparable_readings_are_each_graded_and_the_worst_wins(self) -> None:
        threshold = max(
            (
                spec["legacyAffectedThrough"]
                for spec in read_minimum("components.virtioNetBluefield.lines").values()
                if spec.get("legacyAffectedThrough")
            ),
            key=lambda value: security.numeric_version(value, parts=3),
        )
        major, minor, _ = security.numeric_version(threshold, parts=3)
        above_retired = f"{major}.{minor + 1}.0"
        lts24 = read_minimum("components.virtioNetBluefield.lines.LTS24.fixed")
        below_lts24 = _shift_patch(lts24, -1)

        self.assertEqual(security.virtio_net_verdict(above_retired).status, "unknown")
        self.assertEqual(
            security.virtio_net_verdict(below_lts24, line="LTS24").status, "fail"
        )
        self.assertLess(
            security.numeric_version(above_retired, parts=3),
            security.numeric_version(below_lts24, parts=3),
        )

        record = security.virtio_net_result(
            "unknown",
            observed=[
                {"version": above_retired, "line": None, "mode": "dpu", "host": "node-a"},
                {"version": below_lts24, "line": "LTS24", "mode": "dpu", "host": "node-b"},
            ],
            coverage_complete=False,
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["gradedVersion"], below_lts24)
        self.assertEqual(record["gradedHost"], "node-b")
        self.assertEqual(record["observedControllers"], 2)

    def test_no_host_read_a_version_falls_back_to_the_rollup(self) -> None:
        rollup = security.virtio_net_result("unknown", mode="dpu")
        for worst in (None, "", "unknown", "not-observed"):
            with self.subTest(worst=worst):
                fleet = security.virtio_net_result(
                    "unknown", mode="dpu", worst_version=worst, coverage_complete=True
                )
                self.assertEqual(fleet["status"], rollup["status"])
                self.assertEqual(fleet["detail"], rollup["detail"])
                self.assertEqual(fleet["gradedFrom"], "cluster-rollup")

    def test_a_gapped_fleet_with_no_reading_still_names_the_gap(self) -> None:
        covered = security.virtio_net_result("unknown", mode="dpu", coverage_complete=True)
        gapped = security.virtio_net_result("unknown", mode="dpu", coverage_complete=False)

        self.assertEqual(covered["status"], gapped["status"])
        self.assertEqual(covered["status"], "unknown")
        self.assertEqual(covered["minimum"], gapped["minimum"])
        self.assertEqual(covered["exposure"], gapped["exposure"])
        self.assertEqual(gapped["gradedFrom"], "cluster-rollup")

        self.assertNotEqual(covered["detail"], gapped["detail"])
        self.assertTrue(gapped["detail"].startswith(covered["detail"].rstrip(".")))
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, gapped["detail"])
        self.assertIn("At least one host could not be", gapped["detail"])
        self.assertIn("not cleared", gapped["detail"])

    def test_a_fully_assessed_fleet_with_no_reading_is_unchanged(self) -> None:
        for mode in (None, "dpu", "nic", "absent"):
            with self.subTest(mode=mode):
                for version in ("unknown", "not-installed"):
                    plain = security.virtio_net_result(version, mode=mode)
                    covered = security.virtio_net_result(
                        version, mode=mode, coverage_complete=True
                    )
                    self.assertEqual(covered["detail"], plain["detail"])
                    self.assertEqual(covered["status"], plain["status"])

    def test_the_rollup_gap_keeps_a_status_it_cannot_withdraw(self) -> None:
        for label, kwargs in {
            "hidden version": {"version": "unknown", "mode": "dpu"},
            "controller absent": {"version": "not-installed", "mode": "dpu"},
            "no bluefield": {"version": "unknown", "mode": "absent"},
            "idle in nic mode": {"version": "unknown", "mode": "nic"},
        }.items():
            with self.subTest(case=label):
                version = kwargs.pop("version")
                covered = security.virtio_net_result(
                    version, coverage_complete=True, **kwargs
                )
                gapped = security.virtio_net_result(
                    version, coverage_complete=False, **kwargs
                )
                if label == "idle in nic mode":
                    self.assertEqual(covered["status"], "pass")
                    self.assertEqual(gapped["status"], "unknown")
                else:
                    self.assertEqual(covered["status"], gapped["status"])
                    self.assertEqual(covered["exposure"], gapped["exposure"])

    def test_a_gapped_rollup_pass_is_withdrawn_to_unknown(self) -> None:
        covered = security.virtio_net_result(
            self.highest, mode="dpu", coverage_complete=True
        )
        gapped = security.virtio_net_result(
            self.highest, mode="dpu", coverage_complete=False
        )
        self.assertEqual(covered["status"], "pass")
        self.assertEqual(gapped["status"], "unknown")
        self.assertNotEqual(gapped["status"], "pass")
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, gapped["detail"])
        self.assertEqual(gapped["gradedFrom"], "cluster-rollup")
        observed = security.virtio_net_result(
            "unknown",
            worst_version=self.highest,
            worst_mode="dpu",
            coverage_complete=False,
        )
        self.assertEqual(gapped["status"], observed["status"])
        self.assertEqual(gapped["exposure"], observed["exposure"])

    def test_a_fully_assessed_rollup_pass_is_unchanged(self) -> None:
        plain = security.virtio_net_result(self.highest, mode="dpu")
        covered = security.virtio_net_result(
            self.highest, mode="dpu", coverage_complete=True
        )
        self.assertEqual(covered["status"], "pass")
        self.assertEqual(covered["detail"], plain["detail"])
        self.assertEqual(covered["exposure"], plain["exposure"])

    def test_a_proven_fail_on_the_rollup_path_keeps_the_fail_caveat(self) -> None:
        # Reject a below-floor rollup even though collectors normally require full coverage.
        gapped = security.virtio_net_result(
            self.below, mode="dpu", coverage_complete=False
        )
        self.assertEqual(gapped["status"], "fail")
        self.assertIn("confirmed on at least one host", gapped["detail"])


class UnassessedDpuHostEvidenceTests(unittest.TestCase):
    """A below-minimum controller proven idle here may be live on a host we never read."""

    def setUp(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        self.line = "LTS24"
        self.fixed = lines[self.line]["fixed"]
        self.below = _shift_patch(self.fixed, -1)

    def record(self, fleet_mode: str) -> dict:
        return security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net="unknown",
            virtio_net_mode=fleet_mode,
            virtio_net_state="unknown",
            virtio_net_worst=self.below,
            virtio_net_worst_line=self.line,
            virtio_net_worst_mode="nic",
            virtio_net_worst_host="node-a",
        )["virtioNetBluefield"]

    def test_the_fleet_mode_changes_the_evidence_and_never_the_grade(self) -> None:
        exposed_fleet = self.record("dpu")
        idle_fleet = self.record("nic")

        self.assertEqual(exposed_fleet["status"], idle_fleet["status"])
        self.assertEqual(exposed_fleet["exposure"], idle_fleet["exposure"])
        self.assertEqual(exposed_fleet["status"], "unknown")
        self.assertEqual(exposed_fleet["exposure"], "latent")
        self.assertEqual(exposed_fleet["gradedVersion"], idle_fleet["gradedVersion"])
        self.assertEqual(exposed_fleet["minimum"], idle_fleet["minimum"])

        self.assertIs(exposed_fleet["unassessedDpuHostRisk"], True)
        self.assertIs(idle_fleet["unassessedDpuHostRisk"], False)
        self.assertEqual(exposed_fleet["fleetMode"], "dpu")
        self.assertEqual(idle_fleet["fleetMode"], "nic")
        self.assertNotEqual(exposed_fleet["detail"], idle_fleet["detail"])

    def test_the_detail_names_the_unassessed_dpu_host_and_the_next_step(self) -> None:
        detail = self.record("dpu")["detail"]
        self.assertIn("not currently running", detail)
        self.assertIn("DPU mode could not be assessed", detail)
        self.assertIn("actively exposed", detail)
        self.assertIn("attestation", detail)

    def test_the_flag_needs_a_below_minimum_reading_an_idle_host_and_a_gap(self) -> None:
        base = dict(
            worst_version=self.below,
            worst_line=self.line,
            worst_mode="nic",
            coverage_complete=False,
        )
        self.assertIs(
            security.virtio_net_result("unknown", mode="dpu", **base)["unassessedDpuHostRisk"],
            True,
        )
        for label, override in {
            "reading is at the minimum": {"worst_version": self.fixed},
            "graded host is in DPU mode": {"worst_mode": "dpu"},
            "coverage is complete": {"coverage_complete": True},
        }.items():
            with self.subTest(case=label):
                self.assertIs(
                    security.virtio_net_result(
                        "unknown", mode="dpu", **{**base, **override}
                    )["unassessedDpuHostRisk"],
                    False,
                )


class VirtioNetCollectorBindingTests(unittest.TestCase):
    """evaluate() consumes the check's collector_summary() field names."""

    def setUp(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        fixed = [spec["fixed"] for spec in lines.values() if spec.get("fixed")]
        self.lowest = min(fixed, key=lambda value: security.numeric_version(value, parts=3))
        self.highest = max(fixed, key=lambda value: security.numeric_version(value, parts=3))

    def graded(self, **kwargs):
        base = dict(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        return security.evaluate(**base, **kwargs)["virtioNetBluefield"]

    def test_unresolved_rollup_does_not_soften_a_proven_host_failure(self) -> None:
        record = self.graded(
            virtio_net="unknown",
            virtio_net_state="unknown",
            virtio_net_worst=_shift_patch(self.lowest, -1),
            virtio_net_worst_mode="dpu",
            virtio_net_worst_host="node-a",
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "live")
        self.assertEqual(record["gradedHost"], "node-a")
        self.assertIs(record["coverageComplete"], False)

    def test_a_clean_reading_never_clears_an_unresolved_rollup(self) -> None:
        record = self.graded(
            virtio_net="unknown",
            virtio_net_state="incomplete",
            virtio_net_worst=self.highest,
            virtio_net_worst_mode="dpu",
        )
        self.assertNotEqual(record["status"], "pass")
        self.assertEqual(record["status"], "unknown")

    def test_every_state_the_check_settles_counts_as_complete_coverage(self) -> None:
        cleared = self.graded(
            virtio_net="unknown",
            virtio_net_state="version",
            virtio_net_worst=self.highest,
            virtio_net_worst_mode="dpu",
        )
        self.assertIs(cleared["coverageComplete"], True)
        self.assertIs(cleared["everyBluefieldHostRead"], True)
        self.assertEqual(cleared["status"], "pass")
        self.assertNotIn("could not be", cleared["detail"])

        mixed = self.graded(
            virtio_net="unknown",
            virtio_net_state="not_running",
            virtio_net_worst=self.highest,
            virtio_net_worst_mode="dpu",
        )
        self.assertIs(mixed["coverageComplete"], True)
        self.assertIs(mixed["everyBluefieldHostRead"], False)
        self.assertNotEqual(mixed["status"], "pass")
        self.assertEqual(mixed["status"], "unknown")
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, mixed["detail"])

        for state in ("unknown", "incomplete", None):
            with self.subTest(state=state, coverage="gapped"):
                record = self.graded(
                    virtio_net="unknown",
                    virtio_net_state=state,
                    virtio_net_worst=self.highest,
                    virtio_net_worst_mode="dpu",
                )
                self.assertIs(record["coverageComplete"], False)
                self.assertEqual(record["status"], "unknown")
                self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, record["detail"])

    def test_a_fully_scanned_fleet_with_no_bluefield_claims_no_gap(self) -> None:
        record = self.graded(
            virtio_net="not-installed",
            virtio_net_mode="absent",
            virtio_net_state="not_applicable",
        )
        self.assertIs(record["coverageComplete"], True)
        self.assertIs(record["everyBluefieldHostRead"], False)
        self.assertEqual(record["status"], "not_applicable")
        self.assertNotIn("could not be assessed", record["detail"])
        self.assertNotIn(security.COVERAGE_GAP_CLEAN_CAVEAT, record["detail"])

    def test_observed_readings_are_graded_when_no_single_worst_was_nameable(self) -> None:
        record = self.graded(
            virtio_net="unknown",
            virtio_net_state="unknown",
            virtio_net_observed=[
                {"version": self.highest, "line": None, "mode": "dpu", "host": "node-a"},
                {
                    "version": _shift_patch(self.lowest, -1),
                    "line": None,
                    "mode": "dpu",
                    "host": "node-b",
                },
            ],
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["gradedHost"], "node-b")

    def test_empty_worst_observed_falls_through_to_the_reading_list(self) -> None:
        record = self.graded(
            virtio_net="unknown",
            virtio_net_state="unknown",
            virtio_net_worst="",
            virtio_net_worst_mode="unknown",
            virtio_net_worst_host="",
            virtio_net_observed=[
                {
                    "version": _shift_patch(self.lowest, -1),
                    "line": None,
                    "mode": "dpu",
                    "host": "node-b",
                }
            ],
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["gradedHost"], "node-b")

    def test_the_worst_mode_is_graded_as_given_not_re_derived(self) -> None:
        below = _shift_patch(self.lowest, -1)
        record = self.graded(
            virtio_net="unknown",
            virtio_net_state="unknown",
            virtio_net_worst=below,
            virtio_net_worst_mode="dpu",
            virtio_net_worst_host="node-a",
            virtio_net_observed=[
                {"version": below, "line": None, "mode": "nic", "host": "node-a"}
            ],
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "live")
        self.assertEqual(record["platformMode"], "dpu")

    def test_malformed_observed_json_yields_no_readings_rather_than_a_crash(self) -> None:
        self.assertEqual(security._parse_observed_json("{not json"), [])
        self.assertEqual(security._parse_observed_json(None), [])
        self.assertEqual(security._parse_observed_json('{"version": "25.10.1"}'), [])
        self.assertEqual(
            security._parse_observed_json('[{"version": "25.10.1"}, 7]'),
            [{"version": "25.10.1"}],
        )


class VirtioNetRollupReachesTheVerdictTests(unittest.TestCase):
    """The link itself: per-host records -> check rollup -> CLI -> verdict."""

    # audit-common.sh: VIRTIO_NET_SUMMARY_KEYS -> the evaluator's flags. Empty
    # values are omitted there, so they are omitted here.
    COLLECTOR_FLAGS = {
        "virtioNet": "--virtio-net",
        "virtioNetLine": "--virtio-net-line",
        "virtioNetMode": "--virtio-net-mode",
        "virtioNetSource": "--virtio-net-source",
        "virtioNetReason": "--virtio-net-reason",
        "state": "--virtio-net-state",
        "virtioNetWorstObserved": "--virtio-net-worst",
        "virtioNetWorstObservedLine": "--virtio-net-worst-line",
        "virtioNetWorstObservedMode": "--virtio-net-worst-mode",
        "virtioNetWorstObservedHost": "--virtio-net-worst-host",
        "virtioNetObservedJson": "--virtio-net-observed-json",
        "dpuIsolationJson": "--dpu-isolation-json",
    }

    @classmethod
    def setUpClass(cls) -> None:
        path = AUDIT_SCRIPTS / "checks" / "fabric" / "virtio-net-check.py"
        spec = importlib.util.spec_from_file_location("virtio_net_check", path)
        assert spec and spec.loader
        cls.check = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.check)
        cls.line = "LTS24"
        cls.patched = read_minimum(f"components.virtioNetBluefield.lines.{cls.line}.fixed")

    def host(self, **fields):
        """One per-host record, with the check's own state machine deciding it."""
        record = {
            "host": "node",
            "scanComplete": True,
            "bluefield3Present": True,
            "version": None,
            "line": None,
            "versionSource": None,
            "mode": None,
            "rshimHostAccess": {},
            **fields,
        }
        record["state"], record["reason"] = self.check.decide(record)
        return record

    def verdict(self, records):
        """Roll the fleet up and grade it through the evaluator's CLI."""
        summary = self.check.summarize(records)
        collected = self.check.collector_summary(
            {"virtio_net_bluefield": {"summary": summary}}
        )
        argv = ["security_version_audit.py", "--driver", "unknown", "--nct", "unknown",
                "--runc", "unknown"]
        for key, flag in self.COLLECTOR_FLAGS.items():
            value = collected.get(key)
            if value:
                argv.extend([flag, str(value)])
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(stdout):
            security.main()
        return summary, json.loads(stdout.getvalue())["virtioNetBluefield"]

    def test_a_patched_peer_never_clears_a_host_whose_card_went_unread(self) -> None:
        summary, record = self.verdict(
            [
                self.host(
                    host="node-a", mode="dpu", version=self.patched, line=self.line,
                    versionSource="virtnet-version",
                ),
                self.host(host="node-b", mode="nic"),
            ]
        )
        self.assertEqual(summary["state"], "not_running")
        self.assertEqual(record["gradedVersion"], self.patched)
        self.assertEqual(record["floorStatus"], "pass")

        self.assertIs(record["coverageComplete"], True)
        self.assertIs(record["everyBluefieldHostRead"], False)

        self.assertNotEqual(record["status"], "pass")
        self.assertEqual(record["status"], "unknown")
        self.assertNotEqual(record["exposure"], "none")
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, record["detail"])

    def test_an_idle_below_minimum_card_is_not_made_live_by_a_patched_peer(self) -> None:
        below = "24.10.17"
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version=below, line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version=self.patched, line=self.line,
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(summary["worstObserved"], None)
        self.assertNotEqual(record["exposure"], "live")
        self.assertEqual(record["exposure"], "none")
        self.assertEqual(record["status"], "pass")
        self.assertEqual(record["gradedHost"], "node-b")
        self.assertTrue(any(
            row["host"] == "node-a" and row["floorStatus"] == "fail"
            for row in record["storedFirmwareFindings"]
        ))

    def test_a_nic_mode_reading_never_speaks_for_a_fleet_with_a_dpu_host(self) -> None:
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version=self.patched, line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version=self.patched, line=self.line,
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(record["status"], "pass")
        self.assertNotIn("not currently running", record["detail"])
        self.assertEqual(record["gradedHost"], "node-b")

    def test_unknown_running_controller_outranks_idle_firmware_without_losing_evidence(self) -> None:
        below = "24.10.17"
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version=below, line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version="25.10.4",
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(record["gradedHost"], "node-b")
        self.assertEqual(record["floorStatus"], "unknown")
        self.assertEqual(record["exposure"], "unknown")
        self.assertTrue(any(
            row["host"] == "node-a" and row["floorStatus"] == "fail"
            for row in record["storedFirmwareFindings"]
        ))

    def test_a_patched_tie_still_lets_the_running_host_own_the_detail(self) -> None:
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version=self.patched, line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version=self.patched, line=self.line,
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(record["gradedHost"], "node-b")
        self.assertNotIn("not currently running", record["detail"])

    def test_a_lineless_fleet_never_clears_a_below_minimum_peer(self) -> None:
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="dpu", version="23.10.30",
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version="24.10.17",
                          versionSource="virtnet-version"),
            ]
        )
        self.assertIsNone(summary["worstObserved"])
        self.assertEqual(record["status"], "fail")
        self.assertNotEqual(record["status"], "pass")
        self.assertEqual(record["exposure"], "live")

    def test_a_lineless_fleet_that_is_genuinely_clean_still_passes(self) -> None:
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="dpu", version="23.10.30",
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version="24.10.60",
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(record["status"], "pass")
        self.assertEqual(record["exposure"], "none")

    def test_a_running_below_minimum_card_is_still_live(self) -> None:
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version="24.10.17", line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version="24.10.40", line=self.line,
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(summary["worstObserved"], None)
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "live")

    def test_a_fleet_that_read_every_card_is_still_cleared(self) -> None:
        summary, record = self.verdict(
            [
                self.host(
                    host="node-a", mode="dpu", version=self.patched, line=self.line,
                    versionSource="virtnet-version",
                ),
                self.host(host="node-b", bluefield3Present=False),
            ]
        )
        self.assertEqual(summary["state"], "version")
        self.assertIs(record["coverageComplete"], True)
        self.assertIs(record["everyBluefieldHostRead"], True)
        self.assertEqual(record["status"], "pass")
        self.assertNotIn(security.COVERAGE_GAP_CLEAN_CAVEAT, record["detail"])

    def test_a_not_applicable_rollup_can_never_carry_a_reading(self) -> None:
        empty = self.check.summarize(
            [
                self.host(host="node-a", bluefield3Present=False),
                self.host(host="node-b", bluefield3Present=False),
            ]
        )
        self.assertEqual(empty["state"], "not_applicable")
        self.assertEqual(empty["observedControllers"], [])
        self.assertIsNone(empty["worstObserved"])

        reader = self.host(
            host="node-a", mode="dpu", version=self.patched, line=self.line,
            versionSource="virtnet-version",
        )
        for label, peer in {
            "no bluefield": self.host(host="node-b", bluefield3Present=False),
            "nic mode": self.host(host="node-b", mode="nic"),
            "unreadable dpu": self.host(host="node-b", mode="dpu"),
            "scan failed": self.host(
                host="node-b", scanComplete=False, scanError="lspci is not installed"
            ),
        }.items():
            with self.subTest(peer=label):
                summary = self.check.summarize([reader, peer])
                self.assertNotEqual(summary["state"], "not_applicable")
                self.assertEqual(len(summary["observedControllers"]), 1)


class UnreadableVirtioVersionCorrelationTests(unittest.TestCase):
    """Two opposite reasons for the same unknown, told apart from one evaluate()."""

    HARDENED = {
        "scanComplete": True,
        "bluefield3Present": True,
        "rshimHostAccess": {
            "rshimRestricted": True,
            "rshimDeviceNode": False,
            "tmfifoNet0": False,
            "internalCpuRshim": "1",
        },
    }
    OPEN = {
        "scanComplete": True,
        "bluefield3Present": True,
        "rshimHostAccess": {
            "rshimRestricted": False,
            "rshimDeviceNode": True,
            "tmfifoNet0": False,
            "internalCpuRshim": "0",
        },
    }
    UNREADABLE_POSTURE = {"scanComplete": False, "scanError": "lspci is not installed"}

    @staticmethod
    def graded(isolation: dict) -> dict:
        """One evaluate() with an unreadable controller version and this posture."""
        return security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net="unknown",
            virtio_net_mode="dpu",
            dpu_isolation=isolation,
        )

    def test_identical_unknown_is_explained_differently_by_the_dpu_posture(self) -> None:
        hardened = self.graded(self.HARDENED)["virtioNetBluefield"]
        exposed = self.graded(self.OPEN)["virtioNetBluefield"]

        self.assertEqual(hardened["version"], exposed["version"])
        self.assertEqual(hardened["versionUnavailableReason"], "dpu-hardened")
        self.assertEqual(exposed["versionUnavailableReason"], "not-observed")
        self.assertNotEqual(hardened["detail"], exposed["detail"])
        self.assertIn("correctly isolated", hardened["detail"])
        self.assertIn("attestation", hardened["detail"])
        self.assertNotIn("correctly isolated", exposed["detail"])

    def test_the_correlation_never_changes_either_status(self) -> None:
        hardened = self.graded(self.HARDENED)
        exposed = self.graded(self.OPEN)
        self.assertEqual(hardened["virtioNetBluefield"]["status"], "unknown")
        self.assertEqual(exposed["virtioNetBluefield"]["status"], "unknown")
        self.assertEqual(hardened["dpuHostIsolation"]["status"], "pass")
        self.assertEqual(exposed["dpuHostIsolation"]["status"], "fail")

    def test_unknown_posture_is_not_treated_as_hardened(self) -> None:
        record = self.graded(self.UNREADABLE_POSTURE)
        self.assertEqual(record["virtioNetBluefield"]["versionUnavailableReason"], "not-observed")
        self.assertEqual(record["dpuHostIsolation"]["status"], "unknown")

    def test_a_readable_version_carries_no_unavailable_reason(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        highest = max(
            (spec["fixed"] for spec in lines.values() if spec.get("fixed")),
            key=lambda value: security.numeric_version(value, parts=3),
        )
        record = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net=highest,
            virtio_net_mode="dpu",
            virtio_net_state="version",
            dpu_isolation=self.HARDENED,
        )["virtioNetBluefield"]
        self.assertEqual(record["status"], "pass")
        self.assertIsNone(record["versionUnavailableReason"])
        self.assertNotIn("correctly isolated", record["detail"])


class DpuHostIsolationTests(unittest.TestCase):
    """Zero-trust mode: the host must not reach the BlueField control plane."""

    @staticmethod
    def evidence(**rshim) -> dict:
        base = {
            "rshimRestricted": True,
            "rshimDeviceNode": False,
            "tmfifoNet0": False,
            "internalCpuRshim": "1",
        }
        base.update(rshim)
        return {"scanComplete": True, "bluefield3Present": True, "rshimHostAccess": base}

    def test_restricted_rshim_with_no_host_path_passes(self) -> None:
        verdict = security.dpu_host_isolation_verdict(self.evidence())
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.advisory, read_minimum("components.virtioNetBluefield.advisory"))

    def test_each_host_side_path_to_the_dpu_control_plane_fails(self) -> None:
        cases = {
            "rshim device node": {"rshimDeviceNode": True},
            "tmfifo interface": {"tmfifoNet0": True},
            "rshim enabled": {"rshimRestricted": False, "internalCpuRshim": "0"},
        }
        for label, override in cases.items():
            with self.subTest(case=label):
                verdict = security.dpu_host_isolation_verdict(self.evidence(**override))
                self.assertEqual(verdict.status, "fail")
                self.assertIn("zero-trust", verdict.detail)
                self.assertIn("mlxprivhost", verdict.detail)
                self.assertIn("--disable_rshim", verdict.detail)

    def test_a_missing_pci_scan_cannot_erase_a_proven_rshim_path(self) -> None:
        for label, paths in (
            ("device node", {"rshimDeviceNode": True, "tmfifoNet0": False}),
            ("tmfifo interface", {"rshimDeviceNode": False, "tmfifoNet0": True}),
        ):
            with self.subTest(case=label):
                verdict = security.dpu_host_isolation_verdict(
                    {
                        "scanComplete": False,
                        "bluefield3Present": None,
                        "scanError": "lspci not found",
                        "rshimHostAccess": paths,
                    }
                )
                self.assertEqual(verdict.status, "fail")
                self.assertIn("mlxprivhost", verdict.detail)
                self.assertIn("did not complete", verdict.detail)
                self.assertIn("already stands", verdict.detail)

    def test_a_missing_pci_scan_with_no_rshim_path_stays_unknown(self) -> None:
        verdict = security.dpu_host_isolation_verdict(
            {
                "scanComplete": False,
                "bluefield3Present": None,
                "scanError": "lspci not found",
                "rshimHostAccess": {"rshimDeviceNode": False, "tmfifoNet0": False},
            }
        )
        self.assertEqual(verdict.status, "unknown")
        self.assertNotEqual(verdict.status, "pass")

    def test_an_mlxconfig_reading_still_waits_for_the_scan(self) -> None:
        verdict = security.dpu_host_isolation_verdict(
            {
                "scanComplete": False,
                "bluefield3Present": None,
                "scanError": "lspci not found",
                "rshimHostAccess": {
                    "rshimRestricted": False,
                    "rshimDeviceNode": False,
                    "tmfifoNet0": False,
                    "internalCpuRshim": "0",
                },
            }
        )
        self.assertEqual(verdict.status, "unknown")

    def test_no_bluefield_in_a_complete_scan_is_not_applicable(self) -> None:
        verdict = security.dpu_host_isolation_verdict(
            {"scanComplete": True, "bluefield3Present": False}
        )
        self.assertEqual(verdict.status, "not_applicable")

    def test_rootless_evidence_is_unknown_rather_than_a_pass(self) -> None:
        # mlxconfig usually needs root, so a tenant-side run reads no
        # INTERNAL_CPU_RSHIM. Silence is not a clean bill of health.
        verdict = security.dpu_host_isolation_verdict(
            {
                "scanComplete": True,
                "bluefield3Present": True,
                "modeError": "mlxconfig failed: permission denied",
                "rshimHostAccess": {
                    "rshimRestricted": None,
                    "rshimDeviceNode": False,
                    "tmfifoNet0": False,
                    "internalCpuRshim": "unknown",
                },
            }
        )
        self.assertEqual(verdict.status, "unknown")
        self.assertIn("permission denied", verdict.detail)

    def test_incomplete_scan_and_absent_evidence_are_unknown(self) -> None:
        for label, evidence in {
            "no evidence": None,
            "scan failed": {"scanComplete": False, "scanError": "lspci is not installed"},
            "presence unknown": {"scanComplete": True, "bluefield3Present": None},
        }.items():
            with self.subTest(case=label):
                self.assertEqual(
                    security.dpu_host_isolation_verdict(evidence).status, "unknown"
                )

    def test_a_proven_failure_names_the_hosts_that_could_not_be_assessed(self) -> None:
        covered = security.dpu_host_isolation_verdict(self.evidence(rshimDeviceNode=True))
        gapped = security.dpu_host_isolation_verdict(
            {**self.evidence(rshimDeviceNode=True), "unassessedHosts": ["node-b"]}
        )
        self.assertEqual(covered.status, gapped.status)
        self.assertEqual(gapped.status, "fail")
        self.assertEqual(covered.minimum, gapped.minimum)

        self.assertNotEqual(covered.detail, gapped.detail)
        self.assertIn("does not prove usable RShim access or DPU login", gapped.detail)
        self.assertIn("confirmed on at least one host", gapped.detail)
        self.assertIn("could not be assessed", gapped.detail)
        self.assertIn("node-b", gapped.detail)

    def test_a_fully_assessed_fleet_keeps_todays_detail_byte_for_byte(self) -> None:
        base = security.dpu_host_isolation_verdict(self.evidence(rshimDeviceNode=True))
        for label, evidence in {
            "empty list": {**self.evidence(rshimDeviceNode=True), "unassessedHosts": []},
            "key absent": self.evidence(rshimDeviceNode=True),
            "blank names": {
                **self.evidence(rshimDeviceNode=True),
                "unassessedHosts": ["", "   "],
            },
        }.items():
            with self.subTest(case=label):
                self.assertEqual(
                    security.dpu_host_isolation_verdict(evidence).detail, base.detail
                )

    def test_the_caveat_never_moves_a_pass_or_an_unknown(self) -> None:
        for label, evidence in {
            "pass": self.evidence(),
            "unknown": {
                "scanComplete": True,
                "bluefield3Present": True,
                "modeError": "mlxconfig failed: permission denied",
                "rshimHostAccess": {
                    "rshimRestricted": None,
                    "rshimDeviceNode": False,
                    "tmfifoNet0": False,
                    "internalCpuRshim": "unknown",
                },
            },
        }.items():
            with self.subTest(case=label):
                covered = security.dpu_host_isolation_verdict(evidence)
                gapped = security.dpu_host_isolation_verdict(
                    {**evidence, "unassessedHosts": ["node-b"]}
                )
                self.assertEqual(covered.status, gapped.status)
                self.assertEqual(covered.detail, gapped.detail)

    def test_unassessed_hosts_are_echoed_into_the_record(self) -> None:
        record = security.dpu_host_isolation_result(
            {**self.evidence(rshimDeviceNode=True), "unassessedHosts": ["node-c", "node-b"]}
        )
        self.assertEqual(record["unassessedHosts"], ["node-c", "node-b"])
        empty = security.dpu_host_isolation_result(self.evidence())
        self.assertEqual(empty["unassessedHosts"], [])

    def test_result_record_exposes_the_evidence_and_the_remediation(self) -> None:
        record = security.dpu_host_isolation_result(self.evidence(rshimDeviceNode=True))
        self.assertEqual(record["status"], "fail")
        self.assertIs(record["rshimDeviceNode"], True)
        self.assertIs(record["rshimRestricted"], True)
        self.assertEqual(record["internalCpuRshim"], "1")
        self.assertIn("--disable_port_owner", record["remediation"])


class EvaluateTests(unittest.TestCase):
    def test_visible_missing_host_runtimes_are_not_applicable(self) -> None:
        result = security.evaluate(
            driver=newest_driver_minimum(),
            nct="not-installed",
            runc="not-installed",
            docker="not-installed",
            connectx_firmware=[],
        )
        self.assertEqual(result["nvidiaContainerToolkit"]["status"], "not_applicable")
        self.assertEqual(result["docker"]["status"], "not_applicable")
        self.assertEqual(result["runc"]["status"], "not_applicable")

    def test_hidden_host_versions_are_unknown(self) -> None:
        result = security.evaluate(
            driver=newest_driver_minimum(),
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
        )
        self.assertEqual(result["nvidiaDriver"]["status"], "pass")
        self.assertEqual(result["nvidiaContainerToolkit"]["status"], "unknown")
        self.assertEqual(result["runc"]["status"], "unknown")
        self.assertEqual(result["connectxFirmware"]["status"], "unknown")

    def test_nvidia_checks_are_not_applicable_to_amd_cluster(self) -> None:
        result = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc=sorted(read_minimum("components.runc.ladder").values())[-1],
            connectx_firmware=[],
            gpu_vendor="amd",
        )
        self.assertEqual(result["nvidiaDriver"]["status"], "not_applicable")
        self.assertEqual(result["nvidiaContainerToolkit"]["status"], "not_applicable")
        self.assertEqual(result["runc"]["status"], "pass")

    def test_virtio_net_defaults_to_unknown_and_accepts_a_release_line(self) -> None:
        baseline = security.evaluate(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        self.assertEqual(baseline["virtioNetBluefield"]["status"], "unknown")

        line, spec = next(iter(sorted(read_minimum("components.virtioNetBluefield.lines").items())))
        graded = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net=spec["fixed"],
            virtio_net_line=line,
            virtio_net_state="version",
        )
        self.assertEqual(graded["virtioNetBluefield"]["status"], "pass")
        self.assertEqual(graded["virtioNetBluefield"]["minimum"], spec["fixed"])

        unstated = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net=spec["fixed"],
            virtio_net_line=line,
        )
        self.assertEqual(unstated["virtioNetBluefield"]["status"], "unknown")

    def test_dpu_host_isolation_defaults_to_unknown_and_accepts_check_evidence(self) -> None:
        baseline = security.evaluate(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        self.assertEqual(baseline["dpuHostIsolation"]["status"], "unknown")

        graded = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            dpu_isolation={
                "scanComplete": True,
                "bluefield3Present": True,
                "rshimHostAccess": {
                    "rshimRestricted": False,
                    "rshimDeviceNode": True,
                    "tmfifoNet0": False,
                    "internalCpuRshim": "0",
                },
            },
        )
        self.assertEqual(graded["dpuHostIsolation"]["status"], "fail")
        self.assertIs(graded["dpuHostIsolation"]["rshimDeviceNode"], True)

    def test_virtio_mode_reaches_the_values_record(self) -> None:
        lines = read_minimum("components.virtioNetBluefield.lines")
        lowest = min(
            (spec["fixed"] for spec in lines.values() if spec.get("fixed")),
            key=lambda value: security.numeric_version(value, parts=3),
        )
        result = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            virtio_net=_shift_patch(lowest, -1),
            virtio_net_mode="nic",
        )
        self.assertEqual(result["virtioNetBluefield"]["exposure"], "latent")
        self.assertEqual(result["virtioNetBluefield"]["platformMode"], "nic")

    def test_dcgm_pair_defaults_to_unknown_and_grades_the_supplied_versions(self) -> None:
        baseline = security.evaluate(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        self.assertEqual(baseline["dcgm"]["status"], "unknown")
        self.assertEqual(baseline["dcgmExporter"]["status"], "unknown")

        graded = security.evaluate(
            driver="unknown",
            nct="unknown",
            runc="unknown",
            connectx_firmware=[],
            dcgm=read_minimum("components.dcgm.minimum"),
            dcgm_exporter=read_minimum("components.dcgmExporter.minimum"),
        )
        self.assertEqual(graded["dcgm"]["status"], "pass")
        self.assertEqual(graded["dcgmExporter"]["status"], "pass")
        self.assertEqual(graded["dcgm"]["minimum"], read_minimum("components.dcgm.minimum"))
        self.assertEqual(
            graded["dcgmExporter"]["minimum"], read_minimum("components.dcgmExporter.minimum")
        )

    def test_result_carries_the_minimum_table_provenance(self) -> None:
        result = security.evaluate(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        metadata = result["floorsMetadata"]
        self.assertEqual(metadata["schemaVersion"], minimums.load()["schemaVersion"])
        self.assertEqual(metadata["generated"], minimums.load()["generated"])
        self.assertEqual(metadata["maxAgeDays"], minimums.max_age_days())
        self.assertIn("stale", metadata)
        self.assertEqual(
            metadata["sources"]["nvidiaDriver"], read_minimum("components.nvidiaDriver.source")
        )


class MissingMinimumTableTests(unittest.TestCase):
    """A table the audit cannot read must never grade a host as clean."""

    def test_every_check_reports_unknown_and_names_the_missing_table(self) -> None:
        with unreadable_minimum_table():
            result = security.evaluate(
                driver="580.159.03",
                nct="1.19.1",
                runc="1.4.3",
                docker="29.4.3",
                cuda="13.1",
                connectx_firmware=["mlx5_0=40.46.3008"],
                connectx_inventory_complete=True,
                virtio_net="25.10.6",
                virtio_net_line="GA",
                dcgm="4.5.3",
                dcgm_exporter="4.8.2",
            )
        for component in (
            "nvidiaDriver",
            "nvidiaContainerToolkit",
            "cudaToolkit",
            "docker",
            "runc",
            "connectxFirmware",
            "virtioNetBluefield",
            "dcgm",
            "dcgmExporter",
        ):
            with self.subTest(component=component):
                self.assertEqual(result[component]["status"], "unknown")
        self.assertIn(
            "minimum-versions.json", result["nvidiaDriver"]["detail"]
        )
        self.assertIn("minimum-versions.json", result["floorsMetadata"]["error"])

    def test_missing_table_does_not_pass_a_vulnerable_host(self) -> None:
        with unreadable_minimum_table():
            verdict = security.nvidia_container_toolkit_verdict("1.0.0")
        self.assertEqual(verdict.status, "unknown")


class GpuAbsentDriverPolicyTests(unittest.TestCase):
    """A completed scan that found no NVIDIA GPU ends the driver's scope."""

    def evaluate_driver(self, **kwargs) -> dict:
        base = dict(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[]
        )
        base.update(kwargs)
        return security.evaluate(**base)["nvidiaDriver"]

    def test_positive_absence_with_no_readable_driver_is_not_applicable(self) -> None:
        record = self.evaluate_driver(nvidia_gpu_present=False)
        self.assertEqual(record["status"], "not_applicable")
        self.assertEqual(record["version"], "not-present")
        self.assertIn("No NVIDIA GPU is present", record["detail"])

    def test_a_readable_driver_version_outranks_the_absence_claim(self) -> None:
        # A wrong "absent" must never mask a below-minimum driver: the version
        # reading is direct evidence an NVIDIA stack is deployed.
        record = self.evaluate_driver(
            driver="580.126.09", nvidia_gpu_present=False
        )
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["version"], "580.126.09")

    def test_no_claim_keeps_the_unknown_and_attest_behavior(self) -> None:
        # None is "the collector said nothing", which includes every fleet
        # where any host could not read its bus.
        record = self.evaluate_driver(nvidia_gpu_present=None)
        self.assertEqual(record["status"], "unknown")

    def test_the_cli_flag_reaches_the_evaluator(self) -> None:
        argv = ["security_version_audit.py", "--nvidia-gpu-absent"]
        buffer = io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(buffer):
            security.main()
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["nvidiaDriver"]["status"], "not_applicable")

    def test_without_the_flag_the_cli_stays_unknown(self) -> None:
        argv = ["security_version_audit.py"]
        buffer = io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(buffer):
            security.main()
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["nvidiaDriver"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
