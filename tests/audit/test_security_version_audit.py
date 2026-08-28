#!/usr/bin/env python3
"""Tests for advisory-backed container-host security version policy.

The policy holds no minimum of its own: every minimum, branch, ladder rung, and
firmware train comes from the generated `minimum-versions.json`. These tests
therefore read the minimums they need from that table through the same reader the
policy uses. A test that restated a minimum here would pass against a stale
policy and hide exactly the drift the generated table exists to prevent.

`test_minimum_versions.py` owns the table contract itself, including the
generated self-test that replays every published minimum (and the release below
it) through these evaluators and the bulletin grace window. This file owns the
underlying grading semantics after that window: not-installed, unknown,
package-epoch handling, branch and train coverage, aggregation, provenance,
and the degraded path when the table cannot be read.
"""

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


def read_minimum(dotted: str):
    """Read one published minimum, so a test cannot drift from the table."""
    value = minimums.get(dotted)
    assert value is not None, f"minimum version table has no {dotted}"
    return value


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
    def test_runpod_driver_is_below_its_branch_minimum_version(self) -> None:
        # Observed on runpod-b300 (2026-07-19): an R580 host one point release
        # behind the branch minimum.
        verdict = security.nvidia_driver_verdict("580.126.09")
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

    def test_branch_newer_than_the_bulletin_passes_with_a_re_verify_caveat(self) -> None:
        newest = max(int(key) for key in read_minimum("components.nvidiaDriver.branches"))
        verdict = security.nvidia_driver_verdict(f"{newest + 5}.10.02")
        self.assertEqual(verdict.status, "pass")
        self.assertIn(str(newest), verdict.minimum)

    def test_non_nvidia_driver_version_is_never_graded_as_a_pass(self) -> None:
        """The amdgpu value that reached the driver check ungated.

        oracle-mi355x reports amdgpu 6.16.13 in the deliberately vendor-neutral
        gpus.driverVersion field. The gpu_vendor gate catches it, and this is
        the second line: branch 6 is outside any NVIDIA branch, so the verdict
        is unknown. Before the domain guard, a foreign value only avoided a
        pass by being numerically below the tracked branches.
        """
        verdict = security.nvidia_driver_verdict("6.16.13")
        self.assertEqual(verdict.status, "unknown")
        self.assertNotEqual(verdict.status, "pass")
        self.assertIn("does not look like an NVIDIA Linux driver version", verdict.detail)

    def test_implausible_branch_above_the_newest_does_not_reach_the_pass_rule(self) -> None:
        # The dangerous direction: a first component larger than every tracked
        # branch would otherwise take the newer-than-newest pass.
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
        """What tracking a second bulletin buys: a finding that was invisible.

        570.133.20 is an observed committed version, not a minimum, so it stays a
        literal. While R570 carried no published minimum it graded ``unknown``.
        The max-across-bulletins policy pulls the a_id 5747 minimum into the
        table, and the same hosts now grade as the failures they are.
        """
        minimum = read_minimum("components.nvidiaDriver.branches.570")
        verdict = security.nvidia_driver_verdict("570.133.20")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, minimum)

    def test_r590_fleet_at_the_newly_tracked_minimum_grades_pass(self) -> None:
        minimum = read_minimum("components.nvidiaDriver.branches.590")
        verdict = security.nvidia_driver_verdict(minimum)
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.minimum, minimum)

    def test_observed_r610_fleet_stays_above_every_tracked_branch(self) -> None:
        # 610.43.02 is the most common driver in committed runs. It is an
        # observed version, not a minimum, so it stays a literal. It must keep the
        # newer-than-newest pass with its caveat: regressing it to unknown would
        # move a large share of qualified clusters to "requires attestation"
        # with no new evidence.
        newest = max(int(key) for key in read_minimum("components.nvidiaDriver.branches"))
        self.assertGreater(
            610,
            newest,
            "R610 is now assessed by the bulletin table, so this sample no longer "
            "exercises the newer-than-newest path",
        )
        verdict = security.nvidia_driver_verdict("610.43.02")
        # A clean pass, not a provisional one. The audit grades against
        # published minimums, and no minimum exists for this branch yet, so there is
        # nothing for an operator to act on. The daily refresh regrades the same
        # reading once a minimum is published, so the detail must not ask a reader
        # to re-verify by hand.
        self.assertEqual(verdict.status, "pass")
        self.assertNotIn("re-verify", verdict.detail)
        self.assertIn(str(newest), verdict.detail)


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
        # NVIDIA bulletin a_id 5850 (June 2026, CVE-2026-24260) moved the minimum
        # above the 1.17.8 line the policy used to hardcode.
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

    def test_absent_cuda_toolkit_is_not_applicable(self) -> None:
        for reported in ("not-installed", "not-found"):
            with self.subTest(reported=reported):
                self.assertEqual(
                    security.cuda_toolkit_verdict(reported).status, "not_applicable"
                )

    def test_docker_minimum_comes_from_the_generated_table(self) -> None:
        minimum = read_minimum("components.docker.minimum")
        verdict = security.docker_verdict(minimum)
        self.assertEqual(verdict.status, "pass")
        self.assertEqual(verdict.minimum, minimum)
        self.assertEqual(verdict.advisory, read_minimum("components.docker.advisory"))

    def test_docker_release_before_cve_2026_17106_fix_fails(self) -> None:
        self.assertEqual(read_minimum("components.docker.minimum"), "29.7.0")
        self.assertEqual(security.docker_verdict("29.6.2").status, "fail")
        self.assertEqual(security.docker_verdict("29.7.0-rc.1").status, "fail")
        self.assertEqual(security.docker_verdict("29.7.2").status, "pass")


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
        """The integration risk: the image tag carries both versions, 4.x each.

        Tag 4.4.2-4.7.1-ubuntu22.04 means DCGM 4.4.2 and exporter 4.7.1. Two
        independent per-component tests would pass even if the collector handed
        them over swapped, so this grades one version that the two minimums
        disagree about. A transposition therefore changes a status instead of
        going unnoticed.
        """
        dcgm_minimum = security.numeric_version(self.dcgm_minimum)
        exporter_minimum = security.numeric_version(self.exporter_minimum)
        self.assertLess(
            dcgm_minimum,
            exporter_minimum,
            "the DCGM minimums no longer disagree, so this test cannot detect a transposition",
        )

        # 4.7.1 is the exporter version from the real tag, and it sits inside
        # the window where the two minimums disagree.
        discriminator = "4.7.1"
        parsed = security.numeric_version(discriminator)
        self.assertGreaterEqual(parsed, dcgm_minimum)
        self.assertLess(parsed, exporter_minimum)
        self.assertEqual(security.dcgm_verdict(discriminator).status, "pass")
        self.assertEqual(security.dcgm_exporter_verdict(discriminator).status, "fail")

    def test_audited_cluster_tag_grades_both_components_as_failed(self) -> None:
        # Observed on an already-audited cluster: dcgm-exporter image tag
        # 4.4.2-4.7.1-ubuntu22.04, so DCGM 4.4.2 and exporter 4.7.1.
        self.assertEqual(security.dcgm_verdict("4.4.2").status, "fail")
        self.assertEqual(security.dcgm_exporter_verdict("4.7.1").status, "fail")

    def test_absent_and_hidden_dcgm_follow_the_module_conventions(self) -> None:
        for verdict in (security.dcgm_verdict, security.dcgm_exporter_verdict):
            with self.subTest(verdict=verdict.__name__):
                self.assertEqual(verdict("not-installed").status, "not_applicable")
                self.assertEqual(verdict("unknown").status, "unknown")
                self.assertEqual(verdict("not-found").status, "unknown")

    def test_package_revision_suffix_does_not_change_the_verdict(self) -> None:
        self.assertEqual(security.dcgm_verdict(f"{self.dcgm_minimum}-1").status, "pass")

    def test_the_detail_states_which_side_of_the_minimum_the_host_is_on(self) -> None:
        # A bare CVE list read the same on a pass as on a fail, so a passing
        # host looked like it carried an open advisory.
        self.assertIn("Meets", security.dcgm_verdict(self.dcgm_minimum).detail)
        self.assertIn("Below", security.dcgm_verdict("4.0.0").detail)
        self.assertIn(
            "Meets", security.dcgm_exporter_verdict(self.exporter_minimum).detail
        )
        self.assertIn("Below", security.dcgm_exporter_verdict("4.0.0").detail)


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

    def test_failed_release_reports_only_its_branch_minimum(self) -> None:
        branch = "1.3"
        verdict = security.runc_verdict("1.3.3-0ubuntu1~22.04.3")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, self.ladder[branch])

    def test_unknown_release_lists_newest_branches_first(self) -> None:
        expected = " or ".join(
            self.ladder[".".join(str(part) for part in branch)]
            for branch in reversed(self.branches)
        )
        self.assertEqual(security.runc_verdict("unknown").minimum, expected)

    def test_branch_above_the_ladder_passes(self) -> None:
        major, minor = self.branches[-1]
        self.assertEqual(security.runc_verdict(f"{major}.{minor + 1}.0").status, "pass")

    def test_branch_below_the_ladder_never_received_the_fix(self) -> None:
        major, minor = self.branches[0]
        verdict = security.runc_verdict(f"{major}.{minor - 1}.15")
        self.assertEqual(verdict.status, "fail")
        # The way out of an unmaintained branch is the nearest maintained one
        # above it, so the minimum names that branch's minimum, not the whole
        # ladder. For a branch just below the ladder that is the lowest rung.
        next_major, next_minor = self.branches[0]
        self.assertEqual(verdict.minimum, self.ladder[f"{next_major}.{next_minor}"])

    def test_a_failing_release_reports_its_own_branch_minimum_as_the_minimum(self) -> None:
        # "observed 1.3.3, minimum 0.1.0 or 1.0.3 or ... or 1.5.0-rc.3" asked
        # the provider to decode the ladder. The minimum is the one release
        # that clears the observed branch.
        verdict = security.runc_verdict("1.3.3")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, self.ladder["1.3"])

    def test_unknown_release_lists_newest_branches_first(self) -> None:
        expected = " or ".join(
            self.ladder[".".join(str(part) for part in branch)]
            for branch in reversed(self.branches)
        )
        self.assertEqual(security.runc_verdict("unknown").minimum, expected)

    def test_a_failing_release_names_only_the_advisories_that_affect_it(self) -> None:
        # runc 1.3.3 already carries the fixes for every advisory patched at
        # or below 1.3.3. The audit graded it correctly but reported all
        # seventeen advisories in the component's history, which buried the
        # single applicable one and read as a broken check.
        verdict = security.runc_verdict("1.3.3")
        self.assertEqual(verdict.status, "fail")
        self.assertIn("GHSA-xjvp-4fhw-gc47", verdict.detail)
        self.assertIn(self.ladder["1.3"], verdict.detail)
        # Fixed at exactly 1.3.3, so it does not affect 1.3.3.
        self.assertNotIn("GHSA-9493-h29p-rfm2", verdict.detail)
        # Fixed back in the 1.0 series, four branches below this host.
        self.assertNotIn("GHSA-v95c-p5hm-xq8f", verdict.detail)

    def test_each_advisory_names_its_own_fix_not_the_branch_minimum(self) -> None:
        # GHSA-xjvp-4fhw-gc47 affects everything below 1.3.6, so it holds a
        # 1.2.7 host too, and the 1.2.8 branch minimum does not resolve it.
        # Claiming "fixed in 1.2.8" for it would tell a provider they are
        # clear while they stay exposed.
        verdict = security.runc_verdict("1.2.7")
        self.assertEqual(verdict.status, "fail")
        self.assertEqual(verdict.minimum, self.ladder["1.2"])
        self.assertIn("GHSA-xjvp-4fhw-gc47 (fixed in 1.3.6)", verdict.detail)
        self.assertIn("GHSA-9493-h29p-rfm2 (fixed in 1.2.8)", verdict.detail)
        self.assertNotIn("GHSA-xjvp-4fhw-gc47 (fixed in 1.2.8)", verdict.detail)

    def test_a_distro_rebuild_suffix_does_not_lift_the_version_above_its_fix(self) -> None:
        # 1.3.3-0ubuntu1~22.04.3 is a rebuild of 1.3.3, not a release above
        # it. Reading the suffix digits as version parts would re-apply the
        # advisories 1.3.3 already fixed.
        verdict = security.runc_verdict("1.3.3-0ubuntu1~22.04.3")
        self.assertEqual(verdict.status, "fail")
        self.assertNotIn("GHSA-9493-h29p-rfm2", verdict.detail)
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
        # A candidate minimum is cleared by a later candidate or by the stable
        # release of the same patch. A stable minimum is not cleared by any
        # candidate of that patch.
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

    def test_a_graded_train_reports_its_own_minimum_as_the_minimum(self) -> None:
        # Listing every train's minimum asked a reader to work out which one
        # applied to their card. A graded verdict names its train's minimum.
        train, patch = sorted(self.trains.items())[0]
        failing = security.connectx_firmware_verdict(f"40.{train}.{patch - 1}")
        self.assertEqual(failing.status, "fail")
        self.assertEqual(failing.minimum, f"{train}.{patch}")
        self.assertIn("Below", failing.detail)
        passing = security.connectx_firmware_verdict(f"40.{train}.{patch}")
        self.assertEqual(passing.minimum, f"{train}.{patch}")
        self.assertIn("Meets", passing.detail)

    def test_patched_connectx4_firmware_is_not_graded_as_a_fail(self) -> None:
        # 12.28.4702 is a patched ConnectX-4 image. The retired policy compared
        # every unlisted train against the GA train and reported it as failed.
        verdict = security.connectx_firmware_verdict("12.28.4702")
        self.assertEqual(verdict.status, "pass")

    def test_train_newer_than_the_bulletin_passes_with_a_re_verify_caveat(self) -> None:
        # Deployed ConnectX-8 firmware (40.47.2526) runs one train ahead of the
        # bulletin table. Grading it unknown would move already-qualified
        # fleets to "requires host attestation" with no new evidence.
        train = max(self.trains) + 1
        verdict = security.connectx_firmware_verdict(f"40.{train}.2526")
        # A clean pass, for the same reason as the driver branch above: no
        # published minimum covers this train, so the detail states that and does
        # not ask a reader to re-verify by hand.
        self.assertEqual(verdict.status, "pass")
        self.assertNotIn("re-verify", verdict.detail)
        self.assertIn(str(max(self.trains)), verdict.minimum)

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
        # NVIDIA documents shipping controllers at v1.6.x, below the affected
        # range the bulletin names.
        self.assertEqual(security.virtio_net_verdict("1.6.0").status, "fail")

    def test_retired_scheme_above_the_affected_range_is_unknown(self) -> None:
        # Real controllers report v1.9.x. The bulletin publishes no minimum for
        # the retired scheme above its affected range, so claiming those are
        # patched would be a false pass.
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

    def test_nic_mode_below_the_minimum_is_a_latent_exposure_not_a_silent_not_applicable(
        self,
    ) -> None:
        """The regression the user asked for.

        A BlueField in NIC mode runs no virtio-net controller, so there is no
        exposure today. The unpatched firmware is still on the card and the mode
        is an mlxconfig setting, so reporting not_applicable would hide a real
        finding and reporting fail would inflate it into a live one.
        """
        below = _shift_patch(min(
            self.fixed.values(), key=lambda value: security.numeric_version(value, parts=3)
        ), -1)
        record = security.virtio_net_result(below, mode="nic")

        self.assertEqual(record["status"], "unknown")
        self.assertNotEqual(record["status"], "not_applicable")
        self.assertNotEqual(record["status"], "fail")
        self.assertEqual(record["exposure"], "latent")
        self.assertEqual(record["platformMode"], "nic")
        self.assertIs(record["controllerRunning"], False)
        detail = record["detail"]
        self.assertIn("NIC mode", detail)
        self.assertIn("latent", detail)
        self.assertIn("DPU mode", detail)
        self.assertIn("no firmware update", detail)

    def test_nic_mode_with_an_unreadable_version_is_also_latent(self) -> None:
        record = security.virtio_net_result(
            "unknown", mode="nic", version_reason="virtnet is not installed on the host"
        )
        self.assertEqual(record["status"], "unknown")
        self.assertEqual(record["exposure"], "latent")
        self.assertIn("could not be read", record["detail"])
        self.assertEqual(record["versionUnavailableReason"], "not-observed")
        self.assertEqual(
            record["versionUnavailableDetail"], "virtnet is not installed on the host"
        )

    def test_nic_mode_at_the_minimum_passes_and_records_no_exposure(self) -> None:
        record = security.virtio_net_result(self.highest, mode="nic")
        self.assertEqual(record["status"], "pass")
        self.assertEqual(record["exposure"], "none")
        self.assertIn("not currently running", record["detail"])

    def test_patched_idle_firmware_beside_a_gap_is_not_a_latent_exposure(self) -> None:
        """FINDING 1: exposure was read off the post-coverage status.

        A patched NIC-mode reading beside an unread peer has its pass withdrawn
        to unknown by the coverage rule. Deriving exposure from that status
        reported "latent", which asserts there is something a mode change would
        activate, for firmware the audit read and proved patched. Exposure
        describes the firmware; coverage is a separate field.
        """
        gapped = security.virtio_net_result(
            "unknown", worst_version=self.highest, worst_mode="nic", coverage_complete=False
        )
        self.assertEqual(gapped["floorStatus"], "pass")
        self.assertNotEqual(gapped["exposure"], "latent")
        self.assertEqual(gapped["exposure"], "unknown")
        # The withdrawal itself is unchanged: a partial clean is still not a pass.
        self.assertEqual(gapped["status"], "unknown")

    def test_below_minimum_firmware_is_still_latent_when_idle(self) -> None:
        """The state the latent report exists for must survive the fix."""
        # Below every release line, so the minimum grade is unambiguous. A
        # version inside the interleaved window grades unknown by design and
        # would not exercise the proven-below-minimum path.
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
                self.assertEqual(record["exposure"], "latent")

    def test_an_unread_version_on_an_idle_card_stays_latent(self) -> None:
        record = security.virtio_net_result("unknown", mode="nic")
        self.assertEqual(record["floorStatus"], "unknown")
        self.assertEqual(record["exposure"], "latent")

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
    """A proven finding on one host survives an unreadable host elsewhere.

    The check rolls a fleet up to one state and ranks an unresolved host above
    a host whose version was read. Grading that rollup would let node B being
    unreadable soften a below-minimum controller proven on node A, turning a
    critical into a warning. So the worst observed version is graded whenever
    any host produced one, and the rollup only decides whether coverage was
    complete.
    """

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
        # The detail carries both halves: the finding and the coverage gap.
        self.assertIn("below every release line", record["detail"])
        self.assertIn("confirmed on at least one host", record["detail"])
        self.assertIn("could not be assessed", record["detail"])

    def test_partial_coverage_never_reports_a_clean_fleet_as_pass(self) -> None:
        """The asymmetry. An unexamined host can run a vulnerable controller."""
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
        """Both directions, so the existing behavior is provably untouched."""
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

        # NIC mode is the documented exception: nothing runs, so the same
        # firmware is a latent exposure rather than a live one.
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
        """The check leaves worstObserved empty when readings cannot be ordered.

        A bare numeric minimum picks the milder finding across schemes: the
        retired-scheme reading is the lower number yet only grades unknown,
        while the calendar reading is below its line minimum and grades fail.
        Grading every reading and taking the worst verdict needs no ordering.
        """
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

        # The retired reading really is the milder verdict and the lower number.
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
        """Both calls are at complete coverage, which is the point.

        This test originally compared a `coverage_complete=False` call against a
        fully covered one and asserted the details were equal, which encoded the
        very defect it was meant to guard: the gapped path was silently dropping
        the coverage caveat, and the test called that agreement.
        """
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
        """The common shape: reading a controller version needs a route to the DPU.

        No host produced one, so the verdict comes from the rollup. The operator
        still has to see that part of the fleet went unassessed, the same way
        every graded path says it.
        """
        covered = security.virtio_net_result("unknown", mode="dpu", coverage_complete=True)
        gapped = security.virtio_net_result("unknown", mode="dpu", coverage_complete=False)

        # The grade is identical. Only the evidence differs.
        self.assertEqual(covered["status"], gapped["status"])
        self.assertEqual(covered["status"], "unknown")
        self.assertEqual(covered["minimum"], gapped["minimum"])
        self.assertEqual(covered["exposure"], gapped["exposure"])
        self.assertEqual(gapped["gradedFrom"], "cluster-rollup")

        self.assertNotEqual(covered["detail"], gapped["detail"])
        self.assertTrue(gapped["detail"].startswith(covered["detail"].rstrip(".")))
        # The exact wording _apply_partial_coverage uses, so a report reads the
        # same whichever path produced the gap.
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, gapped["detail"])
        self.assertIn("At least one host could not be", gapped["detail"])
        self.assertIn("not cleared", gapped["detail"])

    def test_a_fully_assessed_fleet_with_no_reading_is_unchanged(self) -> None:
        """Nothing moves for a fleet that was fully covered."""
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
        """The sameness half, for the outcomes a gap may not weaken.

        A clean rollup answer IS withdrawn under a gap; that case is covered by
        test_a_gapped_rollup_pass_is_withdrawn_to_unknown. These are the rest:
        an unknown is already the weakest answer, and a not_applicable is a
        fleet-wide claim the check withdraws upstream when coverage is partial.
        """
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
                self.assertEqual(covered["status"], gapped["status"])
                self.assertEqual(covered["exposure"], gapped["exposure"])

    def test_a_gapped_rollup_pass_is_withdrawn_to_unknown(self) -> None:
        """A clean answer speaks only for the hosts that answered.

        Same rule as the observed path. A pass whose own detail says the cluster
        is not cleared is not a defensible verdict, so the gap withdraws the
        pass rather than sitting beside it.
        """
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

    def test_both_paths_withdraw_a_clean_answer_the_same_way(self) -> None:
        """The symmetry itself: same version, same gap, same outcome."""
        rollup = security.virtio_net_result(
            self.highest, mode="dpu", coverage_complete=False
        )
        observed = security.virtio_net_result(
            "unknown",
            worst_version=self.highest,
            worst_mode="dpu",
            coverage_complete=False,
        )
        self.assertEqual(rollup["status"], observed["status"])
        self.assertEqual(rollup["status"], "unknown")
        self.assertEqual(rollup["exposure"], observed["exposure"])

    def test_a_fully_assessed_rollup_pass_is_unchanged(self) -> None:
        plain = security.virtio_net_result(self.highest, mode="dpu")
        covered = security.virtio_net_result(
            self.highest, mode="dpu", coverage_complete=True
        )
        self.assertEqual(covered["status"], "pass")
        self.assertEqual(covered["detail"], plain["detail"])
        self.assertEqual(covered["exposure"], plain["exposure"])

    def test_a_proven_fail_on_the_rollup_path_keeps_the_fail_caveat(self) -> None:
        # Defensive: the collector only fills the rollup version at complete
        # coverage, but a below-minimum rollup version must never be softened.
        gapped = security.virtio_net_result(
            self.below, mode="dpu", coverage_complete=False
        )
        self.assertEqual(gapped["status"], "fail")
        self.assertIn("confirmed on at least one host", gapped["detail"])


class UnassessedDpuHostEvidenceTests(unittest.TestCase):
    """A below-minimum controller proven idle here may be live on a host we never read.

    Mode comes from mlxconfig on the host and the version comes from virtnet on
    the DPU, so modes read everywhere and versions read almost nowhere. One
    readable NIC-mode host below the minimum beside several unread DPU-mode hosts
    is the ordinary fleet picture, and in a homogeneous cluster those unread
    hosts probably run the same controller, live.
    """

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
        """The sameness half is the point: evidence must not leak into grading."""
        exposed_fleet = self.record("dpu")
        idle_fleet = self.record("nic")

        # Identical grade, both directions asserted explicitly.
        self.assertEqual(exposed_fleet["status"], idle_fleet["status"])
        self.assertEqual(exposed_fleet["exposure"], idle_fleet["exposure"])
        self.assertEqual(exposed_fleet["status"], "unknown")
        self.assertEqual(exposed_fleet["exposure"], "latent")
        self.assertEqual(exposed_fleet["gradedVersion"], idle_fleet["gradedVersion"])
        self.assertEqual(exposed_fleet["minimum"], idle_fleet["minimum"])

        # Different evidence.
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
        """Every condition is load-bearing, so each one alone clears the flag."""
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
        """The reported defect, end to end through evaluate().

        Node A reads a below-minimum controller, node B is unresolved, so the
        check rolls the cluster up to unknown and sends virtioNet="unknown".
        The worst observed reading still has to produce a fail.
        """
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
        """FINDING 3: only "version" counted, so settled states claimed a gap.

        The check clamps not_running, version and not_applicable down to
        incomplete whenever the fan-out misses a host, so all three can only
        arrive settled from a fully scanned fleet, and none of them may claim a
        host was unreachable. A genuinely gapped fleet must still say so, which
        is what the second half of this table checks.

        Reaching every host and reading every card are different questions with
        different answers, so the settled states do not share a verdict. Only
        "version" proves every BlueField produced a reading, so only there may
        one reading clear the fleet. "not_running" beside a reading is the mixed
        fleet: every host answered, and one answered "NIC mode, firmware
        installed, nobody read it", so the pass is withdrawn with the coverage
        caveat while coverageComplete stays true. "not_applicable" is a fleet
        with no BlueField at all, so no reading can exist beside it and it is
        asserted in its reachable shape by
        test_a_fully_scanned_fleet_with_no_bluefield_claims_no_gap.
        """
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
        """The regression FINDING 3 named: a settled not_applicable fleet.

        No host carries a BlueField, so no host can produce a controller
        reading and everyBluefieldHostRead is false. It costs this fleet
        nothing: the flag only gates a reading, and the rollup path grades this
        one. The check cannot produce a reading beside this state, which
        test_a_not_applicable_rollup_can_never_carry_a_reading proves from the
        rollup itself.
        """
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
        """The check sends "" for worst when its readings are incomparable.

        The empty string is the literal contract, not None, so it is pinned
        here: it must route to the per-reading grading rather than being
        treated as a version or as no evidence at all.
        """
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
        """virtioNetWorstObservedMode is the worst mode across readings.

        It is not necessarily the mode of the host holding the lowest version,
        so it must be used as sent. Re-deriving it from the reading list would
        soften a live finding to a latent one whenever the lowest version
        happens to sit on a NIC-mode host.
        """
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
    """The link itself: per-host records -> check rollup -> CLI -> verdict.

    The mixed-fleet defect reopened twice because nothing ran this chain. The
    check tests stop at the rollup state, and the tests above hand the coverage
    flags to `virtio_net_result` directly, so a consumer that read the rollup
    with the wrong meaning was invisible to both. These tests start from host
    records the check's own state machine grades and end at the values record,
    through the same argument names `audit-common.sh` passes.
    """

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
        """The mixed fleet, end to end. Adding a patched host must not turn it green.

        node-a is in DPU mode and its controller was read at the LTS24 minimum.
        node-b is in NIC mode: its BlueField carries installed controller
        firmware and nobody read it. Every host answered, so the rollup settles
        on not_running and no host may be called unreachable. The reading still
        speaks only for node-a, so the pass is withdrawn and the report names
        the gap.
        """
        summary, record = self.verdict(
            [
                self.host(
                    host="node-a", mode="dpu", version=self.patched, line=self.line,
                    versionSource="virtnet-version",
                ),
                self.host(host="node-b", mode="nic"),
            ]
        )
        # The rollup the consumer has to interpret correctly.
        self.assertEqual(summary["state"], "not_running")
        self.assertEqual(record["gradedVersion"], self.patched)
        self.assertEqual(record["floorStatus"], "pass")

        # Reached is not read, and the two flags say so separately.
        self.assertIs(record["coverageComplete"], True)
        self.assertIs(record["everyBluefieldHostRead"], False)

        self.assertNotEqual(record["status"], "pass")
        self.assertEqual(record["status"], "unknown")
        self.assertNotEqual(record["exposure"], "none")
        self.assertIn(security.COVERAGE_GAP_CLEAN_CAVEAT, record["detail"])

    def test_an_idle_below_minimum_card_is_not_made_live_by_a_patched_peer(self) -> None:
        """End to end for the invented-host defect, in both directions.

        The below-minimum firmware sits on the NIC-mode host, so it is idle. The
        DPU-mode host that is actually running a controller is patched. No host
        is live, and the rollup must not manufacture one by wearing node-a's
        version with node-b's mode.
        """
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
        self.assertEqual(record["exposure"], "latent")
        self.assertEqual(record["status"], "unknown")

    def test_a_nic_mode_reading_never_speaks_for_a_fleet_with_a_dpu_host(self) -> None:
        """Which reading owns the detail when the statuses tie.

        Both hosts are patched, so both grade pass and neither status can decide
        it. The NIC-mode grade carries "the BlueField is in NIC mode, so the
        virtio-net controller is not currently running", which is a claim about
        the fleet in the text a provider reads, and node-b disproves it. So the
        DPU reading owns the detail even though the NIC host sorts first.
        """
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

    def test_the_tie_break_never_drops_a_proven_below_minimum_reading(self) -> None:
        """The winning entry supplies floorStatus and exposure as well as status.

        node-a is proven below its LTS24 minimum and idle in NIC mode, which the
        NIC softening grades unknown. node-b is in DPU mode with a version that
        shares the 25.10 prefix with two release lines, so it cannot be graded
        and is also unknown. Ranking the platform mode ahead of the minimum grade
        handed the record to node-b, dropped floorStatus to unknown, and with it
        the below-minimum latent finding that node-a proves.
        """
        below = "24.10.17"
        summary, record = self.verdict(
            [
                self.host(host="node-a", mode="nic", version=below, line=self.line,
                          versionSource="virtnet-version"),
                self.host(host="node-b", mode="dpu", version="25.10.4",
                          versionSource="virtnet-version"),
            ]
        )
        self.assertEqual(record["gradedHost"], "node-a")
        self.assertEqual(record["floorStatus"], "fail")
        self.assertEqual(record["exposure"], "latent")

    def test_a_patched_tie_still_lets_the_running_host_own_the_detail(self) -> None:
        """The mode tie-break survives underneath the minimum tie-break.

        Both hosts are patched, so the minimum grade cannot separate them and the
        mode decides, keeping the NIC softening clause out of a detail that a
        DPU host disproves.
        """
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
        """End to end for the commonest fleet shape there is.

        The collector reports a release line only when the output names one, so
        every host reporting `line: None` is ordinary. 23.10.30 clears the LTS23
        minimum and 24.10.17 is below the LTS24 minimum, and because the lines
        interleave the lower NUMBER is the milder grade. Reading a shared `None`
        as one comparable line graded this fleet pass with exposure none while a
        below-minimum controller was running.
        """
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
        """The other direction, so the fix is not a blanket withdrawal."""
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
        """The direction the invented pairing existed to protect.

        Same shape, except the DPU-mode host is itself below the minimum. That is
        a proven live failure on a real host, and narrowing the rollup must not
        soften it.
        """
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
        """The other direction, so the fix cannot be a blanket withdrawal.

        Same patched reading, and the NIC-mode host replaced by a host that has
        no BlueField at all. Nothing is left holding unread firmware, the rollup
        settles on version, and the pass stands.
        """
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
        """Why the split costs the no-BlueField fleet nothing.

        `everyBluefieldHostRead` is false for a not_applicable fleet, which
        would matter only if a reading could reach the observed path beside it.
        The rung is below `version` on the check's ladder, so one host with a
        version pulls the rollup off it, and a fleet that stays on it produced
        no reading at all.
        """
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

        # Same input version, so any difference comes from the correlation.
        self.assertEqual(hardened["version"], exposed["version"])
        self.assertEqual(hardened["versionUnavailableReason"], "dpu-hardened")
        self.assertEqual(exposed["versionUnavailableReason"], "not-observed")
        self.assertNotEqual(hardened["detail"], exposed["detail"])
        self.assertIn("correctly isolated", hardened["detail"])
        self.assertIn("attestation", hardened["detail"])
        self.assertNotIn("correctly isolated", exposed["detail"])

    def test_the_correlation_never_changes_either_status(self) -> None:
        """The important half: explaining an unknown must not grade it.

        A hardened DPU does not make an unread controller version a pass, and an
        exposed one does not make it a fail. Both criteria stay independent.
        """
        hardened = self.graded(self.HARDENED)
        exposed = self.graded(self.OPEN)
        self.assertEqual(hardened["virtioNetBluefield"]["status"], "unknown")
        self.assertEqual(exposed["virtioNetBluefield"]["status"], "unknown")
        # The isolation verdicts do differ, which is what makes the pair a test.
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
        """The reachability proof does not depend on the scan that used to gate it.

        `collect_rshim` stats /dev/rshim0 and /sys/class/net/tmfifo_net0 and
        never runs lspci, so a host with no lspci still reports them truthfully.
        That is the normal shape of a minimal k8s driver pod, and it used to
        report "could not be assessed" for a host proven to expose the DPU
        control plane.
        """
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
                # The gap is named, and it does not weaken the grade.
                self.assertIn("did not complete", verdict.detail)
                self.assertIn("already stands", verdict.detail)

    def test_a_missing_pci_scan_with_no_rshim_path_stays_unknown(self) -> None:
        """The other direction: absent proof must not become a proven pass.

        Without a scan and without either path, nothing is known either way, so
        the fix must not trade the old false unknown for a false clean.
        """
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
        """INTERNAL_CPU_RSHIM is not part of the scan-independent proof.

        It comes from mlxconfig reading the device the scan finds, so unlike the
        two filesystem paths it cannot be trusted ahead of the scan.
        """
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
        """A proven reachable control plane, plus the coverage gap beside it.

        Same discipline as the firmware caveat: an unassessed peer host cannot
        weaken a host we proved, so the gap is named rather than allowed to
        soften the grade.
        """
        covered = security.dpu_host_isolation_verdict(self.evidence(rshimDeviceNode=True))
        gapped = security.dpu_host_isolation_verdict(
            {**self.evidence(rshimDeviceNode=True), "unassessedHosts": ["node-b"]}
        )
        # The grade is identical with and without the gap. Naming a coverage
        # gap must never regrade a proven finding, in either direction.
        self.assertEqual(covered.status, gapped.status)
        self.assertEqual(gapped.status, "fail")
        self.assertEqual(covered.minimum, gapped.minimum)

        # Only the evidence differs.
        self.assertNotEqual(covered.detail, gapped.detail)
        self.assertIn("can reach the DPU control plane", gapped.detail)
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
        """The sameness half: naming a gap must not regrade a criterion."""
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

        # Without a rollup state, coverage counts as incomplete, so the same
        # clean version is withdrawn rather than clearing the fleet. A caller
        # that cannot say how much of the fleet answered gets the safe answer.
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

    def test_the_committed_table_is_readable_again_afterwards(self) -> None:
        with unreadable_minimum_table():
            pass
        self.assertEqual(
            security.docker_verdict(read_minimum("components.docker.minimum")).status, "pass"
        )


class GpuAbsentDriverPolicyTests(unittest.TestCase):
    """A completed scan that found no NVIDIA GPU ends the driver's scope.

    The reported defect: a GPU-less standalone host (20260827-134338, model
    ``no-nvidia-smi``) graded ``unknown`` and warned, which raises an
    attestation request for a driver that cannot exist on that host. Only the
    collector's positive absence claim may cause the skip, and only while the
    driver version itself is unreadable.
    """

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
