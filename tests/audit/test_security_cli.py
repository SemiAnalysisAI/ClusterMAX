"""Tests for the checkout-free security audit CLI."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from cmax import audit_report, cli, runtime_paths, security, target_selection
from cmax.yaml_support import load_yaml_module

_MINIMUM_FIXTURE = tempfile.TemporaryDirectory()
_MINIMUM_ENV = "CLUSTERMAX_MINIMUM_VERSIONS"


TOOLKIT_MINIMUM = {
    "kind": "minimum",
    "minimum": "1.19.1",
    "advisory": "https://nvidia.custhelp.com/app/answers/detail/a_id/5850/",
    "cves": ["CVE-2026-24260"],
    "source": {"aId": 5850, "feed": "nvidia-csaf"},
}

# The advisory URLs the fixture table publishes. Every check in
# `security.MINIMUM_BOUND_CHECKS` takes its bulletin link from here, so a link
# hardcoded back into `cmax/security.py` renders the wrong URL and fails. The
# values are deliberately not the real ones: a fixture that repeated the
# committed table would pass whether the code read the table or a constant.
FIXTURE_ADVISORIES = {
    "nvidiaDriver": "https://example.invalid/minimums/driver",
    "nvidiaContainerToolkit": TOOLKIT_MINIMUM["advisory"],
    "cudaToolkit": "https://example.invalid/minimums/cuda",
    "runc": "https://example.invalid/minimums/runc",
    "docker": "https://example.invalid/minimums/docker",
    "connectxFirmware": "https://example.invalid/minimums/connectx",
    "virtioNetBluefield": "https://example.invalid/minimums/virtio",
}


def minimum_table(generated: datetime, **components: dict) -> dict:
    """Build a minimal minimum table shaped like the generated one."""
    return {
        "schemaVersion": 1,
        "generated": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gracePeriodDays": 3,
        "maxAgeDays": 10,
        "components": components
        or {
            "docker": {
                "kind": "minimum",
                "minimum": "29.4.3",
                "advisory": FIXTURE_ADVISORIES["docker"],
                "source": {"feed": "manual"},
            },
            "nvidiaContainerToolkit": dict(TOOLKIT_MINIMUM),
            "nvidiaDriver": {
                "kind": "branchMap",
                "branches": {"580": "580.159.03"},
                "advisory": FIXTURE_ADVISORIES["nvidiaDriver"],
                "source": {"aId": 5821, "feed": "nvidia-csaf"},
            },
            "cudaToolkit": {
                "kind": "minimum",
                "minimum": "13.1",
                "advisory": FIXTURE_ADVISORIES["cudaToolkit"],
                "cves": ["CVE-2025-33228"],
                "source": {"aId": 5755, "feed": "nvidia-csaf"},
            },
            "runc": {
                "kind": "ladder",
                "ladder": {"1.3": "1.3.3"},
                "advisory": FIXTURE_ADVISORIES["runc"],
                "source": {"feed": "osv"},
            },
            "connectxFirmware": {
                "kind": "trainMap",
                "trains": {"46": 3008},
                "advisory": FIXTURE_ADVISORIES["connectxFirmware"],
                "source": {"aId": 5699, "feed": "nvidia-csaf"},
            },
            "virtioNetBluefield": {
                "kind": "releaseLines",
                "lines": {"GA": {"fixed": "25.10.6"}},
                "advisory": FIXTURE_ADVISORIES["virtioNetBluefield"],
                "cves": ["CVE-2026-65094"],
                "source": {"aId": 5815, "feed": "nvidia-csaf"},
            },
        },
    }


def write_minimum_table(directory: Path, table: dict, name: str = "minimums.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n")
    return path


def setUpModule() -> None:
    """Grade every report in this module against a pinned, current minimum table.

    The freshness check reads the installed table, so without this the whole
    file would depend on the age of the committed `minimum-versions.json` and
    would start failing whenever the daily refresh workflow stalls. The stamp
    is relative to the run, so the fixture never expires.
    """
    fresh = write_minimum_table(
        Path(_MINIMUM_FIXTURE.name),
        minimum_table(datetime.now(timezone.utc) - timedelta(days=1)),
    )
    os.environ[_MINIMUM_ENV] = str(fresh)


def tearDownModule() -> None:
    os.environ.pop(_MINIMUM_ENV, None)
    _MINIMUM_FIXTURE.cleanup()


def security_values() -> dict:
    return {
        "audit_data": {
            "securityVersions": {
                "nvidiaDriver": {
                    "status": "fail",
                    "version": "580.126.09",
                    "minimum": "580.159.03",
                    "detail": "Below the minimum version",
                },
                "nvidiaContainerToolkit": {
                    "status": "unknown",
                    "version": "unknown",
                    "minimum": "1.19.1",
                },
                "cudaToolkit": {
                    "status": "not_applicable",
                    "version": "not-installed",
                    "minimum": "13.1",
                },
                "runc": {
                    "status": "pass",
                    "version": "1.3.3",
                    "minimum": "1.3.3",
                },
                "docker": {
                    "status": "pass",
                    "version": "29.4.3",
                    "minimum": "29.4.3",
                },
                "connectxFirmware": {
                    "status": "not_applicable",
                    "minimum": "NVIDIA ConnectX/BlueField only",
                    "devices": [],
                },
            },
            "security": {
                "guestKernel": {
                    "running": "6.8.0-58-generic",
                    "newestInstalled": "6.8.0-136-generic",
                    "newerInstalled": True,
                },
                "fragnesia": {
                    "cve": "CVE-2026-46300",
                    "relatedCves": ["CVE-2026-43284", "CVE-2026-43500"],
                    "status": "fail",
                    "ubuntuNoblePackageMinimum": "6.8.0-124.124",
                },
                "januscape": {
                    "cpuVirtualizationExposed": True,
                    "kvmDeviceExposed": True,
                    "nestedEnabled": "true",
                    "exposed": True,
                    "status": "host-patch-required",
                },
                "bmcIpmi": {"exposed": False},
                "ufmSecuredBareMetalCloud": {
                    "applicable": True,
                    "status": "manual",
                },
                "pciePassthrough": {"hostVerificationRequired": True},
                "virtualization": {"type": "none", "guest": False},
                "nvlinkBoundary": {
                    "nvlinkExposed": False,
                    "topologyChecked": True,
                    "topologyCoverageComplete": True,
                    "nvidiaGpuPresent": True,
                    "targetIsVm": False,
                },
                "nvidiaMay2026": {"nvlinkExposed": False},
            },
        }
    }


class TargetDetectionTests(unittest.TestCase):
    def test_explicit_targets_map_to_harness_and_environment(self) -> None:
        expected = {
            "slurm": ("slurm", "slurm"),
            "k8s": ("k8s", "k8s"),
            "vm": ("standalone", "vm"),
            "container": ("standalone", "container"),
            "standalone": ("standalone", "bare-metal"),
        }
        for flag, pair in expected.items():
            with self.subTest(flag=flag):
                target = security.detect_target(flag)
                self.assertEqual((target.harness, target.environment), pair)
                self.assertTrue(target.explicit)

    def test_detection_prefers_slurm_then_kubernetes(self) -> None:
        with mock.patch.dict("os.environ", {"SLURM_JOB_ID": "123"}, clear=True):
            self.assertEqual(security.detect_target().harness, "slurm")
        with mock.patch.dict(
            "os.environ", {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, clear=True
        ):
            self.assertEqual(security.detect_target().harness, "k8s")

    def test_standalone_subtypes_are_detected(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch.object(security.shutil, "which", return_value=None):
                with mock.patch.object(
                    security, "_inside_container", return_value=True
                ):
                    self.assertEqual(security.detect_target().environment, "container")
                with mock.patch.object(
                    security, "_inside_container", return_value=False
                ):
                    with mock.patch.object(security, "_inside_vm", return_value=True):
                        self.assertEqual(security.detect_target().environment, "vm")
                    with mock.patch.object(
                        security, "_inside_vm", return_value=False
                    ), mock.patch.object(security.platform, "system", return_value="Linux"):
                        self.assertEqual(
                            security.detect_target().environment, "bare-metal"
                        )

    def test_macos_is_a_local_machine_instead_of_bare_metal(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(
            security.shutil, "which", return_value=None
        ), mock.patch.object(
            security, "_inside_container", return_value=False
        ), mock.patch.object(
            security, "_inside_vm", return_value=False
        ), mock.patch.object(
            security.platform, "system", return_value="Darwin"
        ):
            target = security.detect_target()
        self.assertEqual((target.harness, target.environment), ("standalone", "local"))
        self.assertFalse(target.explicit)

    def test_local_override_ignores_installed_cluster_clients(self) -> None:
        with mock.patch.object(
            security.shutil, "which", return_value="/usr/bin/sbatch"
        ), mock.patch.object(
            security, "_inside_container", return_value=False
        ), mock.patch.object(
            security, "_inside_vm", return_value=False
        ), mock.patch.object(
            security.platform, "system", return_value="Darwin"
        ):
            target = security.detect_target("local")
        self.assertEqual((target.harness, target.environment), ("standalone", "local"))
        self.assertTrue(target.explicit)

    def test_systemd_bare_metal_result_overrides_cloud_dmi_strings(self) -> None:
        completed = mock.Mock(returncode=1)
        with mock.patch.object(
            security.shutil, "which", return_value="/usr/bin/systemd-detect-virt"
        ):
            with mock.patch.object(security.subprocess, "run", return_value=completed):
                with mock.patch.object(
                    security.Path,
                    "read_text",
                    side_effect=AssertionError("DMI fallback must not run"),
                ):
                    self.assertFalse(security._inside_vm())

    def test_systemd_vm_result_is_detected(self) -> None:
        completed = mock.Mock(returncode=0)
        with mock.patch.object(
            security.shutil, "which", return_value="/usr/bin/systemd-detect-virt"
        ):
            with mock.patch.object(security.subprocess, "run", return_value=completed):
                self.assertTrue(security._inside_vm())

    def test_vm_detection_falls_back_to_dmi_without_systemd(self) -> None:
        with mock.patch.object(security.shutil, "which", return_value=None):
            with mock.patch.object(
                security.Path, "read_text", return_value="KVM virtual machine"
            ):
                self.assertTrue(security._inside_vm())

    def test_standalone_environment_override_wins_over_installed_slurm(self) -> None:
        with mock.patch.dict(
            "os.environ", {"CLUSTERMAX_HARNESS": "standalone"}, clear=True
        ):
            with mock.patch.object(
                security.shutil, "which", return_value="/usr/bin/sbatch"
            ):
                with mock.patch.object(
                    security, "_inside_container", return_value=False
                ):
                    with mock.patch.object(security, "_inside_vm", return_value=True):
                        target = security.detect_target()
        self.assertEqual((target.harness, target.environment), ("standalone", "vm"))
        self.assertTrue(target.explicit)

    def test_harness_environment_override_is_labeled_explicit(self) -> None:
        with mock.patch.dict("os.environ", {"CLUSTERMAX_HARNESS": "k8s"}, clear=True):
            target = security.detect_target()
        self.assertEqual((target.harness, target.environment), ("k8s", "k8s"))
        self.assertTrue(target.explicit)


class SecurityReportTests(unittest.TestCase):
    def test_security_checks_classify_pass_warning_and_critical(self) -> None:
        checks = security.evaluate_security(security_values())
        statuses = {check.id: check.status for check in checks}
        self.assertEqual(statuses["nvidia-driver"], security.CRITICAL)
        self.assertEqual(statuses["nvidia-container-toolkit"], security.WARNING)
        self.assertEqual(statuses["runc"], security.PASS)
        self.assertEqual(statuses["cuda-toolkit"], security.NOT_APPLICABLE)
        self.assertEqual(statuses["connectx-firmware"], security.NOT_APPLICABLE)
        self.assertEqual(statuses["guest-kernel"], security.CRITICAL)
        self.assertEqual(statuses["bmc-ipmi"], security.PASS)
        self.assertEqual(statuses["nvlink-boundary"], security.NOT_APPLICABLE)
        nvlink = next(check for check in checks if check.id == "nvlink-boundary")
        self.assertIn("no NVLink path", nvlink.assessment)
        self.assertEqual(
            sum(security.counts(checks).values()), len(security.CHECK_SPECS)
        )

    def test_bmc_ipmi_report_names_exposed_nodes_and_privileged_scope(self) -> None:
        values = security_values()
        values["audit_data"]["security"]["bmcIpmi"] = {
            "exposed": True,
            "accessMode": "administrative-privileged-host-root-pod",
            "ordinaryPodExposureTested": False,
            "nodesTotal": 6,
            "nodesChecked": 6,
            "nodeCoverageComplete": True,
            "exposedNodes": ["gpu-1", "gpu-2", "cpu-1", "cpu-2"],
        }

        check = next(
            item
            for item in security.evaluate_security(values)
            if item.id == "bmc-ipmi"
        )

        self.assertEqual(check.status, security.CRITICAL)
        self.assertIn("4/6 worker nodes", check.observed)
        self.assertIn("gpu-1, gpu-2, cpu-1, cpu-2", check.observed)
        self.assertIn("privileged pod", check.assessment)
        self.assertIn("ordinary workload pod", check.assessment)

    def test_bmc_ipmi_incomplete_fleet_without_exposure_warns(self) -> None:
        values = security_values()
        values["audit_data"]["security"]["bmcIpmi"] = {
            "exposed": False,
            "accessMode": "administrative-privileged-host-root-pod",
            "nodesTotal": 6,
            "nodesChecked": 4,
            "nodeCoverageComplete": False,
            "exposedNodes": [],
        }

        check = next(
            item
            for item in security.evaluate_security(values)
            if item.id == "bmc-ipmi"
        )

        self.assertEqual(check.status, security.WARNING)
        self.assertIn("checked 4/6", check.observed)
        self.assertIn("Fleet coverage was incomplete", check.assessment)

    def test_not_applicable_kernel_advisory_is_skipped(self) -> None:
        values = security_values()
        values["audit_data"]["security"]["fragnesia"]["status"] = "not-applicable"

        fragnesia = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "fragnesia"
        )

        self.assertEqual(fragnesia.status, security.NOT_APPLICABLE)
        self.assertIn("does not apply", fragnesia.assessment)

    def test_visible_nvlink_requires_provider_partition_verification(self) -> None:
        values = security_values()
        values["audit_data"]["security"]["nvlinkBoundary"]["nvlinkExposed"] = True
        nvlink = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "nvlink-boundary"
        )
        self.assertEqual(nvlink.status, security.WARNING)
        self.assertIn("provider must verify", nvlink.assessment)
        self.assertIn("whole-host VM", nvlink.assessment)
        self.assertIn("rack-scale", nvlink.assessment)

    def test_vm_without_a_visible_link_still_requires_host_evidence(self) -> None:
        values = security_values()
        boundary = values["audit_data"]["security"]["nvlinkBoundary"]
        boundary.update({"nvlinkExposed": False, "targetIsVm": True})
        values["audit_data"]["security"]["virtualization"] = {
            "type": "kvm",
            "guest": True,
        }

        nvlink = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "nvlink-boundary"
        )

        self.assertEqual(nvlink.status, security.WARNING)
        self.assertIn("hidden cross-VM boundary", nvlink.assessment)
        self.assertIn("target=VM", nvlink.observed)

    def test_exclusive_physical_domain_clears_nvlink_warning(self) -> None:
        values = security_values()
        boundary = values["audit_data"]["security"]["nvlinkBoundary"]
        boundary.update(
            {
                "nvlinkExposed": True,
                "targetIsVm": True,
                "domainExclusive": True,
            }
        )

        nvlink = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "nvlink-boundary"
        )

        self.assertEqual(nvlink.status, security.PASS)
        self.assertIn("complete physical NVLink", nvlink.assessment)

    def test_missing_topology_result_never_becomes_no_nvlink(self) -> None:
        values = security_values()
        boundary = values["audit_data"]["security"]["nvlinkBoundary"]
        boundary.update({"nvlinkExposed": "unknown", "topologyChecked": False})

        nvlink = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "nvlink-boundary"
        )

        self.assertEqual(nvlink.status, security.WARNING)
        self.assertIn("could not be determined", nvlink.assessment)

    def test_no_nvlink_on_one_kubernetes_node_does_not_clear_the_fleet(self) -> None:
        values = security_values()
        boundary = values["audit_data"]["security"]["nvlinkBoundary"]
        boundary.update(
            {
                "nvlinkExposed": False,
                "topologyChecked": True,
                "topologyCoverageComplete": False,
            }
        )

        nvlink = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "nvlink-boundary"
        )

        self.assertEqual(nvlink.status, security.WARNING)
        self.assertIn("did not cover every GPU host", nvlink.assessment)

    def test_connectx_report_names_devices_below_the_minimum(self) -> None:
        values = security_values()
        values["audit_data"]["securityVersions"]["connectxFirmware"] = {
            "status": "fail",
            "minimum": "GA 46.3008; LTS24 43.8002",
            "devices": [
                {"device": "mlx5_0", "version": "40.47.2526", "status": "pass"},
                {"device": "mlx5_4", "version": "22.43.2566", "status": "fail"},
                {
                    "device": "mlx5_bond_0",
                    "version": "26.43.2566",
                    "status": "fail",
                },
            ],
        }
        check = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "connectx-firmware"
        )
        self.assertEqual(check.status, security.CRITICAL)
        self.assertIn("2 of 3 devices below minimum", check.observed)
        self.assertIn("mlx5_4=22.43.2566", check.observed)
        self.assertIn("mlx5_bond_0=26.43.2566", check.observed)
        self.assertNotIn("not collected", check.observed)

    def test_connectx_report_marks_incomplete_inventory_as_warning(self) -> None:
        values = security_values()
        values["audit_data"]["securityVersions"]["connectxFirmware"] = {
            "status": "unknown",
            "minimum": "GA 46.3008",
            "devices": [
                {"device": "unknown", "version": "unknown", "status": "unknown"}
            ],
        }
        check = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "connectx-firmware"
        )
        self.assertEqual(check.status, security.WARNING)
        self.assertIn("unknown=unknown", check.observed)

    def test_connectx_report_explains_incomplete_passing_inventory(self) -> None:
        values = security_values()
        values["audit_data"]["securityVersions"]["connectxFirmware"] = {
            "status": "unknown",
            "minimum": "GA 46.3008",
            "devices": [
                {"device": "mlx5_0", "version": "40.47.2526", "status": "pass"}
            ],
        }
        check = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "connectx-firmware"
        )
        self.assertEqual(check.status, security.WARNING)
        self.assertIn("inventory incomplete after 1 collected device", check.observed)
        self.assertNotIn("0 of 1 devices unverified", check.observed)

    def test_connectx_report_marks_empty_unknown_inventory_not_collected(self) -> None:
        values = security_values()
        values["audit_data"]["securityVersions"]["connectxFirmware"] = {
            "status": "unknown",
            "minimum": "GA 46.3008",
        }
        check = next(
            check
            for check in security.evaluate_security(values)
            if check.id == "connectx-firmware"
        )
        self.assertEqual(check.status, security.WARNING)
        self.assertIn("not collected", check.observed)
        self.assertNotIn("0 collected devices", check.observed)

    def test_unknown_guest_kernel_inventory_never_passes(self) -> None:
        for missing_field in ("running", "newestInstalled"):
            with self.subTest(missing_field=missing_field):
                values = security_values()
                guest_kernel = values["audit_data"]["security"]["guestKernel"]
                guest_kernel[missing_field] = "unknown"
                guest_kernel["newerInstalled"] = False
                check = next(
                    check
                    for check in security.evaluate_security(values)
                    if check.id == "guest-kernel"
                )
                self.assertEqual(check.status, security.WARNING)
                self.assertIn("inventory was unavailable", check.assessment)

    def test_default_report_shows_every_check_and_observed_versions(self) -> None:
        values = security_values()
        driver = values["audit_data"]["securityVersions"]["nvidiaDriver"]
        driver["status"] = "pass"
        driver["detail"] = "Below the minimum version"
        driver["gracePeriod"] = {
            "active": True,
            "message": "(passes as fix became available within past 3 days)",
        }
        checks = security.evaluate_security(values)
        report = security.format_report(
            checks,
            security.SecurityTarget("standalone", "vm"),
            Path("/tmp/report"),
        )
        self.assertIn("# ClusterMAX security audit report", report)
        # CUDA, ConnectX, and the absent bare-metal NVLink boundary do not apply.
        self.assertIn("3 failed, 5 warnings, 4 passed, 3 skipped", report)
        self.assertIn("Action required: 3 critical findings.", report)
        self.assertNotIn("critical findings are known exposure", report)
        self.assertIn("NVIDIA driver minimum version", report)
        self.assertIn("[nvidia-driver]", report)
        self.assertIn("FAIL     ", report)
        # Level one is the minimum, so the default lists every check.
        self.assertEqual(
            sum(
                report.count(f"\n{label}")
                for label in ("PASS", "WARNING", "FAIL", "SKIPPED")
            ),
            len(security.CHECK_SPECS),
        )
        self.assertIn("PASS     ", report)
        self.assertIn(
            "observed version 580.126.09; minimum version 580.159.03", report
        )
        self.assertNotIn("Recommendation:", report)
        self.assertNotIn("Why:", report)
        self.assertIn("security-report.log", report)
        self.assertIn("run with -vv", report)

    def test_action_required_uses_singular_for_one_critical_finding(self) -> None:
        critical = next(
            check
            for check in security.evaluate_security(security_values())
            if check.status == security.CRITICAL
        )
        report = security.format_report(
            [critical],
            security.SecurityTarget("standalone", "vm"),
            Path("/tmp/report"),
        )
        self.assertIn("Action required: 1 critical finding.", report)

    def test_maximum_verbosity_report_omits_the_rerun_hint(self) -> None:
        checks = security.evaluate_security(security_values())
        report = security.format_report(
            checks,
            security.SecurityTarget("standalone", "vm"),
            Path("/tmp/report"),
            verbosity=3,
        )
        self.assertNotIn("run with", report)

    def test_verbosity_levels_add_requested_details(self) -> None:
        checks = security.evaluate_security(security_values())
        target = security.SecurityTarget("standalone", "vm")
        one = security.format_report(checks, target, Path("/tmp/report"), verbosity=1)
        two = security.format_report(checks, target, Path("/tmp/report"), verbosity=2)
        three = security.format_report(checks, target, Path("/tmp/report"), verbosity=3)
        # Level one shows every check and the observed value.
        self.assertIn("[nvidia-driver]", one)
        self.assertIn("NVIDIA driver minimum version", one)
        self.assertIn("PASS     ", one)
        self.assertEqual(
            sum(
                one.count(f"\n{label}")
                for label in ("PASS", "WARNING", "FAIL", "SKIPPED")
            ),
            len(security.CHECK_SPECS),
        )
        self.assertIn(
            "observed version 580.126.09; minimum version 580.159.03", one
        )
        self.assertNotIn("Why:", one)
        self.assertIn("References:", one)
        self.assertIn(
            "https://www.clustermax.ai/minimum-versions#nvidiaDriver", one
        )
        self.assertNotIn(FIXTURE_ADVISORIES["nvidiaDriver"], one)
        # Level two adds direct documentation for checks that do not have a
        # canonical minimum-version row. Level three adds the issue description
        # and fix.
        self.assertIn("References:", two)
        self.assertNotIn("Why:", two)
        self.assertNotIn("Recommendation:", two)
        self.assertIn("Why:", three)
        self.assertIn("Recommendation:", three)
        # Minimum-version checks point only to the website row. The row owns the
        # upstream advisory links, so the CLI does not bypass it at any detail
        # level.
        self.assertIn(
            "https://www.clustermax.ai/minimum-versions#nvidiaDriver", two
        )
        self.assertNotIn("NVIDIA GPU driver bulletin", two)
        self.assertNotIn(FIXTURE_ADVISORIES["nvidiaDriver"], two)
        self.assertNotIn(FIXTURE_ADVISORIES["nvidiaDriver"], three)
        # Checks without a website row keep their direct documentation.
        self.assertIn("https://docs.kernel.org/driver-api/vfio.html", two)
        self.assertLess(
            three.index("PASS     "), three.index("WARNING ")
        )
        self.assertLess(
            three.index("WARNING "), three.index("FAIL    ")
        )

    def test_checks_include_multiple_labeled_security_references(self) -> None:
        checks = {
            check.id: check for check in security.evaluate_security(security_values())
        }
        toolkit = checks["nvidia-container-toolkit"]
        self.assertEqual(toolkit.documentation, toolkit.references[0].url)
        # The bulletin and CVE links come from the generated minimum table, so a
        # new bulletin cannot leave a retired one cited here.
        self.assertEqual(
            [reference.label for reference in toolkit.references],
            [
                "ClusterMAX minimum versions",
                "NVIDIA Container Toolkit bulletin",
                "CVE-2026-24260",
                "NVIDIA product security",
            ],
        )
        self.assertEqual(
            toolkit.documentation,
            "https://www.clustermax.ai/minimum-versions#nvidiaContainerToolkit",
        )
        detailed = security.format_report(
            [toolkit],
            security.SecurityTarget("standalone", "container"),
            Path("/tmp/report"),
            verbosity=3,
            color=False,
        )
        self.assertIn(toolkit.documentation, detailed)
        self.assertNotIn("github.com", detailed)
        self.assertNotIn("nvd.nist.gov", detailed)

    def test_every_security_check_has_a_remediation_reference(self) -> None:
        scenarios = [("current table", security.evaluate_security(security_values()))]
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent.json"
            with mock.patch.dict(os.environ, {_MINIMUM_ENV: str(missing)}):
                scenarios.append(
                    ("missing table", security.evaluate_security(security_values()))
                )
        for scenario, checks in scenarios:
            for check in checks:
                with self.subTest(scenario=scenario, check=check.id):
                    self.assertTrue(check.references)
                    reference_pairs = [
                        (reference.label, reference.url)
                        for reference in check.references
                    ]
                    self.assertEqual(len(reference_pairs), len(set(reference_pairs)))

    def test_every_minimum_bound_check_links_the_table_advisory(self) -> None:
        # Pinning only the container toolkit let the other bound checks keep a
        # hardcoded bulletin that matched the table by coincidence of one
        # snapshot. The fixture publishes a different URL per component, so a
        # check that reads a constant renders the wrong link and fails here.
        checks = {
            check.id: check for check in security.evaluate_security(security_values())
        }
        self.assertEqual(
            sorted(security.MINIMUM_BOUND_CHECKS),
            sorted(
                check_id
                for check_id in checks
                if check_id in security.MINIMUM_BOUND_CHECKS
            ),
        )
        for check_id, (component, _, label) in security.MINIMUM_BOUND_CHECKS.items():
            expected = FIXTURE_ADVISORIES[component]
            check = checks[check_id]
            website, bulletin = check.references[:2]
            self.assertEqual(
                website.url,
                security.minimum_links.security_check_url(check_id),
                check_id,
            )
            self.assertEqual(website.label, "ClusterMAX minimum versions", check_id)
            self.assertEqual(bulletin.url, expected, check_id)
            self.assertEqual(bulletin.label, label, check_id)
            self.assertEqual(check.documentation, website.url, check_id)

    def test_minimum_bound_labels_carry_no_bulletin_date(self) -> None:
        # A dated label ("May 2026 driver bulletin") goes stale exactly when the
        # URL beside it does, and a reader trusts the date more than the link.
        for check_id, (_, _, label) in security.MINIMUM_BOUND_CHECKS.items():
            self.assertNotRegex(
                label,
                r"(?i)\b(january|february|march|april|may|june|july|august"
                r"|september|october|november|december|20\d\d)\b",
                check_id,
            )

    def test_minimum_backed_remediation_names_the_current_minimum(self) -> None:
        toolkit = next(
            check
            for check in security.evaluate_security(security_values())
            if check.id == "nvidia-container-toolkit"
        )
        self.assertIn("1.19.1 or newer", toolkit.remediation)
        # The retired 1.17.8 minimum must not survive anywhere in the check.
        self.assertNotIn("1.17.8", toolkit.remediation)
        self.assertNotIn(
            "1.17.8", " ".join(reference.url for reference in toolkit.references)
        )

    def test_unreadable_minimum_table_keeps_a_generic_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent.json"
            with mock.patch.dict(os.environ, {_MINIMUM_ENV: str(missing)}):
                toolkit = next(
                    check
                    for check in security.evaluate_security(security_values())
                    if check.id == "nvidia-container-toolkit"
                )
        self.assertIn("published minimum version", toolkit.remediation)
        self.assertTrue(toolkit.documentation)

    def test_fragnesia_observation_names_versions_and_cves(self) -> None:
        check = next(
            check
            for check in security.evaluate_security(security_values())
            if check.id == "fragnesia"
        )
        self.assertIn("observed version 6.8.0-58-generic", check.observed)
        self.assertIn("minimum version 6.8.0-124.124", check.observed)
        self.assertIn("CVE-2026-46300", check.observed)

    def test_reports_are_saved_at_maximum_detail(self) -> None:
        checks = security.evaluate_security(security_values())
        target = security.SecurityTarget("standalone", "container")
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            security.write_reports(checks, target, log_dir)
            payload = json.loads((log_dir / "security-report.json").read_text())
            text = (log_dir / "security-report.log").read_text()
        self.assertEqual(payload["target"]["environment"], "container")
        self.assertEqual(len(payload["checks"]), len(security.CHECK_SPECS))
        self.assertGreater(len(payload["checks"][0]["references"]), 1)
        # The on-disk log is the maximum-detail (verbosity 3), plain-text report.
        self.assertIn("Recommendation:", text)
        self.assertNotIn("\033[", text)

class SecurityCliTests(unittest.TestCase):
    def test_security_profile_dispatches_to_the_shared_audit_runner(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(
            security, "detect_target", return_value=target
        ) as detect:
            with mock.patch.object(
                target_selection, "prepare_audit_target", return_value=target
            ) as prepare, mock.patch(
                "cmax.audit_runner.run", return_value=0
            ) as run:
                result = cli.main(
                    [
                        "--repo",
                        "/runtime",
                        "audit",
                        "security",
                        "--vm",
                    ]
                )
        self.assertEqual(result, 0)
        detect.assert_called_once_with("vm")
        prepare.assert_called_once_with(
            target,
            command="cmax audit security",
            assume_yes=False,
            kubeconfig=None,
        )
        run.assert_called_once_with(
            repo="/runtime",
            verbosity=1,
            category="security",
            resolved_target=target,
            exit_on_fail=True,
        )

    def test_security_cancel_stops_before_the_collector(self) -> None:
        with mock.patch.object(
            target_selection,
            "prepare_audit_target",
            side_effect=target_selection.TargetSelectionCancelled("audit canceled"),
        ), mock.patch(
            "cmax.audit_runner.run"
        ) as run, contextlib.redirect_stderr(io.StringIO()) as error:
            result = cli.main(["audit", "security"])

        self.assertEqual(result, cli.AUDIT_CANCEL_EXIT)
        run.assert_not_called()
        self.assertIn("cmax: audit canceled", error.getvalue())

    def test_show_lists_security_checks_without_running(self) -> None:
        for flag in ("-s", "--show"):
            output = io.StringIO()
            with self.subTest(flag=flag), mock.patch.object(
                security,
                "find_runtime_root",
                return_value=runtime_paths.package_runtime_root(),
            ), mock.patch(
                "cmax.audit_runner.run"
            ) as run, contextlib.redirect_stdout(output):
                result = cli.main(["audit", "security", flag])
            self.assertEqual(result, 0)
            run.assert_not_called()
            self.assertIn(
                "securityVersions.nvidiaDriver.status", output.getvalue()
            )
            self.assertIn("[isolation] Security isolation", output.getvalue())
            self.assertNotIn("[hardware]", output.getvalue())

    def test_yaml_output_is_a_resolved_dry_run_of_cmax_config(self) -> None:
        output = io.StringIO()
        repo_root = Path(__file__).resolve().parents[2]
        runtime_root = runtime_paths.package_runtime_root()
        with mock.patch.object(
            target_selection, "prepare_audit_target"
        ) as prepare, mock.patch("cmax.audit_runner.run") as run:
            with contextlib.redirect_stdout(output):
                result = cli.main(
                    [
                        "--repo",
                        str(repo_root),
                        "audit",
                        "security",
                        "--vm",
                        "--dry-run",
                        "-o",
                        "yaml",
                    ]
                )

        yaml = load_yaml_module(runtime_root)
        plan = yaml.safe_load(output.getvalue())
        configured = yaml.safe_load((runtime_root / "cmax.yaml").read_text())
        configured_tests = sum(len(tests) for tests in configured["phase"].values())
        self.assertEqual(result, 0)
        prepare.assert_not_called()
        run.assert_not_called()
        self.assertEqual(plan["version"], configured["version"])
        self.assertEqual(plan["manifest_selection"]["enabled"], ["audit.audit"])
        self.assertEqual(
            plan["manifest_selection"]["disabled_count"], configured_tests - 1
        )
        self.assertEqual(
            set(plan["manifest_selection"]["disabled_by_phase"]),
            set(configured["phase"]),
        )
        self.assertEqual(plan["audit_profile"]["target"]["environment"], "vm")
        self.assertEqual(plan["audit_profile"]["target"]["harness"], "standalone")
        self.assertTrue(plan["audit_profile"]["scope"]["checks"]["fabric"])
        self.assertFalse(plan["audit_profile"]["scope"]["checks"]["gpu"])
        self.assertEqual(
            set(plan["audit_profile"]["checks"]),
            {
                check.key
                for check in audit_report.list_check_specs(
                    runtime_root,
                    category="security",
                    harness="standalone",
                )
            },
        )
        self.assertEqual(
            plan["audit_profile"]["artifacts"],
            ["audit.out", "audit.values.json"],
        )
        self.assertTrue(plan["audit_profile"]["scope"]["standard_report"])
        self.assertNotIn("security_report", plan["audit_profile"]["scope"])

    def test_custom_output_directory_is_rejected_by_each_live_audit(self) -> None:
        for profile in ([], ["security"]):
            with self.subTest(profile=profile), contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit):
                    cli.main(
                        ["audit", *profile, "--output-dir", "security-output"]
                    )

    def test_exit_zero_flag_is_rejected_by_full_audit(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["audit", "--exit-zero"])

    def test_critical_findings_return_nonzero_exit(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=2) as run:
                result = cli.main(["--repo", "/runtime", "audit", "security", "--vm"])
        self.assertEqual(result, cli.SECURITY_CRITICAL_EXIT)
        run.assert_called_once_with(
            repo="/runtime",
            verbosity=1,
            category="security",
            resolved_target=target,
            exit_on_fail=True,
        )

    def test_exit_zero_suppresses_the_critical_exit_code(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0) as run:
                result = cli.main(
                    ["--repo", "/runtime", "audit", "security", "--vm", "--exit-zero"]
                )
        self.assertEqual(result, 0)
        run.assert_called_once_with(
            repo="/runtime",
            verbosity=1,
            category="security",
            resolved_target=target,
        )

    def test_clean_run_returns_zero(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0):
                result = cli.main(["--repo", "/runtime", "audit", "security", "--vm"])
        self.assertEqual(result, 0)


class AbsentDeviceTests(unittest.TestCase):
    """A criterion for hardware the machine does not have is not a pass.

    Grading it pass credits a provider for a device it never shipped and
    inflates the passed count on every cluster without one. It is also not an
    issue, so it is counted and printed on its own.
    """

    def test_absent_devices_report_not_applicable_and_leave_the_pass_count(self) -> None:
        absent = {
            "securityVersions": {
                "connectxFirmware": {"status": "not_applicable"},
                "virtioNetBluefield": {"status": "not_applicable"},
                "dpuHostIsolation": {"status": "not_applicable"},
            }
        }
        for check_id, evaluate in (
            ("connectx-firmware", security._connectx_firmware),
            ("virtio-net-bluefield", security._virtio_net_bluefield),
            ("dpu-host-isolation", security._dpu_host_isolation),
        ):
            with self.subTest(check=check_id):
                status, observed, _ = evaluate(absent)
                self.assertEqual(status, security.NOT_APPLICABLE)
                self.assertNotEqual(status, security.PASS)
                self.assertIn("no ", observed.lower())

    def test_ufm_profile_without_infiniband_fabric_is_not_a_pass(self) -> None:
        """applicable=False means the profile was never assessed, not passed."""
        status, observed, assessment = security._ufm(
            {
                "security": {
                    "ufmSecuredBareMetalCloud": {
                        "applicable": False,
                        "status": "not_applicable",
                    }
                }
            }
        )
        self.assertEqual(status, security.NOT_APPLICABLE)
        self.assertNotEqual(status, security.PASS)
        self.assertEqual(observed, "no native InfiniBand fabric detected")
        self.assertIn("No native InfiniBand fabric", assessment)

    def test_ufm_profile_on_an_infiniband_fabric_still_grades_its_status(self) -> None:
        """The not-applicable path must not swallow a fabric that was assessed."""
        for status_value, expected in (
            ("pass", security.PASS),
            ("fail", security.CRITICAL),
            ("manual", security.WARNING),
        ):
            with self.subTest(status=status_value):
                status, _, _ = security._ufm(
                    {
                        "security": {
                            "ufmSecuredBareMetalCloud": {
                                "applicable": True,
                                "status": status_value,
                            }
                        }
                    }
                )
                self.assertEqual(status, expected)

    def test_a_present_device_still_passes_on_its_own_merits(self) -> None:
        """The rule must not turn every device criterion into not-applicable."""
        status, _, _ = security._dpu_host_isolation(
            {"securityVersions": {"dpuHostIsolation": {"status": "pass", "version": "1"}}}
        )
        self.assertEqual(status, security.PASS)

    def test_absent_hardware_is_given_no_remediation_to_apply(self) -> None:
        """A criterion for hardware that is not there has nothing to fix.

        The fix block was skipped only for a pass, so after absent-hardware
        checks moved off `pass` the report printed "apply the zero-trust host
        profile" underneath "no BlueField DPU present". That reads as an action
        item on a machine with no DPU, and it is written to the saved log too.
        """
        checks = [
            security.SecurityCheck(
                id="dpu-host-isolation", title="BlueField host isolation (RShim)",
                status=security.NOT_APPLICABLE, observed="no BlueField DPU present",
                importance="", assessment="No BlueField DPU is present.",
                remediation="Apply the zero-trust host profile with mlxprivhost.",
                documentation="", references=(),
            ),
            security.SecurityCheck(
                id="guest-kernel", title="Active kernel version",
                status=security.CRITICAL, observed="6.8.0-58",
                importance="", assessment="Reboot required.",
                remediation="Reboot into the newer kernel.",
                documentation="", references=(),
            ),
        ]
        report = security.format_report(
            checks, security.detect_target("vm"), Path("/tmp/report"), verbosity=3
        )
        self.assertNotIn("Apply the zero-trust host profile", report)
        # The real finding still gets its remediation, so this is not a blanket
        # suppression of the fix block.
        self.assertIn("Reboot into the newer kernel", report)

    def test_not_applicable_is_neither_an_issue_nor_a_pass(self) -> None:
        checks = [
            security.SecurityCheck(
                id="x", title="X", status=security.NOT_APPLICABLE,
                observed="no device", importance="", assessment="",
                remediation="", documentation="", references=(),
            )
        ]
        tally = security.counts(checks)
        self.assertEqual(tally[security.NOT_APPLICABLE], 1)
        self.assertEqual(tally[security.PASS], 0)
        self.assertEqual(tally[security.WARNING] + tally[security.CRITICAL], 0)


class MinimumFreshnessTests(unittest.TestCase):
    """The generated minimum table must age out loudly, never silently."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.generated = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def _use(self, table: dict | str) -> Path:
        if isinstance(table, str):
            path = self.directory / "minimums.json"
            path.write_text(table)
        else:
            path = write_minimum_table(self.directory, table)
        patcher = mock.patch.dict(os.environ, {_MINIMUM_ENV: str(path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return path

    def _report(self, *, now: datetime | None = None, verbosity: int = 0) -> str:
        return security.format_report(
            security.evaluate_security(security_values()),
            security.SecurityTarget("standalone", "vm"),
            Path("/tmp/report"),
            verbosity=verbosity,
            now=now,
        )

    def test_notice_is_absent_at_the_age_limit_and_present_one_day_later(self) -> None:
        self._use(minimum_table(self.generated))
        at_limit = self._report(now=self.generated + timedelta(days=10))
        past_limit = self._report(now=self.generated + timedelta(days=11))
        self.assertNotIn("Minimum data:", at_limit)
        self.assertIn("Minimum data:", past_limit)
        self.assertIn("11 days old", past_limit)
        self.assertIn("generated 2026-01-01", past_limit)

    def test_stale_notice_names_the_update_action_and_a_rerun(self) -> None:
        self._use(minimum_table(self.generated))
        report = self._report(now=self.generated + timedelta(days=40))
        # The table sits in a temporary directory here, which is the shape of a
        # pip installation, so the notice names the fetch and not `git pull`.
        self.assertIn("`cmax audit security` to fetch", report)
        self.assertIn("run the audit again", report)
        self.assertIn("vulnerable version as a pass", report)

    def test_staleness_changes_no_count_and_no_exit_code(self) -> None:
        self._use(minimum_table(self.generated))
        stale_checks = security.evaluate_security(security_values())
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0):
                clean_exit = cli.main(["audit", "security", "--vm"])
        self.assertEqual(
            security.counts(stale_checks),
            # The two BlueField checks warn here because this fixture carries no
            # BlueField evidence at all. A real machine with no DPU reports
            # not_applicable from a completed scan and both count as not
            # applicable, so this is the "check did not report" path and not the
            # "no DPU" path.
            # The completed bare-metal topology scan also makes an absent
            # NVLink boundary not applicable instead of counting it as a pass.
            {
                security.PASS: 3,
                security.WARNING: 5,
                security.CRITICAL: 4,
                security.NOT_APPLICABLE: 3,
            },
        )
        self.assertEqual(sum(security.counts(stale_checks).values()), 15)
        # A stale table is a notice, so a run with no critical finding still
        # exits 0 and no check is graded critical by staleness alone.
        self.assertEqual(clean_exit, 0)
        report = self._report(now=self.generated + timedelta(days=40), verbosity=3)
        self.assertNotIn("minimum-version-freshness", report)
        self.assertEqual(
            sum(
                report.count(f"\n{label}")
                for label in ("PASS", "WARNING", "FAIL", "SKIPPED")
            ),
            len(security.CHECK_SPECS),
        )

    def test_notice_sits_between_the_summary_and_the_saved_report_line(self) -> None:
        self._use(minimum_table(self.generated))
        report = self._report(now=self.generated + timedelta(days=11))
        self.assertLess(report.index(" failed"), report.index("Minimum data:"))
        self.assertLess(report.index("Minimum data:"), report.index("report saved to"))

    def test_notice_is_visible_at_every_verbosity(self) -> None:
        self._use(minimum_table(self.generated))
        for verbosity in (0, 1, 2, 3):
            with self.subTest(verbosity=verbosity):
                report = self._report(
                    now=self.generated + timedelta(days=11), verbosity=verbosity
                )
                self.assertIn("Minimum data:", report)

    def test_missing_table_shows_the_notice_and_never_stays_silent(self) -> None:
        patcher = mock.patch.dict(
            os.environ, {_MINIMUM_ENV: str(self.directory / "absent.json")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        state = security.minimum_freshness()
        self.assertIn("could not be read", state["notice"])
        self.assertIn("absent.json", state["notice"])
        self.assertIn("Minimum data:", self._report())

    def test_corrupt_table_shows_the_notice_and_never_stays_silent(self) -> None:
        self._use("{ this is not json")
        self.assertIn("could not be read", security.minimum_freshness()["notice"])
        self.assertIn("Minimum data:", self._report())

    def test_saved_report_records_the_minimum_state(self) -> None:
        self._use(minimum_table(self.generated))
        checks = security.evaluate_security(security_values())
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            security.write_reports(
                checks, security.SecurityTarget("standalone", "vm"), log_dir
            )
            payload = json.loads((log_dir / "security-report.json").read_text())
        minimum_data = payload["minimum_data"]
        self.assertEqual(minimum_data["generated"], "2026-01-01")
        self.assertEqual(minimum_data["max_age_days"], 10)
        self.assertTrue(minimum_data["stale"])
        self.assertIn("`cmax audit security` to fetch", minimum_data["notice"])
        # Recorded beside the checks, never counted as one of them.
        self.assertEqual(sum(payload["counts"].values()), len(payload["checks"]))

    def test_minimum_freshness_is_not_a_graded_criterion(self) -> None:
        ids = [spec.id for spec in security.CHECK_SPECS]
        self.assertEqual(len(ids), 15)
        self.assertEqual(len(set(ids)), 15)
        self.assertEqual(
            ids,
            [
                "nvidia-driver",
                "nvidia-container-toolkit",
                "cuda-toolkit",
                "runc",
                "docker",
                "connectx-firmware",
                "guest-kernel",
                "fragnesia",
                "januscape",
                "bmc-ipmi",
                "ufm-profile",
                "pcie-passthrough",
                "nvlink-boundary",
                "virtio-net-bluefield",
                "dpu-host-isolation",
            ],
        )


def fake_generator(**attributes: object) -> types.ModuleType:
    """Build a stand-in for cmax.minimum_refresh with the agreed contract."""
    module = types.ModuleType("cmax.minimum_refresh")
    for name, value in attributes.items():
        setattr(module, name, value)
    return module


@contextlib.contextmanager
def installed_generator(module: types.ModuleType | None):
    """Install a stand-in generator, or remove the generator entirely.

    `from cmax import minimum_refresh` reads the package attribute first, so a
    sys.modules entry alone is ignored once any other test has imported the real
    module. Passing None reproduces an install that ships no generator at all.
    """
    import cmax

    had_attribute = hasattr(cmax, "minimum_refresh")
    previous_attribute = getattr(cmax, "minimum_refresh", None)
    had_entry = "cmax.minimum_refresh" in sys.modules
    previous_entry = sys.modules.get("cmax.minimum_refresh")
    try:
        if module is None:
            if had_attribute:
                delattr(cmax, "minimum_refresh")
            sys.modules["cmax.minimum_refresh"] = None
        else:
            setattr(cmax, "minimum_refresh", module)
            sys.modules["cmax.minimum_refresh"] = module
        yield
    finally:
        if had_attribute:
            setattr(cmax, "minimum_refresh", previous_attribute)
        elif hasattr(cmax, "minimum_refresh"):
            delattr(cmax, "minimum_refresh")
        if had_entry:
            sys.modules["cmax.minimum_refresh"] = previous_entry
        else:
            sys.modules.pop("cmax.minimum_refresh", None)


class MinimumRefreshTests(unittest.TestCase):
    """`--refresh-minimums` is opt-in, and a failed refresh never blocks an audit."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = write_minimum_table(
            Path(self.tmp.name),
            minimum_table(datetime.now(timezone.utc) - timedelta(days=1)),
        )
        self.committed = self.path.read_text()
        patcher = mock.patch.dict(os.environ, {_MINIMUM_ENV: str(self.path)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _refresh(self, generator: types.ModuleType | None) -> str:
        output = io.StringIO()
        with installed_generator(generator):
            with contextlib.redirect_stdout(output):
                self.refreshed = security.refresh_minimum_table()
        return output.getvalue()

    def test_moved_minimums_are_written_and_summarized_old_to_new(self) -> None:
        updated = minimum_table(
            datetime.now(timezone.utc),
            docker={
                "kind": "minimum",
                "minimum": "29.5.0",
                "source": {"feed": "manual"},
            },
            cudaToolkit={
                "kind": "minimum",
                "minimum": "13.2",
                "source": {"feed": "nvidia-csaf"},
            },
            # Absent from the fixture, so this covers the other half of the
            # summary: a component the refresh adds rather than moves.
            dcgm={
                "kind": "minimum",
                "minimum": "4.5.3",
                "source": {"feed": "nvidia-csaf"},
            },
        )
        printed = self._refresh(
            fake_generator(build_minimums=lambda **kwargs: updated)
        )
        self.assertTrue(self.refreshed)
        self.assertIn("docker.minimum: 29.4.3 -> 29.5.0", printed)
        self.assertIn("cudaToolkit.minimum: 13.1 -> 13.2", printed)
        self.assertIn("dcgm.minimum: absent -> 4.5.3", printed)
        self.assertEqual(
            json.loads(self.path.read_text())["components"]["docker"]["minimum"],
            "29.5.0",
        )

    def test_unchanged_minimums_report_no_change(self) -> None:
        current = json.loads(self.committed)

        def build(**kwargs):
            table = json.loads(json.dumps(current))
            table["generated"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            return table

        printed = self._refresh(fake_generator(build_minimums=build))
        self.assertIn("no change", printed)
        self.assertNotIn("->", printed)

    def test_generator_failure_keeps_the_committed_table(self) -> None:
        def build(**kwargs):
            raise RuntimeError("nvidia-csaf feed unreachable")

        printed = self._refresh(fake_generator(build_minimums=build))
        self.assertFalse(self.refreshed)
        self.assertIn("minimum refresh failed", printed)
        self.assertIn("nvidia-csaf feed unreachable", printed)
        self.assertEqual(self.path.read_text(), self.committed)

    def test_fail_closed_exit_keeps_the_committed_table(self) -> None:
        def build(**kwargs):
            raise SystemExit(1)

        printed = self._refresh(fake_generator(build_minimums=build))
        self.assertFalse(self.refreshed)
        self.assertIn("minimum refresh failed", printed)
        self.assertEqual(self.path.read_text(), self.committed)

    def test_empty_component_table_is_rejected(self) -> None:
        printed = self._refresh(
            fake_generator(build_minimums=lambda **kwargs: {"components": {}})
        )
        self.assertFalse(self.refreshed)
        self.assertIn("no components", printed)
        self.assertEqual(self.path.read_text(), self.committed)

    def test_missing_generator_degrades_to_a_clear_message(self) -> None:
        printed = self._refresh(None)
        self.assertFalse(self.refreshed)
        self.assertIn("minimum generator is unavailable", printed)
        self.assertEqual(self.path.read_text(), self.committed)

    def test_read_only_install_says_so_and_keeps_the_table(self) -> None:
        self.path.chmod(0o444)
        self.addCleanup(self.path.chmod, 0o644)
        printed = self._refresh(
            fake_generator(
                build_minimums=lambda **kwargs: minimum_table(datetime.now(timezone.utc))
            )
        )
        self.assertFalse(self.refreshed)
        self.assertIn("read-only", printed)
        self.assertIn("pip-installed wheel", printed)
        self.assertEqual(self.path.read_text(), self.committed)

    def test_refresh_runs_before_the_audit_and_a_failure_does_not_stop_it(
        self,
    ) -> None:
        order: list[str] = []
        target = security.SecurityTarget("standalone", "vm", True)

        def build(**kwargs):
            order.append("refresh")
            raise RuntimeError("no outbound network")

        def fake_audit(*args, **kwargs):
            order.append("audit")
            return 0

        output = io.StringIO()
        with installed_generator(fake_generator(build_minimums=build)):
            with mock.patch.object(security, "detect_target", return_value=target):
                with mock.patch(
                    "cmax.audit_runner.run", side_effect=fake_audit
                ):
                    with contextlib.redirect_stdout(output):
                        result = cli.main(
                            ["audit", "security", "--vm", "--refresh-minimums"]
                        )
        self.assertEqual(result, 0)
        self.assertEqual(order, ["refresh", "audit"])
        self.assertIn("no outbound network", output.getvalue())
        self.assertEqual(self.path.read_text(), self.committed)

    def test_refresh_is_not_the_default(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0):
                with mock.patch.object(security, "refresh_minimum_table") as refresh:
                    result = cli.main(["audit", "security", "--vm"])
        self.assertEqual(result, 0)
        refresh.assert_not_called()

    def test_refresh_minimums_is_rejected_outside_the_security_profile(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit):
                cli.main(["audit", "--refresh-minimums"])
        self.assertIn("unrecognized arguments: --refresh-minimums", stderr.getvalue())


class PackagedRuntimeTests(unittest.TestCase):
    def test_runner_passes_each_profile_to_the_check_dispatcher(self) -> None:
        run_script = runtime_paths.audit_runner(
            runtime_paths.package_runtime_root()
        ).read_text()
        self.assertIn('"${CLUSTERMAX_AUDIT_SCOPE:-full}"', run_script)

    def test_package_directory_is_a_runtime_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_runtime = root / "site-packages" / "cmax"
            runner = runtime_paths.audit_runner(package_runtime)
            runner.parent.mkdir(parents=True)
            runner.write_text("#!/bin/bash\n")
            with mock.patch.dict("os.environ", {}, clear=True):
                with mock.patch.object(
                    security.Path, "cwd", return_value=root / "empty"
                ):
                    with mock.patch.object(
                        runtime_paths,
                        "package_runtime_root",
                        return_value=package_runtime,
                    ):
                        self.assertEqual(
                            security.find_runtime_root(), package_runtime.resolve()
                        )

    def test_configured_repo_environment_selects_packaged_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "configured-repo"
            runtime = repo / "cmax"
            runner = runtime_paths.audit_runner(runtime)
            runner.parent.mkdir(parents=True)
            runner.write_text("#!/bin/bash\n")
            with mock.patch.dict(
                "os.environ", {security.REPO_ENV: str(repo)}, clear=True
            ):
                self.assertEqual(security.find_runtime_root(), runtime.resolve())

    def test_explicit_repo_overrides_configured_repo_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            explicit = Path(tmp) / "explicit-repo"
            configured = Path(tmp) / "configured-repo"
            for repo in (explicit, configured):
                runtime = repo / "cmax"
                runner = runtime_paths.audit_runner(runtime)
                runner.parent.mkdir(parents=True)
                runner.write_text("#!/bin/bash\n")
            with mock.patch.dict(
                "os.environ", {security.REPO_ENV: str(configured)}, clear=True
            ):
                self.assertEqual(
                    security.find_runtime_root(str(explicit)),
                    (explicit / "cmax").resolve(),
                )

    def test_package_runtime_is_selected_outside_a_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_runtime = root / "site-packages" / "cmax"
            wheel_runner = runtime_paths.audit_runner(wheel_runtime)
            wheel_runner.parent.mkdir(parents=True)
            wheel_runner.write_text("#!/bin/bash\n")
            with mock.patch.dict("os.environ", {}, clear=True):
                with mock.patch.object(
                    security.Path, "cwd", return_value=root / "outside"
                ):
                    with mock.patch.object(
                        runtime_paths,
                        "package_runtime_root",
                        return_value=wheel_runtime,
                    ):
                        self.assertEqual(
                            security.find_runtime_root(), wheel_runtime.resolve()
                        )


if __name__ == "__main__":
    unittest.main()
