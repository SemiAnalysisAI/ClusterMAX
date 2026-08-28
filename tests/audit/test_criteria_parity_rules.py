#!/usr/bin/env python3
"""Unit tests for the criteria-parity batch of audit rules.

Representative sample: one rule per new pattern (guarded install checks,
dict-valued user management, numeric thresholds, status-string checks, and
guard suppression).
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


AUDIT_SCRIPTS = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
)


def load_findings_module():
    name = "audit_findings_criteria_rules"
    spec = importlib.util.spec_from_file_location(
        name, AUDIT_SCRIPTS / "audit_findings.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit_findings = load_findings_module()


def keys(findings) -> set[str]:
    return {f.key for f in findings}


class AccessRuleTests(unittest.TestCase):
    def test_missing_sudo_and_ssh_are_flagged(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {"access": {"sudoAvailable": False, "sshToComputeNodes": False}}
            )
        )
        self.assertIn("access.sudoAvailable", found)
        self.assertIn("access.sshToComputeNodes", found)

    def test_working_access_is_clean(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {
                    "access": {
                        "sudoAvailable": True,
                        "sshToComputeNodes": True,
                        "slurmCommandsOk": True,
                        "externalIdp": {"detected": True},
                        "userManagement": {"useradd": True, "groupadd": True},
                    }
                }
            )
        )
        self.assertFalse({key for key in found if key.startswith("access.")})

    def test_user_management_fails_when_either_command_is_unusable(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {"access": {"userManagement": {"useradd": True, "groupadd": False}}}
            )
        )
        self.assertIn("access.userManagement", found)

    def test_user_management_ignores_uncollected_shapes(self) -> None:
        found = keys(
            audit_findings.detect_findings({"access": {"userManagement": {}}})
        )
        self.assertNotIn("access.userManagement", found)


class ContainerRuleTests(unittest.TestCase):
    def test_missing_runtimes_are_flagged_when_the_worker_was_inspected(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {
                    "containers": {
                        "workerCheckOk": True,
                        "enroot": False,
                        "dockerOnWorkers": False,
                        "singularity": False,
                    }
                }
            )
        )
        self.assertIn("containers.enroot", found)
        self.assertIn("containers.dockerOnWorkers", found)
        self.assertIn("containers.singularity", found)

    def test_worker_vantage_failure_suppresses_runtime_findings(self) -> None:
        # When the worker container check could not run, "enroot: false" is a
        # vantage artifact rather than evidence that Enroot is missing.
        found = keys(
            audit_findings.detect_findings(
                {
                    "containers": {
                        "workerCheckOk": False,
                        "enroot": False,
                        "dockerOnWorkers": False,
                        "singularity": False,
                    }
                }
            )
        )
        self.assertNotIn("containers.enroot", found)
        self.assertNotIn("containers.dockerOnWorkers", found)
        self.assertNotIn("containers.singularity", found)

    def test_broken_enroot_import_is_flagged_only_when_enroot_is_installed(self) -> None:
        installed = keys(
            audit_findings.detect_findings(
                {
                    "containers": {
                        "workerCheckOk": True,
                        "enroot": True,
                        "enrootImportWorks": False,
                    }
                }
            )
        )
        self.assertIn("containers.enrootImportWorks", installed)

        absent = keys(
            audit_findings.detect_findings(
                {
                    "containers": {
                        "workerCheckOk": True,
                        "enroot": False,
                        "enrootImportWorks": False,
                    }
                }
            )
        )
        self.assertNotIn("containers.enrootImportWorks", absent)


class NumericThresholdRuleTests(unittest.TestCase):
    def test_perf_event_paranoid_flags_only_restrictive_values(self) -> None:
        base = {"software": {"perf": {"installed": True, "perfEventParanoid": "2"}}}
        self.assertIn(
            "software.perf.perfEventParanoid",
            keys(audit_findings.detect_findings(base)),
        )

        base["software"]["perf"]["perfEventParanoid"] = "1"
        self.assertNotIn(
            "software.perf.perfEventParanoid",
            keys(audit_findings.detect_findings(base)),
        )

        # "unknown" is not evidence of a failure; the report layer surfaces it.
        base["software"]["perf"]["perfEventParanoid"] = "unknown"
        self.assertNotIn(
            "software.perf.perfEventParanoid",
            keys(audit_findings.detect_findings(base)),
        )

    def test_perf_sysctls_are_ignored_when_perf_is_not_installed(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {"software": {"perf": {"installed": False, "perfEventParanoid": "3"}}}
            )
        )
        self.assertIn("software.perf.installed", found)
        self.assertNotIn("software.perf.perfEventParanoid", found)


class FabricRuleTests(unittest.TestCase):
    def test_nccl_conf_override_is_flagged(self) -> None:
        found = keys(
            audit_findings.detect_findings({"networking": {"ncclAutoConfig": False}})
        )
        self.assertIn("networking.ncclAutoConfig", found)

    def test_nccl_auto_configuration_is_clean(self) -> None:
        found = keys(
            audit_findings.detect_findings({"networking": {"ncclAutoConfig": True}})
        )
        self.assertNotIn("networking.ncclAutoConfig", found)

    def test_intentionally_unreported_readings_have_no_rules(self) -> None:
        # These collectors expose raw observations but no trustworthy graded
        # verdict, so the CLI must not turn them into report checks.
        rule_keys = {rule.key for rule in audit_findings.RULES}
        self.assertTrue(
            rule_keys.isdisjoint(
                {
                    "networking.ibTenantIsolationStatus",
                    "networking.nicFabric.status",
                    "gpus.thermals.status",
                    "networking.ibTenantIsolation",
                    "networking.nicFabric.computeFabricClass",
                    "gpus.thermals.idleTempMax",
                    "gpus.thermals.idlePowerMax",
                }
            )
        )


class PcieAcsRuleTests(unittest.TestCase):
    def test_enabled_acs_is_flagged_only_for_a_scoped_path_reading(self) -> None:
        scoped = keys(
            audit_findings.detect_findings(
                {"gpus": {"pcieAcs": {"enabled": "true", "scoped": True}}}
            )
        )
        self.assertIn("gpus.pcieAcs.enabled", scoped)

        unscoped = keys(
            audit_findings.detect_findings(
                {"gpus": {"pcieAcs": {"enabled": "true", "scoped": False}}}
            )
        )
        self.assertNotIn("gpus.pcieAcs.enabled", unscoped)


class DcgmRuleTests(unittest.TestCase):
    def test_dcgm_slurm_wiring_is_checked_only_when_dcgm_is_installed(self) -> None:
        missing = keys(
            audit_findings.detect_findings(
                {"healthChecks": {"dcgmInstalled": False, "dcgmSlurm": False}}
            )
        )
        self.assertIn("healthChecks.dcgmInstalled", missing)
        self.assertNotIn("healthChecks.dcgmSlurm", missing)

        unwired = keys(
            audit_findings.detect_findings(
                {"healthChecks": {"dcgmInstalled": True, "dcgmSlurm": False}}
            )
        )
        self.assertIn("healthChecks.dcgmSlurm", unwired)

    def test_amd_clusters_skip_the_dcgm_checks(self) -> None:
        found = keys(
            audit_findings.detect_findings(
                {
                    "gpus": {"amd": {"present": True}},
                    "healthChecks": {"dcgmInstalled": False, "dcgmSlurm": False},
                }
            )
        )
        self.assertNotIn("healthChecks.dcgmInstalled", found)
        self.assertNotIn("healthChecks.dcgmSlurm", found)


if __name__ == "__main__":
    unittest.main()
