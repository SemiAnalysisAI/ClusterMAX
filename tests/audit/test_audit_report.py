#!/usr/bin/env python3
"""Tests for the full cluster audit terminal report."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cmax import runtime_paths


RUNTIME_ROOT = runtime_paths.package_runtime_root()
MODULE_PATH = Path(__file__).resolve().parents[2] / "cmax" / "audit_report.py"
CHECKOUT_ROOT = MODULE_PATH.parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location("audit_report_under_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


audit_report = load_module()


def audit_values() -> dict:
    return {
        "audit_data": {
            "securityVersions": {
                "nvidiaDriver": {
                    "status": "pass",
                    "version": "580.126.09",
                    "minimum": "580.126.09",
                }
            },
            "containers": {
                "workerCheckOk": True,
                "nvidiaContainerToolkit": False,
            },
            "hbm_memory_exposure": {"status": "warning"},
        }
    }


class AuditReportTests(unittest.TestCase):
    def test_list_check_specs_keeps_unique_rule_order(self) -> None:
        findings = SimpleNamespace(
            RULES=[
                SimpleNamespace(key="securityVersions.nvidiaDriver.status"),
                SimpleNamespace(key="containers.workerCheckOk"),
                SimpleNamespace(key="securityVersions.nvidiaDriver.status"),
            ]
        )

        with mock.patch.object(
            audit_report, "_load_findings", return_value=findings
        ), mock.patch.object(
            audit_report, "_security_extension_specs", return_value=[]
        ):
            checks = audit_report.list_check_specs(RUNTIME_ROOT)

        self.assertEqual(
            [(check.key, check.title, check.category) for check in checks],
            [
                (
                    "securityVersions.nvidiaDriver.status",
                    "Security Versions / NVIDIA Driver",
                    "versions",
                ),
                (
                    "containers.workerCheckOk",
                    "Containers / Worker Check Ok",
                    "orchestration",
                ),
            ],
        )

    def test_real_rules_have_one_category_and_stable_counts(self) -> None:
        checks = audit_report.list_check_specs(RUNTIME_ROOT)

        self.assertEqual(len(checks), 59)
        self.assertEqual(
            Counter(check.category for check in checks),
            {
                "versions": 9,
                "isolation": 9,
                "hardware": 8,
                "software": 9,
                "containers": 5,
                "orchestration": 4,
                "networking": 5,
                "storage": 1,
                "health": 4,
                "access": 5,
            },
        )
        keys = {check.key for check in checks}
        self.assertTrue(audit_report._SECURITY_EXTENSION_IDS.issubset(keys))

    def test_januscape_status_shows_the_exposure_evidence(self) -> None:
        values = {
            "audit_data": {
                "security": {
                    "januscape": {
                        "cpuVirtualizationExposed": True,
                        "kvmDeviceExposed": True,
                        "nestedEnabled": True,
                        "exposed": True,
                        "status": "host-patch-required",
                    }
                }
            }
        }

        check = next(
            check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
            if check.key == "security.januscape.status"
        )

        self.assertEqual(check.key, "security.januscape.status")
        self.assertEqual(check.status, audit_report.WARNING)
        self.assertEqual(
            check.observed,
            "CPU virtualization exposed=true; KVM device exposed=true; "
            "nested virtualization enabled=true; status=host-patch-required",
        )
        self.assertEqual(
            check.assessment, "Nested virtualization prerequisites are exposed"
        )

    def test_real_rules_have_specific_passing_assessments(self) -> None:
        findings = audit_report._load_findings(RUNTIME_ROOT)
        rule_keys = {rule.key for rule in findings.RULES}
        dynamic_keys = {
            "gpus.gpuDirectRdmaPath",
            "security.januscape.status",
            "securityVersions.virtioNetBluefield.exposure",
        }

        self.assertEqual(
            rule_keys,
            set(audit_report._PASS_ASSESSMENTS) | dynamic_keys,
        )

    def test_public_release_files_do_not_link_obsolete_repository(self) -> None:
        obsolete_url = "https://github.com/" + "SemiAnalysisAI/ClusterMAX"

        for path in (
            CHECKOUT_ROOT / "README.md",
            CHECKOUT_ROOT / "pyproject.toml",
            MODULE_PATH,
        ):
            with self.subTest(path=path):
                self.assertNotIn(obsolete_url, path.read_text())

    def test_removed_checks_do_not_run_for_any_cluster(self) -> None:
        removed = {
            "containers.dockerVersionOk",
            "containers.nvidiaContainerToolkitVersionOk",
            "healthChecks.monitoringStack.grafana",
            "healthChecks.monitoringStack.prometheus",
            "security.januscape.exposed",
            "security.nvidiaMay2026.patched",
            "security.qemuCve20243446.status",
            "security.vmscape.status",
        }

        for harness in ("k8s", "slurm", "standalone"):
            with self.subTest(harness=harness):
                keys = {
                    check.key
                    for check in audit_report.list_check_specs(
                        RUNTIME_ROOT, harness=harness
                    )
                }
                self.assertTrue(removed.isdisjoint(keys))

    def test_not_applicable_results_are_skipped_for_every_harness(self) -> None:
        values = {
            "audit_data": {
                "securityVersions": {
                    "dcgm": {
                        "status": "not_applicable",
                        "version": "not-installed",
                        "minimum": "4.5.3",
                        "detail": "DCGM is not installed on the inspected host.",
                    },
                    "dcgmExporter": {
                        "status": "not_applicable",
                        "version": "not-installed",
                        "minimum": "4.8.2",
                    },
                    "virtioNetBluefield": {
                        "status": "not_applicable",
                        "exposure": "none",
                        "detail": "No BlueField DPU is present.",
                    },
                    "dpuHostIsolation": {
                        "status": "not_applicable",
                        "detail": "No BlueField DPU is present.",
                    },
                },
                "security": {
                    "fragnesia": {
                        "status": "not-applicable",
                        "ubuntuNoblePackageMinimum": "6.8.0-124.124",
                    }
                },
                "arm_smmu_virtualization": {
                    "status": "not_applicable",
                    "message": "The x86 host has no Arm SMMU.",
                },
                "hbm_memory_exposure": {
                    "status": "not_applicable",
                    "message": "The host has no coherent GPU memory.",
                },
            }
        }
        expected = {
            "arm_smmu_virtualization.status",
            "hbm_memory_exposure.status",
            "security.fragnesia.status",
            "securityVersions.dcgm.status",
            "securityVersions.dcgmExporter.status",
            "securityVersions.dpuHostIsolation.status",
            "securityVersions.virtioNetBluefield.exposure",
            "securityVersions.virtioNetBluefield.status",
        }

        for harness in ("k8s", "slurm", "standalone"):
            with self.subTest(harness=harness):
                values["cluster"] = {"orchestrator": harness}
                by_key = {
                    check.key: check
                    for check in audit_report.evaluate(values, RUNTIME_ROOT)
                }
                self.assertTrue(expected.issubset(by_key))
                self.assertTrue(
                    all(by_key[key].status == audit_report.SKIPPED for key in expected)
                )
                self.assertEqual(
                    by_key["securityVersions.dcgm.status"].assessment,
                    "DCGM is not installed on the inspected host.",
                )
                expected_assessment = (
                    ""
                    if harness == "standalone"
                    else "No BlueField DPU is present."
                )
                self.assertEqual(
                    by_key["securityVersions.virtioNetBluefield.exposure"].assessment,
                    expected_assessment,
                )

    def test_incomplete_bluefield_inventory_remains_visible(self) -> None:
        values = {
            "cluster": {"orchestrator": "k8s"},
            "audit_data": {
                "securityVersions": {
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                    },
                    "dpuHostIsolation": {
                        "status": "unknown",
                        "bluefieldPresent": None,
                        "scanComplete": False,
                    },
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        for key in (
            "securityVersions.virtioNetBluefield.status",
            "securityVersions.virtioNetBluefield.exposure",
            "securityVersions.dpuHostIsolation.status",
        ):
            self.assertEqual(by_key[key].status, audit_report.WARNING)

    def test_detected_bluefield_requests_attestation_instead_of_inventory(self) -> None:
        values = {
            "cluster": {"orchestrator": "k8s"},
            "audit_data": {
                "securityVersions": {
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                        "platformMode": "dpu",
                    },
                    "dpuHostIsolation": {
                        "status": "unknown",
                        "bluefieldPresent": True,
                        "scanComplete": True,
                    },
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        for key in (
            "securityVersions.virtioNetBluefield.status",
            "securityVersions.virtioNetBluefield.exposure",
            "securityVersions.dpuHostIsolation.status",
        ):
            self.assertEqual(by_key[key].status, audit_report.WARNING)
            self.assertIn("Attest", by_key[key].recommendation)
            self.assertNotIn("Complete the BlueField inventory", by_key[key].recommendation)

    def test_bluefield_presence_signals_request_attestation(self) -> None:
        evidence_cases = (
            (
                {
                    "status": "unknown",
                    "exposure": "unknown",
                    "platformMode": "unknown",
                    "gradedVersion": "25.10.6",
                },
                {"status": "unknown", "bluefieldPresent": None},
            ),
            (
                {
                    "status": "unknown",
                    "exposure": "unknown",
                    "platformMode": "unknown",
                },
                {"status": "unknown", "bluefieldPresent": "true"},
            ),
        )

        for controller, isolation in evidence_cases:
            with self.subTest(controller=controller, isolation=isolation):
                values = {
                    "cluster": {"orchestrator": "k8s"},
                    "audit_data": {
                        "securityVersions": {
                            "virtioNetBluefield": controller,
                            "dpuHostIsolation": isolation,
                        }
                    },
                }
                by_key = {
                    check.key: check
                    for check in audit_report.evaluate(values, RUNTIME_ROOT)
                }
                recommendation = by_key[
                    "securityVersions.virtioNetBluefield.exposure"
                ].recommendation
                self.assertIn("Attest", recommendation)
                self.assertNotIn("Complete the BlueField inventory", recommendation)

    def test_ufm_profile_without_infiniband_renders_as_skipped(self) -> None:
        """applicable=False is a check that never ran, so it must not pass."""
        values = {
            "cluster": {"orchestrator": "standalone"},
            "audit_data": {
                "security": {
                    "ufmSecuredBareMetalCloud": {
                        "applicable": False,
                        "status": "not_applicable",
                        "profile": "Secured Bare Metal Cloud",
                    }
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        self.assertEqual(by_key["ufm-profile"].status, audit_report.SKIPPED)
        self.assertEqual(
            by_key["ufm-profile"].observed,
            "n/a for standalone machines",
        )
        self.assertEqual(by_key["ufm-profile"].assessment, "")

    def test_collector_not_applicable_spellings_all_render_as_skipped(self) -> None:
        """Every collector spelling of "does not apply" must skip, never pass."""
        values = {
            "audit_data": {
                "securityVersions": {
                    "dcgm": {
                        "status": "N/A",
                        "version": "not-installed",
                        "minimum": "4.5.3",
                    },
                    # A real pass in the same run must stay a pass.
                    "nvidiaDriver": {
                        "status": "pass",
                        "version": "580.126.09",
                        "minimum": "580.126.09",
                    },
                },
                "security": {
                    "fragnesia": {
                        "status": "n/a",
                        "ubuntuNoblePackageMinimum": "6.8.0-124.124",
                    }
                },
                "hbm_memory_exposure": {"status": "not applicable"},
                "arm_smmu_virtualization": {"status": "Not-Applicable"},
            }
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        for key in (
            "securityVersions.dcgm.status",
            "security.fragnesia.status",
            "hbm_memory_exposure.status",
            "arm_smmu_virtualization.status",
        ):
            with self.subTest(key=key):
                self.assertEqual(by_key[key].status, audit_report.SKIPPED)
        self.assertEqual(
            by_key["securityVersions.nvidiaDriver.status"].status,
            audit_report.PASS,
        )

    def test_not_applicable_normalization_leaves_real_values_alone(self) -> None:
        """A version or an ordinary status must never collapse to a skip."""
        for value in ("n/a", "N/A", "na", "NA", "not applicable", "Not-Applicable",
                      "not_applicable", "NotApplicable", " not applicable "):
            with self.subTest(value=value):
                self.assertTrue(
                    audit_report._is_not_applicable({}, "vm_iommu.status", value)
                )
        for value in ("pass", "fail", "unknown", "manual", "native", "nap",
                      "580.126.09", "1.19.1", "not-present", "6.8.0-124.124",
                      True, False, None):
            with self.subTest(value=value):
                self.assertFalse(
                    audit_report._is_not_applicable({}, "vm_iommu.status", value)
                )

    def test_unverified_literal_is_a_warning(self) -> None:
        values = {
            "audit_data": {
                "security": {"januscape": {"status": "unknown"}}
            }
        }

        check = next(
            check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
            if check.key == "security.januscape.status"
        )

        self.assertEqual(check.key, "security.januscape.status")
        self.assertEqual(check.status, audit_report.WARNING)
        self.assertEqual(
            check.assessment,
            "The collector could not verify this check. Treat this value as unverified.",
        )

    def test_five_applicable_unknown_version_checks_are_warnings(self) -> None:
        keys = (
            "securityVersions.nvidiaDriver.status",
            "securityVersions.nvidiaContainerToolkit.status",
            "securityVersions.cudaToolkit.status",
            "securityVersions.runc.status",
            "securityVersions.docker.status",
        )
        values = {
            "cluster": {"orchestrator": "standalone"},
            "audit_data": {
                "securityVersions": {
                    component: {"status": "unknown"}
                    for component in (
                        "nvidiaDriver",
                        "nvidiaContainerToolkit",
                        "cudaToolkit",
                        "runc",
                        "docker",
                    )
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(
                values, RUNTIME_ROOT, harness="standalone"
            )
        }

        self.assertEqual(
            {key: by_key[key].status for key in keys},
            {key: audit_report.WARNING for key in keys},
        )

    def test_passes_show_collected_context_for_every_harness(self) -> None:
        values = {
            "audit_data": {
                "containers": {
                    "workerCheckOk": True,
                    "workerNode": "shadecloud",
                    "nvidiaContainerToolkit": True,
                    "nvidiaContainerToolkitVersion": "1.17.8",
                },
                "gpu_controls": {
                    "vboost": {
                        "allowed": True,
                        "status": "allowed",
                        "mode": "application-clocks",
                        "allowed_nodes": 1,
                        "checked_nodes": 1,
                    }
                },
                "networking": {
                    "hcaNamingValid": True,
                    "hcaDevices": ["mlx5_0", {"name": "mlx5_1"}],
                },
                "vm_iommu": {
                    "status": "pass",
                    "message": "IOMMU mode is passthrough for 2 GPU / RDMA devices.",
                },
            }
        }

        for harness in ("k8s", "slurm", "standalone"):
            with self.subTest(harness=harness):
                values["cluster"] = {"orchestrator": harness}
                by_key = {
                    check.key: check
                    for check in audit_report.evaluate(values, RUNTIME_ROOT)
                }
                self.assertEqual(
                    by_key["containers.workerCheckOk"].observed,
                    "check completed=true; worker node=shadecloud",
                )
                self.assertEqual(
                    by_key["containers.nvidiaContainerToolkit"].observed,
                    "installed=true; version=1.17.8",
                )
                self.assertEqual(
                    by_key["gpu_controls.vboost.allowed"].observed,
                    "allowed=true; status=allowed; mode=application-clocks; "
                    "allowed nodes=1/1",
                )
                if harness != "slurm":
                    self.assertEqual(
                        by_key["networking.hcaNamingValid"].status,
                        audit_report.SKIPPED,
                    )
                    self.assertEqual(
                        by_key["networking.hcaNamingValid"].observed,
                        f"n/a for {harness} machines",
                    )
                else:
                    self.assertEqual(
                        by_key["networking.hcaNamingValid"].observed,
                        "valid=true; devices=mlx5_0, mlx5_1",
                    )
                self.assertEqual(
                    by_key["vm_iommu.status"].assessment,
                    "IOMMU mode is passthrough for 2 GPU / RDMA devices.",
                )

    def test_dpu_isolation_status_is_not_rendered_as_a_version(self) -> None:
        values = {
            "audit_data": {
                "securityVersions": {
                    "dpuHostIsolation": {
                        "status": "pass",
                        "detail": "The DPU control plane is isolated from the host.",
                    }
                }
            }
        }

        check = audit_report.evaluate(values, RUNTIME_ROOT)[0]

        self.assertEqual(check.key, "securityVersions.dpuHostIsolation.status")
        self.assertEqual(check.status, audit_report.PASS)
        self.assertEqual(check.observed, "pass")

    def test_guest_kernel_observation_names_both_versions(self) -> None:
        values = {
            "audit_data": {
                "security": {
                    "guestKernel": {
                        "running": "6.8.0-90-generic",
                        "newestInstalled": "6.8.0-90-generic",
                        "newerInstalled": False,
                    }
                }
            }
        }

        check = audit_report.evaluate(values, RUNTIME_ROOT)[0]

        self.assertEqual(check.status, audit_report.PASS)
        self.assertEqual(
            check.observed,
            "observed version 6.8.0-90-generic; minimum version not applicable; "
            "newest installed version 6.8.0-90-generic",
        )

    def test_titles_preserve_standard_acronyms(self) -> None:
        self.assertEqual(
            audit_report._title("securityVersions.dcgmExporter.status"),
            "Security Versions / DCGM Exporter",
        )
        self.assertEqual(
            audit_report._title("arm_smmu_virtualization.status"),
            "Arm SMMU Virtualization",
        )

    def test_standalone_list_advertises_scheduler_checks_that_will_skip(self) -> None:
        checks = audit_report.list_check_specs(RUNTIME_ROOT, harness="standalone")

        keys = {check.key for check in checks}
        self.assertIn("containers.pyxisRuntimeWorks", keys)
        self.assertIn("kubelet_cpu_manager_policy.status", keys)
        self.assertIn("nccl_topo_file.status", keys)
        self.assertIn("nccl_ib_qps.status", keys)
        self.assertIn("networking.topologyConfigured", keys)
        self.assertIn("healthChecks.nhcInstalled", keys)
        self.assertIn("hbm_memory_exposure.status", keys)

    def test_standalone_evaluation_marks_scheduler_checks_as_skipped(self) -> None:
        values = {
            "cluster": {"orchestrator": "standalone"},
            "audit_data": {
                "containers": {"pyxisRuntimeWorks": False},
                "kubelet_cpu_manager_policy": {"status": "warning"},
                "nccl_topo_file": {"status": "fail"},
                "nccl_ib_qps": {"status": "warning"},
                "networking": {"topologyConfigured": False},
                "healthChecks": {"nhcInstalled": False},
                "hbm_memory_exposure": {"status": "warning"},
            },
        }

        checks = audit_report.evaluate(values, RUNTIME_ROOT)

        by_key = {check.key: check for check in checks}
        self.assertEqual(by_key["hbm_memory_exposure.status"].status, "warning")
        for key in (
            "containers.pyxisRuntimeWorks",
            "healthChecks.nhcInstalled",
            "kubelet_cpu_manager_policy.status",
            "nccl_ib_qps.status",
            "nccl_topo_file.status",
            "networking.topologyConfigured",
            "gpus.gdrcopy.installed",
            "healthChecks.monitoringStack.dcgmExporter",
            "software.nvhpc.status",
        ):
            self.assertEqual(by_key[key].status, "skipped")

    def test_kubernetes_topology_aware_scheduling_is_graded(self) -> None:
        values = {
            "cluster": {"orchestrator": "k8s"},
            "audit_data": {
                "networking": {
                    "topologyConfigured": True,
                    "topologyMechanisms": ["kueue-tas"],
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }
        self.assertEqual(
            by_key["networking.topologyConfigured"].status, audit_report.PASS
        )

        values["audit_data"]["networking"]["topologyConfigured"] = False
        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }
        self.assertEqual(
            by_key["networking.topologyConfigured"].status,
            audit_report.WARNING,
        )

    def test_slurm_pyxis_check_reports_the_installed_version(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "containers": {
                    "pyxisRuntimeWorks": True,
                    "pyxisVersion": "0.24.0-1",
                }
            },
        }

        checks = audit_report.evaluate(values, RUNTIME_ROOT)

        by_key = {check.key: check for check in checks}
        self.assertEqual(
            by_key["containers.pyxisRuntimeWorks"].title,
            "Containers / Pyxis CLI Available",
        )
        self.assertEqual(
            by_key["containers.pyxisRuntimeWorks"].observed,
            "CLI available true; installed version 0.24.0-1",
        )

    def test_format_check_specs_groups_checks_by_category(self) -> None:
        checks = audit_report.list_check_specs(RUNTIME_ROOT, category="networking")

        rendered = audit_report.format_check_specs(checks)

        self.assertIn("[networking] Networking (5 checks)", rendered)
        self.assertIn("networking.hcaNamingValid", rendered)
        self.assertNotIn("[hardware]", rendered)

    def test_binary_public_criteria_checks_report_passes(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "software": {
                    "lmod": {"modulesStatus": "pass"},
                    "ncu": {"profilingEnabled": True},
                    "cudaVisibleDevicesStatus": "pass",
                },
            },
        }

        by_key = {
            check.key: check for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        for key in (
            "software.lmod.modulesStatus",
            "software.ncu.profilingEnabled",
            "software.cudaVisibleDevicesStatus",
        ):
            with self.subTest(key=key):
                self.assertEqual(by_key[key].status, audit_report.PASS)
        self.assertEqual(by_key["storage.rwxStatus"].status, audit_report.SKIPPED)

    def test_unclassified_rule_is_rejected(self) -> None:
        findings = SimpleNamespace(RULES=[SimpleNamespace(key="new.unclassified")])

        with mock.patch.object(
            audit_report, "_load_findings", return_value=findings
        ), self.assertRaisesRegex(ValueError, "has 0 categories"):
            audit_report.list_check_specs(RUNTIME_ROOT)

    def test_full_report_keeps_an_unclassified_runtime_rule(self) -> None:
        rule = SimpleNamespace(
            key="new.unclassified",
            flag_when_missing=False,
            failing=lambda value: False,
            guard=None,
            severity="",
        )
        findings = SimpleNamespace(
            RULES=[rule],
            MISSING="missing",
            VERSION="version",
            _audit_data=lambda values: values,
            nested_get=lambda values, *parts: values[parts[0]][parts[1]],
        )
        values = {"new": {"unclassified": True}}

        with mock.patch.object(
            audit_report, "_load_findings", return_value=findings
        ), mock.patch.object(
            audit_report, "_security_extension_checks", return_value=[]
        ):
            full = audit_report.evaluate(values, RUNTIME_ROOT)
            filtered = audit_report.evaluate(
                values, RUNTIME_ROOT, category="hardware"
            )

        self.assertEqual(len(full), 1)
        self.assertEqual(full[0].category, "uncategorized")
        self.assertEqual(full[0].key, "new.unclassified")
        self.assertEqual(filtered, [])

    def test_evaluate_classifies_unique_checks(self) -> None:
        checks = audit_report.evaluate(audit_values(), RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        self.assertEqual(by_key["securityVersions.nvidiaDriver.status"].status, "pass")
        self.assertEqual(by_key["containers.nvidiaContainerToolkit"].status, "fail")
        self.assertEqual(by_key["hbm_memory_exposure.status"].status, "warning")

    def test_passing_assessments_explain_false_and_compound_values(self) -> None:
        values = {
            "audit_data": {
                "gpus": {
                    "gpuDirectRdmaPath": {
                        "dmaBuf": False,
                        "nvidiaOpen": True,
                        "nvidiaPeermemLegacy": False,
                    }
                },
                "security": {
                    "guestKernel": {
                        "newerInstalled": False,
                        "running": "6.8.0-90-generic",
                        "newestInstalled": "6.8.0-90-generic",
                    },
                    "januscape": {
                        "exposed": False,
                        "status": "not-exposed",
                    },
                    "fragnesia": {"status": "not_applicable"},
                },
            }
        }

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        self.assertEqual(
            by_key["gpus.gpuDirectRdmaPath"].assessment,
            "The audit found a modern GPUDirect RDMA path through the NVIDIA open kernel modules.",
        )
        self.assertEqual(
            by_key["gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy"].assessment,
            "The deprecated nvidia_peermem path is not in use.",
        )
        self.assertEqual(
            by_key["security.guestKernel.newerInstalled"].assessment,
            "The audit did not find a newer installed kernel that is waiting for a reboot.",
        )
        self.assertEqual(
            by_key["security.januscape.status"].assessment,
            "The audit did not find Januscape exposure on this target.",
        )
        self.assertEqual(
            by_key["security.fragnesia.status"].assessment,
            "The collector reported that this check does not apply to the target.",
        )

        report = audit_report.format_report(checks, verbosity=3)
        self.assertIn("The deprecated nvidia_peermem path is not in use.", report)
        self.assertIn("Observed: false", report)
        self.assertNotIn("The observed value meets this check.", report)

    def test_passing_assessments_do_not_contradict_exposure_states(self) -> None:
        values = {
            "audit_data": {
                "security": {
                    "januscape": {
                        "exposed": False,
                        "status": "host-patch-required",
                    }
                },
                "securityVersions": {
                    "virtioNetBluefield": {
                        "exposure": "live",
                        "status": "pass",
                        "detail": "The BlueField firmware meets the security minimum.",
                    }
                },
            }
        }

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        self.assertEqual(by_key["security.januscape.status"].status, "warning")
        self.assertEqual(
            by_key["security.januscape.status"].assessment,
            "Nested virtualization prerequisites are exposed",
        )
        self.assertEqual(
            by_key["securityVersions.virtioNetBluefield.exposure"].status,
            "pass",
        )
        self.assertEqual(
            by_key["securityVersions.virtioNetBluefield.exposure"].assessment,
            "The BlueField VIRTIO-Net controller is active. Its separate firmware status determines whether it meets the security minimum.",
        )

    def test_evaluate_filters_a_category(self) -> None:
        checks = audit_report.evaluate(audit_values(), RUNTIME_ROOT, category="hardware")

        self.assertEqual(
            [check.key for check in checks], ["hbm_memory_exposure.status"]
        )

    def test_standalone_marks_scale_out_checks_as_skipped(self) -> None:
        values = {
            "cluster": {"orchestrator": "standalone"},
            "audit_data": {},
        }

        checks = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        scale_out_keys = {
            "securityVersions.connectxFirmware.status",
            "securityVersions.virtioNetBluefield.status",
            "securityVersions.virtioNetBluefield.exposure",
            "securityVersions.dpuHostIsolation.status",
            "gpus.gpuDirectRdmaPath",
            "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy",
            "networking.hcaNamingValid",
            "ufm-profile",
        }
        self.assertTrue(scale_out_keys.issubset(checks))
        self.assertTrue(
            all(checks[key].status == audit_report.SKIPPED for key in scale_out_keys)
        )

    def test_security_profile_is_a_subset_of_the_standard_audit(self) -> None:
        full = audit_report.evaluate(audit_values(), RUNTIME_ROOT)
        security_checks = audit_report.evaluate(
            audit_values(), RUNTIME_ROOT, category="security"
        )

        full_by_key = {check.key: check for check in full}
        self.assertTrue(security_checks)
        self.assertTrue(
            all(
                check.category in {"versions", "isolation"}
                for check in security_checks
            )
        )
        self.assertTrue(
            audit_report._SECURITY_EXTENSION_IDS.issubset(
                {check.key for check in security_checks}
            )
        )
        self.assertEqual(
            {check.key: check for check in security_checks},
            {
                check.key: check
                for check in full_by_key.values()
                if check.category in {"versions", "isolation"}
            },
        )

    def test_default_lists_every_check_and_observed_versions(self) -> None:
        report = audit_report.format_report(
            audit_report.evaluate(audit_values(), RUNTIME_ROOT)
        )

        self.assertIn("FAIL", report)
        self.assertIn("WARNING", report)
        self.assertIn("Security Versions / NVIDIA Driver", report)
        self.assertIn(
            "Observed: observed version 580.126.09; minimum version 580.126.09",
            report,
        )
        self.assertIn("1 failed, 5 warnings, 2 passed, 0 skipped", report)
        self.assertIn("run 'cmax audit -vv'", report)

    def test_guarded_inconclusive_value_is_not_counted_as_pass(self) -> None:
        values = audit_values()
        values["audit_data"]["containers"]["workerCheckOk"] = False

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        # The guard-suppressed check stays visible as SKIPPED instead of
        # silently disappearing, and is never rendered as a pass.
        suppressed = by_key["containers.nvidiaContainerToolkit"]
        self.assertEqual(suppressed.status, audit_report.SKIPPED)
        self.assertIn("unverified", suppressed.assessment)
        self.assertEqual(by_key["containers.workerCheckOk"].status, "warning")

    def test_amd_hardware_renders_nvidia_only_check_as_not_applicable(self) -> None:
        # An AMD GPU suppresses the NVIDIA-specific toolkit finding because
        # the check does not apply to this hardware - not because the value
        # went unverified - and the skip wording must say so.
        values = audit_values()
        values["audit_data"]["containers"]["workerCheckOk"] = False
        values["audit_data"]["gpus"] = {"amd": {"present": True}}

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        suppressed = by_key["containers.nvidiaContainerToolkit"]
        self.assertEqual(suppressed.status, audit_report.SKIPPED)
        self.assertIn("Not applicable", suppressed.assessment)
        self.assertIn("AMD", suppressed.assessment)
        self.assertNotIn("unverified", suppressed.assessment)

    def test_amd_hardware_skips_nvidia_dcgm_and_nccl_checks(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "gpus": {"amd": {"present": True}},
                "healthChecks": {
                    "dcgmInstalled": False,
                    "dcgmSlurm": False,
                },
                "software": {"nccl": {"installed": False}},
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        for key in (
            "healthChecks.dcgmInstalled",
            "healthChecks.dcgmSlurm",
            "software.nccl.installed",
        ):
            with self.subTest(key=key):
                check = by_key[key]
                self.assertEqual(check.status, audit_report.SKIPPED)
                self.assertIn("Not applicable", check.assessment)
                self.assertIn("AMD", check.assessment)

    def test_absent_prerequisites_skip_dependent_checks(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "containers": {
                    "workerCheckOk": True,
                    "enroot": False,
                    "enrootImportWorks": False,
                },
                "gpus": {"amd": {"present": False}},
                "healthChecks": {
                    "dcgmInstalled": False,
                    "dcgmSlurm": False,
                },
                "software": {
                    "perf": {
                        "installed": False,
                        "perfEventParanoid": "unknown",
                        "kptrRestrict": "unknown",
                    }
                },
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        prerequisites = {
            "containers.enrootImportWorks": "containers.enroot",
            "healthChecks.dcgmSlurm": "healthChecks.dcgmInstalled",
            "software.perf.perfEventParanoid": "software.perf.installed",
            "software.perf.kptrRestrict": "software.perf.installed",
        }
        for key, prerequisite in prerequisites.items():
            with self.subTest(key=key):
                check = by_key[key]
                self.assertEqual(check.status, audit_report.SKIPPED)
                self.assertIn(prerequisite, check.assessment)

    def test_failed_worker_check_keeps_enroot_import_unverified(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "containers": {
                    "workerCheckOk": False,
                    "enroot": False,
                    "enrootImportWorks": False,
                }
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        check = by_key["containers.enrootImportWorks"]
        self.assertEqual(check.status, audit_report.SKIPPED)
        self.assertIn("unverified", check.assessment)
        self.assertNotIn("Not applicable", check.assessment)

    def test_configured_nvidia_runtime_renders_toolkit_as_pass(self) -> None:
        # docker info reporting the nvidia runtime is positive proof of a
        # working toolkit, so the suppressed "toolkit missing" value renders
        # as a pass naming that evidence, never as an unverified skip.
        values = audit_values()
        values["audit_data"]["containers"]["dockerNvidiaRuntimeConfigured"] = True

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        toolkit = by_key["containers.nvidiaContainerToolkit"]
        self.assertEqual(toolkit.status, audit_report.PASS)
        self.assertIn("nvidia runtime", toolkit.assessment)

    def test_modern_gpudirect_path_renders_loaded_peermem_as_pass(self) -> None:
        for modern_path in ("dmaBuf", "nvidiaOpen"):
            with self.subTest(modern_path=modern_path):
                path = {
                    "dmaBuf": False,
                    "nvidiaOpen": False,
                    "nvidiaPeermemLegacy": True,
                }
                path[modern_path] = True
                values = {
                    "cluster": {"orchestrator": "slurm"},
                    "audit_data": {"gpus": {"gpuDirectRdmaPath": path}},
                }

                checks = audit_report.evaluate(values, RUNTIME_ROOT)
                by_key = {check.key: check for check in checks}

                peermem = by_key["gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy"]
                self.assertEqual(peermem.status, audit_report.PASS)
                self.assertIn("modern GPUDirect path", peermem.assessment)
                self.assertNotIn("unverified", peermem.assessment)

    def test_attested_toolkit_renders_worker_check_gap_as_pass(self) -> None:
        # When the toolkit is positively attested, the suppressed
        # workerCheckOk=false value leaves nothing for the provider to
        # attest, so the row is a pass naming that corroborating evidence.
        values = audit_values()
        values["audit_data"]["containers"]["workerCheckOk"] = False
        values["audit_data"]["containers"]["nvidiaContainerToolkit"] = True

        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}

        worker_check = by_key["containers.workerCheckOk"]
        self.assertEqual(worker_check.status, audit_report.PASS)
        self.assertIn("positively attested", worker_check.assessment)

    def test_ncu_profiling_skip_separates_conclusive_absence_from_no_verdict(self) -> None:
        # Only a conclusively absent Nsight Compute makes the profiling check
        # inapplicable. When the install check never produced a verdict, the
        # false install value is an unfilled default, and the profiling row
        # must report unverified - mirroring the companion installation row -
        # instead of presenting missing evidence as confirmed absence.
        def ncu_values(access: str, kubernetes: bool = False) -> dict:
            values = audit_values()
            values["audit_data"]["software"] = {
                "ncu": {
                    "installed": False,
                    "profilingEnabled": False,
                    "hardwareCounterAccess": access,
                }
            }
            if kubernetes:
                values["audit_data"]["kubernetes"] = {}
            return values

        # A no-ncu verdict outside Kubernetes is conclusive absence.
        checks = audit_report.evaluate(ncu_values("no-ncu"), RUNTIME_ROOT)
        by_key = {check.key: check for check in checks}
        profiling = by_key["software.ncu.profilingEnabled"]
        self.assertEqual(profiling.status, audit_report.SKIPPED)
        self.assertIn("Not applicable", profiling.assessment)
        self.assertNotIn("unverified", profiling.assessment)

        # A failed check pod and an unfilled Kubernetes default both leave
        # the install verdict open, so both NCU rows stay unverified.
        for label, values in (
            ("pod-failed", ncu_values("pod-failed")),
            ("resource-unavailable", ncu_values("resource-unavailable")),
            ("kubernetes-default", ncu_values("no-ncu", kubernetes=True)),
        ):
            with self.subTest(case=label):
                checks = audit_report.evaluate(values, RUNTIME_ROOT)
                by_key = {check.key: check for check in checks}
                for key in (
                    "software.ncu.installed",
                    "software.ncu.profilingEnabled",
                ):
                    with self.subTest(case=label, key=key):
                        check = by_key[key]
                        self.assertEqual(check.status, audit_report.SKIPPED)
                        self.assertIn("unverified", check.assessment)
                        self.assertNotIn("Not applicable", check.assessment)

    def test_verbosity_levels_add_links_then_issue_details_and_remediation(self) -> None:
        values = audit_values()
        values["audit_data"]["securityVersions"]["cudaToolkit"] = {
            "status": "fail",
            "version": "12.8",
            "minimum": "13.1",
        }
        values["audit_data"]["gpus"] = {"cudaVersion": "13.0"}
        checks = audit_report.evaluate(values, RUNTIME_ROOT)
        one = audit_report.format_report(checks, verbosity=1)
        two = audit_report.format_report(checks, verbosity=2)
        three = audit_report.format_report(checks, verbosity=3)

        self.assertIn("Security Versions / NVIDIA Driver", one)
        self.assertIn(
            "Observed: observed version 580.126.09; minimum version 580.126.09",
            one,
        )
        self.assertIn("References:", one)
        self.assertIn(
            "https://www.clustermax.ai/minimum-versions#nvidiaDriver", one
        )
        self.assertNotIn("ClusterMAX audit guidance", one)
        self.assertIn("References:", two)
        self.assertNotIn("The observed value meets this check.", two)
        self.assertNotIn("Recommendation:", two)
        self.assertIn(
            "The NVIDIA driver meets the published security minimum.", three
        )
        self.assertIn(
            "observed version 12.8; minimum version 13.1; CUDA driver "
            "compatibility 13.0 (from nvidia-smi, not the installed toolkit)",
            one,
        )
        self.assertNotIn("Reproduce:", one)
        self.assertNotIn("Reproduce:", two)
        self.assertIn("Reproduce: on the audited worker: nvcc --version", three)
        self.assertIn(
            "nvidia-smi (driver CUDA compatibility only)", three
        )
        self.assertIn(
            "Reproduce: on the audited worker: nvidia-smi "
            "--query-gpu=driver_version --format=csv,noheader",
            three,
        )
        reproduce_lines = [
            line for line in three.splitlines() if "Reproduce:" in line
        ]
        self.assertTrue(reproduce_lines)
        self.assertNotIn("`", "\n".join(reproduce_lines))
        self.assertIn("Recommendation: Install NVIDIA Container Toolkit.", three)
        self.assertIn("References:", three)
        self.assertIn("https://", three)
        self.assertEqual(three.count("References:"), len(checks))
        passing_driver = next(
            check
            for check in checks
            if check.key == "securityVersions.nvidiaDriver.status"
        )
        self.assertEqual(
            passing_driver.references,
            (
                (
                    "ClusterMAX minimum versions",
                    "https://www.clustermax.ai/minimum-versions#nvidiaDriver",
                ),
                (
                    "ClusterMAX evaluation criteria",
                    "https://www.clustermax.ai/criteria#security-every-component-"
                    "patched-to-at-least-the-published-clustermax-minimum-version-"
                    "covering-the-gpu-driver-container-runtime-nic-and-dpu-firmware-"
                    "and-host-packages",
                ),
            ),
        )
        detailed_driver = audit_report.format_report(
            [passing_driver], verbosity=3, color=False
        )
        self.assertIn(
            "https://www.clustermax.ai/minimum-versions#nvidiaDriver",
            detailed_driver,
        )
        self.assertNotIn("github.com", detailed_driver)
        self.assertNotIn("nvd.nist.gov", detailed_driver)
        for status in (
            audit_report.PASS,
            audit_report.WARNING,
            audit_report.FAIL,
        ):
            with self.subTest(status=status):
                members = [check for check in checks if check.status == status]
                self.assertTrue(members)
                self.assertTrue(all(check.references for check in members))

    def test_fragnesia_vvv_includes_kernel_version_reproduction_command(self) -> None:
        values = {
            "audit_data": {
                "security": {
                    "guestKernel": {"running": "6.8.0-100-generic"},
                    "fragnesia": {
                        "status": "fail",
                        "ubuntuNoblePackageMinimum": "6.8.0-124.124",
                    },
                }
            }
        }
        fragnesia = next(
            check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
            if check.key == "security.fragnesia.status"
        )

        report = audit_report.format_report([fragnesia], verbosity=3, color=False)

        self.assertEqual(fragnesia.reproduce, "on the audited worker: `uname -r`")
        self.assertIn(
            "Observed: observed version 6.8.0-100-generic; minimum version "
            "6.8.0-124.124",
            report,
        )
        self.assertIn("Reproduce: on the audited worker: uname -r", report)

    def test_nvhpc_failure_reports_release_compilers_components_and_reproduction(self) -> None:
        values = {
            "cluster": {"orchestrator": "slurm"},
            "audit_data": {
                "software": {
                    "nvhpc": {
                        "status": "fail",
                        "version": "26.1",
                        "minimum": "26.3",
                        "current": "26.5",
                        "compilers": {
                            "nvc": "26.1",
                            "nvcxx": "26.1",
                            "nvfortran": "not-found",
                            "complete": False,
                        },
                        "components": {
                            "complete": False,
                            "missing": "hpcx,nvshmem",
                        },
                    }
                }
            },
        }
        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        self.assertNotIn("software.nvccInPath", by_key)
        self.assertNotIn("software.nvhpc.installed", by_key)
        check = by_key["software.nvhpc.status"]
        self.assertEqual(check.status, audit_report.FAIL)
        self.assertIn("observed version 26.1; minimum version 26.3", check.observed)
        self.assertIn("nvfortran=not-found", check.observed)
        self.assertIn("missing components hpcx,nvshmem", check.observed)
        self.assertIn("nvc++ --version", check.reproduce)

    def test_cuda_compatibility_ignores_absence_sentinels(self) -> None:
        for sentinel in (None, "", "unknown", "n/a", "N/A", "not_applicable"):
            with self.subTest(sentinel=sentinel):
                values = audit_values()
                values["audit_data"]["securityVersions"]["cudaToolkit"] = {
                    "status": "fail",
                    "version": "12.8",
                    "minimum": "13.1",
                }
                values["audit_data"]["gpus"] = {"cudaVersion": sentinel}

                checks = audit_report.evaluate(values, RUNTIME_ROOT)
                toolkit = next(
                    check
                    for check in checks
                    if check.key == "securityVersions.cudaToolkit.status"
                )

                self.assertEqual(
                    toolkit.observed,
                    "observed version 12.8; minimum version 13.1; "
                    "measured from the installed toolkit with nvcc",
                )

    def test_render_names_the_selected_category(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNTIME_ROOT) as tmp:
            values_path = Path(tmp) / "audit.values.json"
            values_path.write_text(json.dumps(audit_values()))

            report = audit_report.render(
                values_path,
                RUNTIME_ROOT,
                rules_root=RUNTIME_ROOT,
                verbosity=1,
                category="hardware",
            )

        self.assertIn("# ClusterMAX hardware audit report", report)
        self.assertIn("HBM Memory Exposure", report)
        self.assertNotIn("Security Versions / NVIDIA Driver", report)

    def test_raw_log_stays_available_without_entering_the_report(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNTIME_ROOT) as tmp:
            run_dir = Path(tmp)
            values_path = run_dir / "audit.values.json"
            values_path.write_text(json.dumps(audit_values()))
            (run_dir / "logs").mkdir()
            (run_dir / "logs" / "audit.out").write_text("tidied collector detail\n")

            raw_log = audit_report.find_raw_log(values_path)
            report = audit_report.render(values_path, RUNTIME_ROOT, verbosity=3)

        self.assertEqual(raw_log, run_dir / "logs" / "audit.out")
        self.assertIn("logs/audit.out", report)
        self.assertNotIn("tidied collector detail", report)

    def test_color_uses_one_style_for_each_report_status(self) -> None:
        checks = [
            audit_report.AuditCheck("pass", "Pass", "hardware", "pass", True),
            audit_report.AuditCheck(
                "warning", "Warning", "hardware", "warning", "warning"
            ),
            audit_report.AuditCheck("fail", "Fail", "hardware", "fail", False),
            audit_report.AuditCheck(
                "skipped", "Skipped", "hardware", "skipped", "not applicable"
            ),
        ]

        report = audit_report.format_report(checks, verbosity=1, color=True)

        self.assertIn("\033[32mPASS", report)
        self.assertIn("\033[33mWARNING", report)
        self.assertIn("\033[1;31mFAIL", report)
        self.assertIn("\033[2mSKIPPED", report)


class VersionDetailReportTests(unittest.TestCase):
    """Version checks show the evidence they graded, and absence skips.

    The reported defect: a real standalone run rendered
    ``observed version unknown unknown`` for ConnectX firmware (the
    collector's placeholder device printed as if it were a reading) and
    ``installed=false; version=unknown`` for a toolkit that is simply not
    there, and warned on checks whose subject the scan proved absent.
    """

    def evaluate_by_key(self, audit_data: dict) -> dict:
        return {
            check.key: check
            for check in audit_report.evaluate(
                {"audit_data": audit_data}, RUNTIME_ROOT
            )
        }

    def test_below_minimum_fail_always_names_observed_and_minimum(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "nvidiaDriver": {
                        "status": "fail",
                        "version": "570.100",
                        "minimum": "570.195.03",
                    }
                }
            }
        )

        check = by_key["securityVersions.nvidiaDriver.status"]
        self.assertEqual(check.status, audit_report.FAIL)
        self.assertEqual(
            check.observed,
            "observed version 570.100; minimum version 570.195.03",
        )

    def test_device_readings_are_labelled_per_device(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "connectxFirmware": {
                        "status": "fail",
                        "minimum": "28.4702",
                        "devices": [
                            {"device": "mlx5_0", "version": "28.33.1002"},
                            {"device": "mlx5_1", "version": "28.39.2048"},
                        ],
                    }
                }
            }
        )

        check = by_key["securityVersions.connectxFirmware.status"]
        self.assertEqual(check.status, audit_report.FAIL)
        self.assertEqual(
            check.observed,
            "device mlx5_0: version 28.33.1002, "
            "device mlx5_1: version 28.39.2048; minimum version 28.4702",
        )

    def test_placeholder_device_entries_never_print_unknown_unknown(self) -> None:
        # The collector pads an unreadable inventory with one entry whose
        # device and version are both "unknown". That is the real
        # 20260827-134338 run shape, and it rendered as the literal
        # "observed version unknown unknown".
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "connectxFirmware": {
                        "status": "unknown",
                        "minimum": "28.4702",
                        "devices": [{"device": "unknown", "version": "unknown"}],
                    }
                }
            }
        )

        check = by_key["securityVersions.connectxFirmware.status"]
        self.assertEqual(check.status, audit_report.WARNING)
        self.assertEqual(
            check.observed, "no readable device; minimum version 28.4702"
        )
        self.assertNotIn("unknown unknown", str(check.observed))

    def test_completed_empty_device_scan_skips_as_no_device_present(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "connectxFirmware": {
                        "status": "not_applicable",
                        "minimum": "28.4702",
                        "devices": [],
                        "detail": "No NVIDIA ConnectX or BlueField NIC is present",
                    }
                }
            }
        )

        check = by_key["securityVersions.connectxFirmware.status"]
        self.assertEqual(check.status, audit_report.SKIPPED)
        self.assertEqual(
            check.observed, "no device present; minimum version 28.4702"
        )
        self.assertEqual(
            check.assessment, "No NVIDIA ConnectX or BlueField NIC is present"
        )

    def test_missing_toolkit_observation_carries_no_version_noise(self) -> None:
        values = audit_values()
        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
        }

        check = by_key["containers.nvidiaContainerToolkit"]
        self.assertEqual(check.status, audit_report.FAIL)
        self.assertEqual(check.observed, "installed=false")

    def test_gpu_absent_driver_record_skips_with_the_collector_detail(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "nvidiaDriver": {
                        "status": "not_applicable",
                        "version": "not-present",
                        "minimum": "NVIDIA GPUs only",
                        "detail": (
                            "No NVIDIA GPU is present in the completed "
                            "device scan, so the NVIDIA driver minimum does "
                            "not apply to this target"
                        ),
                    }
                }
            }
        )

        check = by_key["securityVersions.nvidiaDriver.status"]
        self.assertEqual(check.status, audit_report.SKIPPED)
        self.assertEqual(
            check.observed,
            "observed version not-present; minimum version NVIDIA GPUs only",
        )
        self.assertIn("No NVIDIA GPU is present", check.assessment)

    def test_dependent_check_skips_only_on_a_positively_false_prerequisite(
        self,
    ) -> None:
        # installed=False: there is no ncu whose profiling permission could be
        # graded, so the dependent check is skipped and names its prerequisite.
        # installed=True or absent with an unknown reading stays a WARNING,
        # because "present but could not verify" is a genuine attestation ask.
        cases = (
            (False, audit_report.SKIPPED),
            (True, audit_report.WARNING),
            (None, audit_report.WARNING),
        )
        for installed, expected in cases:
            with self.subTest(installed=installed):
                ncu: dict = {"profilingEnabled": "unknown"}
                if installed is not None:
                    ncu["installed"] = installed
                by_key = self.evaluate_by_key({"software": {"ncu": ncu}})

                check = by_key["software.ncu.profilingEnabled"]
                self.assertEqual(check.status, expected)
                if expected == audit_report.SKIPPED:
                    self.assertIn("software.ncu.installed", check.assessment)

    def test_dependent_check_skips_only_on_a_conclusive_ncu_absence(self) -> None:
        # Kubernetes initializes software.ncu.installed to false before the
        # GPU check pod runs, so installed=False beside an inconclusive
        # counter-access result is an unfilled default, not a determination.
        # Those runs must keep the WARNING; only a conclusive absence skips.
        cases = (
            ("pod-failed", None, audit_report.WARNING),
            ("compile-failed", None, audit_report.WARNING),
            ("resource-unavailable", None, audit_report.WARNING),
            ("untested", None, audit_report.WARNING),
            ("unknown", None, audit_report.WARNING),
            # "no-ncu" from a Kubernetes run can be the pre-initialized
            # default of a check pod that never reported, so it is only
            # conclusive outside Kubernetes.
            ("no-ncu", {"harness": "k8s"}, audit_report.WARNING),
            ("no-ncu", None, audit_report.SKIPPED),
            # A real counter-access verdict proves the check ran to
            # completion, so its absence claim stands.
            ("disabled", {"harness": "k8s"}, audit_report.SKIPPED),
        )
        for access, kubernetes, expected in cases:
            with self.subTest(access=access, kubernetes=kubernetes is not None):
                audit: dict = {
                    "software": {
                        "ncu": {
                            "installed": False,
                            "profilingEnabled": "unknown",
                            "hardwareCounterAccess": access,
                        }
                    }
                }
                if kubernetes is not None:
                    audit["kubernetes"] = kubernetes
                by_key = self.evaluate_by_key(audit)

                check = by_key["software.ncu.profilingEnabled"]
                self.assertEqual(check.status, expected)
                if expected == audit_report.SKIPPED:
                    self.assertIn("software.ncu.installed", check.assessment)

    def test_unverified_kubernetes_gpu_checks_include_rerun_instructions(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "kubernetes": {"version": "v1.36.1"},
                "software": {
                    "cudaVisibleDevicesStatus": "unknown",
                    "ncu": {
                        "installed": False,
                        "profilingEnabled": "unknown",
                        "hardwareCounterAccess": "pod-failed",
                    },
                },
                "securityVersions": {
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                    },
                    "dpuHostIsolation": {
                        "status": "unknown",
                        "bluefieldPresent": None,
                        "scanComplete": False,
                    },
                },
            },
        )

        for key in (
            "software.cudaVisibleDevicesStatus",
            "software.ncu.profilingEnabled",
            "securityVersions.virtioNetBluefield.exposure",
        ):
            check = by_key[key]
            self.assertEqual(check.status, audit_report.WARNING)
            self.assertTrue(check.recommendation)
            self.assertTrue(check.reproduce)
        bluefield = by_key["securityVersions.virtioNetBluefield.exposure"]
        self.assertIn("mlxconfig", bluefield.reproduce)
        self.assertIn("virtnet version", bluefield.reproduce)

    def test_dpu_and_perf_warnings_include_reproduction_commands(self) -> None:
        by_key = self.evaluate_by_key(
            {
                "securityVersions": {
                    "dpuHostIsolation": {
                        "status": "fail",
                        "bluefieldPresent": True,
                        "detail": "INTERNAL_CPU_RSHIM=0 permits host access.",
                    }
                },
                "software": {
                    "perf": {
                        "installed": True,
                        "perfEventParanoid": "4",
                        "kptrRestrict": "1",
                    }
                },
            },
        )

        expected_commands = {
            "securityVersions.dpuHostIsolation.status": "mlxconfig",
            "software.perf.perfEventParanoid": "sysctl kernel.perf_event_paranoid",
            "software.perf.kptrRestrict": "sysctl kernel.kptr_restrict",
        }
        for key, command in expected_commands.items():
            check = by_key[key]
            self.assertEqual(check.status, audit_report.WARNING)
            self.assertIn(command, check.reproduce)
            self.assertNotEqual(
                check.recommendation,
                "Correct the reported configuration, and run the audit again.",
            )

    def test_live_kubernetes_findings_include_verification_steps(self) -> None:
        values = {
            "cluster": {"orchestrator": "k8s"},
            "audit_data": {
                "gpus": {"gdrcopy": {"installed": False}},
                "kubelet_cpu_manager_policy": {
                    "status": "warning",
                    "message": "kubelet CPU Manager policy is none",
                },
                "networking": {"topologyConfigured": False},
                "securityVersions": {
                    "connectxFirmware": {
                        "status": "fail",
                        "version": "28.43.2026",
                        "minimum": "43.8002",
                    },
                    "dcgmExporter": {
                        "status": "fail",
                        "version": "4.8.0",
                        "minimum": "4.8.2",
                    },
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                    },
                    "dpuHostIsolation": {
                        "status": "unknown",
                        "bluefieldPresent": None,
                        "scanComplete": False,
                    },
                },
                "security": {
                    "ufmSecuredBareMetalCloud": {
                        "applicable": True,
                        "status": "manual",
                    },
                    "nvidiaMay2026": {"nvlinkExposed": True},
                    "pciePassthrough": {"hostVerificationRequired": True},
                },
            },
        }

        by_key = {
            check.key: check
            for check in audit_report.evaluate(values, RUNTIME_ROOT, harness="k8s")
        }
        expected = {
            "gpus.gdrcopy.installed": "libgdrapi",
            "kubelet_cpu_manager_policy.status": "cpu_manager_state",
            "networking.topologyConfigured": "kubectl get nodes",
            "securityVersions.connectxFirmware.status": "fw_ver",
            "securityVersions.dcgmExporter.status": "dcgm-exporter",
            "securityVersions.virtioNetBluefield.status": "virtnet version",
            "ufm-profile": "provider-side verification",
            "nvlink-boundary": "nvidia-smi topo -m",
            "pcie-passthrough": "iommu_groups",
        }
        for key, evidence in expected.items():
            with self.subTest(key=key):
                self.assertIn(key, by_key)
                self.assertIn(evidence, by_key[key].reproduce)

    def test_pcie_passthrough_is_skipped_for_a_vm_target(self) -> None:
        values = {
            "cluster": {"orchestrator": "standalone", "environment": "vm"},
            "audit_data": {
                "security": {
                    "pciePassthrough": {"hostVerificationRequired": True}
                }
            },
        }

        vm_check = next(
            check
            for check in audit_report.evaluate(
                values,
                RUNTIME_ROOT,
                harness="standalone",
                environment="vm",
            )
            if check.key == "pcie-passthrough"
        )
        self.assertEqual(vm_check.status, audit_report.SKIPPED)
        self.assertEqual(vm_check.observed, "running in a VM")
        self.assertEqual(
            vm_check.assessment,
            "Skipped because this audit is running in a VM; PCIe passthrough "
            "isolation is controlled by the physical host.",
        )
        self.assertEqual(vm_check.recommendation, "")
        self.assertEqual(vm_check.reproduce, "")

        reviewed_check = next(
            check
            for check in audit_report.evaluate(values, RUNTIME_ROOT)
            if check.key == "pcie-passthrough"
        )
        self.assertEqual(reviewed_check.status, audit_report.SKIPPED)

        report = audit_report.format_report([vm_check], verbosity=3)
        self.assertIn("SKIPPED  PCIe passthrough isolation", report)
        self.assertIn("Observed: running in a VM", report)
        self.assertNotIn("Reproduce:", report)
        self.assertNotIn("Recommendation:", report)

        bare_metal_check = next(
            check
            for check in audit_report.evaluate(
                values,
                RUNTIME_ROOT,
                harness="standalone",
                environment="bare-metal",
            )
            if check.key == "pcie-passthrough"
        )
        self.assertEqual(bare_metal_check.status, audit_report.WARNING)
        self.assertTrue(bare_metal_check.reproduce)


if __name__ == "__main__":
    unittest.main()
