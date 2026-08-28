#!/usr/bin/env python3
"""Unit tests for the audit immediate findings detector."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


FINDINGS_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "audit_findings.py"
)


def load_findings_module():
    name = "audit_findings_under_test"
    spec = importlib.util.spec_from_file_location(name, FINDINGS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register before exec so the @dataclass decorator can resolve the module's
    # annotations via sys.modules (it fails with NoneType otherwise).
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit_findings = load_findings_module()


def titles(findings) -> set[str]:
    return {f.title for f in findings}


def by_key(findings) -> dict[str, object]:
    return {f.key: f for f in findings}


class DetectFindingsTests(unittest.TestCase):
    def test_clean_cluster_has_zero_findings(self) -> None:
        audit_data = {
            "securityVersions": {
                "nvidiaDriver": {"status": "pass"},
                "nvidiaContainerToolkit": {"status": "pass"},
                "docker": {"status": "pass"},
                "runc": {"status": "pass"},
                "connectxFirmware": {"status": "pass"},
            },
            "containers": {
                "nvidiaContainerToolkit": True,
                "nvidiaContainerToolkitVersionOk": True,
                "dockerVersionOk": True,
                "singularity": True,
                "pyxisRuntimeWorks": True,
            },
            "software": {
                "nvccInPath": True,
                "nvhpc": {"installed": True},
                "ncu": {"installed": True},
            },
            "gpus": {
                "gdrcopy": {"installed": True},
                "gpuDirectRdmaPath": {
                    "dmaBuf": True,
                    "nvidiaOpen": True,
                    "nvidiaPeermemLegacy": False,
                },
            },
            "gpu_controls": {"vboost": {"allowed": True}},
            "hbm_memory_exposure": {"status": "pass"},
            "kubelet_cpu_manager_policy": {"status": "pass"},
            "networking": {"topologyConfigured": True, "hcaNamingValid": True},
            "healthChecks": {
                "nhcInstalled": True,
                "monitoringStack": {
                    "prometheus": True,
                    "dcgmExporter": True,
                    "grafana": True,
                },
            },
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        self.assertEqual(findings, [])

    def test_standalone_values_exclude_scheduler_findings(self) -> None:
        values = {
            "cluster": {"orchestrator": "standalone"},
            "audit_data": {
                "containers": {"pyxisRuntimeWorks": False},
                "kubelet_cpu_manager_policy": {"status": "unknown"},
                "nccl_topo_file": {"status": "fail"},
                "nccl_ib_qps": {"status": "warning"},
                "networking": {"topologyConfigured": False},
                "healthChecks": {"nhcInstalled": False},
            },
        }

        self.assertEqual(audit_findings.detect_findings(values), [])

    def test_container_toolkit_false_is_flagged_missing(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"containers": {"nvidiaContainerToolkit": False}}}
        )
        keyed = by_key(findings)
        self.assertIn("containers.nvidiaContainerToolkit", keyed)
        finding = keyed["containers.nvidiaContainerToolkit"]
        self.assertEqual(finding.severity, audit_findings.MISSING)
        self.assertEqual(finding.value, False)
        self.assertEqual(finding.title, "NVIDIA Container Toolkit not installed")

    def test_minimum_version_failures_and_hidden_host_versions_are_flagged(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "securityVersions": {
                        "nvidiaDriver": {"status": "fail"},
                        "nvidiaContainerToolkit": {"status": "unknown"},
                        "cudaToolkit": {"status": "fail"},
                        "docker": {"status": "unknown"},
                        "runc": {"status": "unknown"},
                        "connectxFirmware": {
                            "status": "fail",
                            "minimum": "32.1908",
                            "devices": [
                                {"status": "fail", "version": "32.43.2402"},
                                {"status": "pass", "version": "40.47.2526"},
                            ],
                        },
                    }
                }
            }
        )
        keyed = by_key(findings)
        self.assertEqual(
            keyed["securityVersions.nvidiaDriver.status"].severity,
            audit_findings.VERSION,
        )
        self.assertEqual(
            keyed["securityVersions.runc.status"].severity,
            audit_findings.CONFIG,
        )
        self.assertIn(
            "Host NVIDIA Container Toolkit version requires provider attestation",
            titles(findings),
        )
        self.assertIn("Host Docker version requires provider attestation", titles(findings))
        self.assertIn("CUDA Toolkit below security minimum", titles(findings))
        connectx = keyed["securityVersions.connectxFirmware.status"]
        self.assertEqual(connectx.severity, audit_findings.VERSION)
        self.assertEqual(connectx.detected, "ConnectX firmware 32.43.2402")

        unknown = audit_findings.detect_findings(
            {
                "audit_data": {
                    "securityVersions": {
                        "connectxFirmware": {"status": "fail"}
                    }
                }
            }
        )
        connectx_unknown = by_key(unknown)["securityVersions.connectxFirmware.status"]
        self.assertEqual(connectx_unknown.severity, audit_findings.CONFIG)
        self.assertEqual(
            connectx_unknown.detected,
            "The collector could not verify this check. Treat this value as unverified.",
        )

    def test_unknown_docker_names_server_evidence_and_containerd(self) -> None:
        finding = by_key(
            audit_findings.detect_findings(
                {
                    "audit_data": {
                        "containers": {"dockerVersion": "29.7.2"},
                        "securityVersions": {
                            "docker": {
                                "status": "unknown",
                                "minimum": "29.7.0",
                            }
                        },
                    }
                }
            )
        )["securityVersions.docker.status"]

        self.assertIn("Docker client is 29.7.2", finding.detected)
        self.assertIn("Docker Engine", finding.recommendation)
        self.assertIn("containerd", finding.recommendation)
        self.assertNotIn("29.7.0 or later", finding.recommendation)

    def test_kubernetes_configuration_findings_have_specific_actions(self) -> None:
        findings = by_key(
            audit_findings.detect_findings(
                {
                    "cluster": {"orchestrator": "k8s"},
                    "audit_data": {
                        "kubelet_cpu_manager_policy": {
                            "status": "warning",
                            "message": "kubelet CPU Manager policy is none",
                        },
                        "networking": {"topologyConfigured": False},
                    },
                }
            )
        )

        cpu = findings["kubelet_cpu_manager_policy.status"]
        self.assertIn("policy is none", cpu.detected)
        self.assertIn("policy to static", cpu.recommendation)
        topology = findings["networking.topologyConfigured"]
        self.assertIn("block, rack, and host", topology.recommendation)
        self.assertIn("distributed GPU jobs", topology.recommendation)

    def test_worker_check_unavailable_is_inconclusive_not_missing(self) -> None:
        # Crusoe B300 case: the srun worker check could not schedule, so the
        # container.* booleans hold their stale `false` defaults. That is
        # inconclusive, not "not installed": no MISSING/VERSION finding should
        # fire, only a CONFIG attestation note keyed on workerCheckOk.
        audit_data = {
            "containers": {
                "workerCheckOk": False,
                "docker": False,
                "nvidiaContainerToolkit": False,
                "dockerNvidiaRuntimeConfigured": False,
            }
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        keyed = by_key(findings)
        self.assertNotIn("containers.nvidiaContainerToolkit", keyed)
        self.assertNotIn(
            "NVIDIA Container Toolkit not installed", titles(findings)
        )
        self.assertIn("containers.workerCheckOk", keyed)
        note = keyed["containers.workerCheckOk"]
        self.assertEqual(note.severity, audit_findings.CONFIG)
        self.assertIn("attestation", note.title.lower())

    def test_worker_check_present_with_working_runtime_has_no_false_missing(self) -> None:
        # Jordan's worker-node evidence (node np-b8c3dcfa-2): docker reachable,
        # `docker info` shows the nvidia runtime, enroot works. The check ran and
        # everything passed, so there must be zero container findings.
        audit_data = {
            "containers": {
                "workerCheckOk": True,
                "docker": True,
                "dockerVersionOk": True,
                "dockerNvidiaRuntimeConfigured": True,
                "nvidiaContainerToolkit": True,
                "nvidiaContainerToolkitVersionOk": True,
                "enroot": True,
                "enrootImportWorks": True,
            }
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        container_keys = {k for k in by_key(findings) if k.startswith("containers.")}
        self.assertEqual(container_keys, set())

    def test_configured_nvidia_runtime_suppresses_missing_toolkit(self) -> None:
        # A working `docker info` nvidia runtime is proof the toolkit works, even
        # if the package/CLI check reported the toolkit flag false. It must not
        # surface as "toolkit not installed", and needs no attestation note.
        audit_data = {
            "containers": {
                "workerCheckOk": True,
                "nvidiaContainerToolkit": False,
                "dockerNvidiaRuntimeConfigured": True,
            }
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        keyed = by_key(findings)
        self.assertNotIn("containers.nvidiaContainerToolkit", keyed)
        self.assertNotIn("containers.workerCheckOk", keyed)

    def test_worker_check_ran_and_toolkit_absent_still_flags_missing(self) -> None:
        # When the check DID run on a worker and the toolkit is genuinely absent
        # (no package, no nvidia runtime), the MISSING finding must still fire.
        audit_data = {
            "containers": {
                "workerCheckOk": True,
                "nvidiaContainerToolkit": False,
                "dockerNvidiaRuntimeConfigured": False,
            }
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        keyed = by_key(findings)
        self.assertIn("containers.nvidiaContainerToolkit", keyed)
        self.assertEqual(
            keyed["containers.nvidiaContainerToolkit"].severity,
            audit_findings.MISSING,
        )

    def test_missing_pyxis_cli_is_flagged_as_config(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"containers": {"pyxisRuntimeWorks": False}}}
        )
        keyed = by_key(findings)
        self.assertIn("containers.pyxisRuntimeWorks", keyed)
        finding = keyed["containers.pyxisRuntimeWorks"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertEqual(
            finding.title, "Slurm does not expose the Pyxis command-line options"
        )
        self.assertIn(
            "https://github.com/NVIDIA/pyxis#installation",
            finding.recommendation,
        )

    def test_incomplete_nvhpc_sdk_is_flagged(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"software": {"nvhpc": {"status": "fail"}}}}
        )
        self.assertIn(
            "NVIDIA HPC SDK is incomplete or outside the supported release window",
            titles(findings),
        )

    def test_ncu_check_failure_does_not_turn_false_default_into_finding(self) -> None:
        for access in ("pod-failed", "compile-failed", "untested", "unknown"):
            with self.subTest(access=access):
                findings = audit_findings.detect_findings(
                    {
                        "audit_data": {
                            "software": {
                                "ncu": {
                                    "installed": False,
                                    "profilingEnabled": False,
                                    "hardwareCounterAccess": access,
                                }
                            }
                        }
                    }
                )
                self.assertNotIn("Nsight Compute (ncu) not installed", titles(findings))

    def test_ncu_profiling_requires_a_confirmed_permission_result(self) -> None:
        unknown = audit_findings.detect_findings(
            {
                "audit_data": {
                    "software": {
                        "ncu": {"installed": True, "profilingEnabled": "unknown"}
                    }
                }
            }
        )
        restricted = audit_findings.detect_findings(
            {
                "audit_data": {
                    "software": {
                        "ncu": {"installed": True, "profilingEnabled": False}
                    }
                }
            }
        )

        self.assertNotIn(
            "Nsight Compute profiling is not enabled for the audited user",
            titles(unknown),
        )
        self.assertIn(
            "Nsight Compute profiling is not enabled for the audited user",
            titles(restricted),
        )

    def test_ncu_no_ncu_result_is_confirmed_absence(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "software": {
                        "ncu": {
                            "installed": False,
                            "profilingEnabled": False,
                            "hardwareCounterAccess": "no-ncu",
                        }
                    }
                }
            }
        )
        self.assertIn("Nsight Compute (ncu) not installed", titles(findings))

    def test_ncu_k8s_check_image_missing_ncu_is_inconclusive(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "kubernetes": {"version": "v1.36.2"},
                    "software": {
                        "ncu": {
                            "installed": False,
                            "profilingEnabled": False,
                            "hardwareCounterAccess": "no-ncu",
                        }
                    },
                }
            }
        )
        self.assertNotIn("Nsight Compute (ncu) not installed", titles(findings))

    def test_ncu_confirmed_absent_still_has_finding(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"software": {"ncu": {"installed": False}}}}
        )
        self.assertIn("Nsight Compute (ncu) not installed", titles(findings))

    def test_amd_cluster_suppresses_nvidia_only_findings(self) -> None:
        # TensorWave MI355X incident, 2026-07-31: the compatibility fields keep
        # their NVIDIA-shaped false defaults even though the AMD inventory is
        # positive. Only vendor-neutral findings must remain.
        audit_data = {
            "gpus": {
                "amd": {"present": True},
                "gdrcopy": {"installed": False},
                "gpuDirectRdmaPath": {
                    "dmaBuf": False,
                    "nvidiaOpen": False,
                    "nvidiaPeermemLegacy": False,
                },
            },
            "containers": {
                "workerCheckOk": True,
                "nvidiaContainerToolkit": False,
            },
            "software": {
                "nvccInPath": False,
                "nvhpc": {"installed": False},
                "ncu": {"installed": False},
            },
            "gpu_controls": {
                "vboost": {"allowed": False, "status": "denied"},
            },
            "securityVersions": {
                "nvidiaDriver": {"status": "fail"},
                "nvidiaContainerToolkit": {"status": "unknown"},
                "cudaToolkit": {"status": "fail"},
                "docker": {"status": "fail"},
            },
            "healthChecks": {
                "monitoringStack": {
                    "dcgmExporter": False,
                },
            },
        }

        findings = audit_findings.detect_findings({"audit_data": audit_data})

        self.assertEqual(
            set(by_key(findings)),
            {"securityVersions.docker.status"},
        )

    def test_legacy_peermem_true_is_flagged_config(self) -> None:
        # This rule fires on TRUE (legacy path active), unlike the _is_false rules.
        findings = audit_findings.detect_findings(
            {"audit_data": {"gpus": {"gpuDirectRdmaPath": {"nvidiaPeermemLegacy": True}}}}
        )
        keyed = by_key(findings)
        self.assertIn("gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy", keyed)
        self.assertEqual(
            keyed["gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy"].severity,
            audit_findings.CONFIG,
        )

    def test_legacy_peermem_not_flagged_when_dmabuf_also_present(self) -> None:
        # Both paths coexist safely: the driver and NCCL select dma_buf
        # automatically when it is available, so a loaded nvidia_peermem
        # module alongside dma_buf must not be penalized.
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": True,
                            "nvidiaOpen": False,
                            "nvidiaPeermemLegacy": True,
                        }
                    }
                }
            }
        )
        self.assertNotIn(
            "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy", by_key(findings)
        )

    def test_legacy_peermem_not_flagged_when_nvidia_open_present(self) -> None:
        # nvidia-open implies dma_buf capability even when the narrow sysfs
        # probe misses it, so peermem loaded alongside is likewise fine.
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": False,
                            "nvidiaOpen": True,
                            "nvidiaPeermemLegacy": True,
                        }
                    }
                }
            }
        )
        self.assertNotIn(
            "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy", by_key(findings)
        )

    def test_legacy_peermem_still_flagged_when_only_path(self) -> None:
        # When peermem is the ONLY GPUDirect path, the legacy finding stands.
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": False,
                            "nvidiaOpen": False,
                            "nvidiaPeermemLegacy": True,
                        }
                    }
                }
            }
        )
        keyed = by_key(findings)
        self.assertIn("gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy", keyed)
        self.assertEqual(
            keyed["gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy"].severity,
            audit_findings.CONFIG,
        )

    def test_nvidia_open_is_accepted_when_narrow_dmabuf_check_is_false(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": False,
                            "nvidiaOpen": True,
                            "nvidiaPeermemLegacy": False,
                        }
                    }
                }
            }
        )
        self.assertNotIn("gpus.gpuDirectRdmaPath", by_key(findings))

    def test_absent_modern_gpudirect_path_is_flagged_config(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": False,
                            "nvidiaOpen": False,
                            "nvidiaPeermemLegacy": False,
                        }
                    }
                }
            }
        )
        keyed = by_key(findings)
        self.assertIn("gpus.gpuDirectRdmaPath", keyed)
        self.assertEqual(
            keyed["gpus.gpuDirectRdmaPath"].severity,
            audit_findings.CONFIG,
        )

    def test_standalone_does_not_create_scale_out_findings(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "cluster": {"orchestrator": "standalone"},
                "audit_data": {
                    "gpus": {
                        "gpuDirectRdmaPath": {
                            "dmaBuf": False,
                            "nvidiaOpen": False,
                            "nvidiaPeermemLegacy": True,
                        }
                    },
                    "networking": {"hcaNamingValid": False},
                    "securityVersions": {
                        "connectxFirmware": {"status": "fail"},
                        "virtioNetBluefield": {
                            "status": "fail",
                            "exposure": "latent",
                        },
                        "dpuHostIsolation": {"status": "fail"},
                    },
                },
            }
        )

        scale_out_keys = {
            "gpus.gpuDirectRdmaPath",
            "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy",
            "networking.hcaNamingValid",
            "securityVersions.connectxFirmware.status",
            "securityVersions.virtioNetBluefield.status",
            "securityVersions.virtioNetBluefield.exposure",
            "securityVersions.dpuHostIsolation.status",
        }
        self.assertTrue(scale_out_keys.isdisjoint(by_key(findings)))

    def test_hbm_exposure_fail_is_flagged_config(self) -> None:
        # A real HBM exposure failure must land in the AUDIT FINDINGS block,
        # not only in the mid-run stderr WARNING from run_checks.py.
        findings = audit_findings.detect_findings(
            {"audit_data": {"hbm_memory_exposure": {"status": "fail"}}}
        )
        keyed = by_key(findings)
        self.assertIn("hbm_memory_exposure.status", keyed)
        finding = keyed["hbm_memory_exposure.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertEqual(
            finding.title, "GPU HBM exposed as ordinary OS-managed system memory"
        )
        self.assertEqual(finding.value, "fail")

    def test_hbm_exposure_warning_is_flagged_advisory(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"hbm_memory_exposure": {"status": "warning"}}}
        )
        keyed = by_key(findings)
        self.assertIn("hbm_memory_exposure.status", keyed)
        finding = keyed["hbm_memory_exposure.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("advisory warning", finding.title)

    def test_hbm_exposure_pass_and_not_applicable_do_not_flag(self) -> None:
        for status in ("pass", "not_applicable", "unknown"):
            findings = audit_findings.detect_findings(
                {"audit_data": {"hbm_memory_exposure": {"status": status}}}
            )
            self.assertEqual(findings, [], f"status={status} must not flag")

    def test_cpu_manager_warning_is_a_separate_advisory(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "hbm_memory_exposure": {"status": "not_applicable"},
                    "kubelet_cpu_manager_policy": {"status": "warning"},
                }
            }
        )
        keyed = by_key(findings)

        self.assertNotIn("hbm_memory_exposure.status", keyed)
        self.assertIn("kubelet_cpu_manager_policy.status", keyed)
        finding = keyed["kubelet_cpu_manager_policy.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("advisory", finding.title.lower())

    def test_cpu_manager_pass_and_not_applicable_do_not_flag(self) -> None:
        for status in ("pass", "not_applicable"):
            findings = audit_findings.detect_findings(
                {"audit_data": {"kubelet_cpu_manager_policy": {"status": status}}}
            )
            self.assertEqual(findings, [], f"status={status} must not flag")

    def test_cpu_manager_unknown_reports_unavailable_policy_evidence(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"kubelet_cpu_manager_policy": {"status": "unknown"}}}
        )
        keyed = by_key(findings)

        self.assertIn("kubelet_cpu_manager_policy.status", keyed)
        finding = keyed["kubelet_cpu_manager_policy.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("could not be checked", finding.title.lower())

    def test_vboost_unavailable_check_does_not_flag_denial(self) -> None:
        # GCore Soperator login node: nvidia-smi is a stub binary, so every
        # per-node result is nvidia_smi_error and the check aggregates to
        # status "unavailable" with allowed=false. That is missing data, not a
        # provider denial; the "not allowed" finding must stay silent.
        audit_data = {
            "gpu_controls": {
                "vboost": {
                    "checked": True,
                    "allowed": False,
                    "status": "unavailable",
                }
            }
        }
        findings = audit_findings.detect_findings({"audit_data": audit_data})
        self.assertNotIn("gpu_controls.vboost.allowed", by_key(findings))

    def test_vboost_denied_on_b300_family_does_not_flag(self) -> None:
        # B300 and GB300 expose no boost slider at all: nvidia-smi returns
        # "Invalid Argument" on every node regardless of provider policy, so
        # allowed=false is a hardware capability gap, not a denial.
        for model in (
            "NVIDIA-B300-SXM6-AC",
            "NVIDIA B300",
            "NVIDIA-GB300",
            "GB300 NVL72",
            "nvidia-gb300",
        ):
            audit_data = {
                "gpus": {"model": model},
                "gpu_controls": {
                    "vboost": {
                        "checked": True,
                        "allowed": False,
                        "status": "denied",
                    }
                },
            }
            findings = audit_findings.detect_findings({"audit_data": audit_data})
            self.assertNotIn(
                "gpu_controls.vboost.allowed",
                by_key(findings),
                f"model={model} must not flag",
            )

    def test_vboost_denied_on_slider_capable_gpu_still_flags(self) -> None:
        # GPUs that do implement the boost slider (e.g. B200, H100) must keep
        # flagging a denial; the B300-family guard must not silence them.
        for model in ("NVIDIA-B200", "NVIDIA-H100-80GB-HBM3"):
            audit_data = {
                "gpus": {"model": model},
                "gpu_controls": {
                    "vboost": {
                        "checked": True,
                        "allowed": False,
                        "status": "denied",
                    }
                },
            }
            keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
            self.assertIn("gpu_controls.vboost.allowed", keyed, f"model={model} must flag")

    def test_vboost_denied_still_flags(self) -> None:
        # A genuine denial (the control was exercised and refused) must keep
        # firing even with the unavailable guard in place.
        audit_data = {
            "gpu_controls": {
                "vboost": {
                    "checked": True,
                    "allowed": False,
                    "status": "denied",
                }
            }
        }
        keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
        self.assertIn("gpu_controls.vboost.allowed", keyed)
        self.assertEqual(
            keyed["gpu_controls.vboost.allowed"].severity,
            audit_findings.CONFIG,
        )

    def test_absent_key_does_not_flag(self) -> None:
        # An audit that simply did not check a component should not generate
        # noise: rules only fire when their key is present.
        findings = audit_findings.detect_findings({"audit_data": {}})
        self.assertEqual(findings, [])

    def test_verifiable_hypervisor_security_bulletins_surface_findings(self) -> None:
        audit_data = {
            "security": {
                "januscape": {
                    "exposed": True,
                    "status": "host-patch-required",
                },
            }
        }
        keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
        self.assertEqual(
            set(keyed),
            {
                "security.januscape.status",
            },
        )
        self.assertEqual(
            keyed["security.januscape.status"].detected,
            "Nested virtualization prerequisites are exposed",
        )

    def test_unknown_januscape_exposure_requires_verification(self) -> None:
        audit_data = {
            "security": {
                "januscape": {"exposed": "unknown", "status": "unknown"},
            }
        }
        keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
        self.assertIn("security.januscape.status", keyed)
        self.assertEqual(
            keyed["security.januscape.status"].severity,
            audit_findings.CONFIG,
        )
        self.assertNotIn("security.januscape.exposed", keyed)

    def test_newer_installed_kernel_requires_reboot(self) -> None:
        audit_data = {
            "security": {
                "guestKernel": {
                    "running": "6.8.0-58-generic",
                    "newestInstalled": "6.8.0-136-generic",
                    "newerInstalled": True,
                    "rebootRequired": True,
                }
            }
        }
        keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
        self.assertIn("security.guestKernel.newerInstalled", keyed)
        self.assertEqual(
            keyed["security.guestKernel.newerInstalled"].severity,
            audit_findings.VERSION,
        )

    def test_fragnesia_exposed_kernel_is_a_version_finding(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"security": {"fragnesia": {"status": "fail"}}}}
        )
        keyed = by_key(findings)
        self.assertEqual(
            keyed["security.fragnesia.status"].severity,
            audit_findings.VERSION,
        )
        finding = keyed["security.fragnesia.status"]
        self.assertNotIn("CVE-", finding.title)
        self.assertEqual(
            finding.cves,
            ("CVE-2026-46300", "CVE-2026-43284", "CVE-2026-43500"),
        )

    def test_accepts_bare_audit_data_dict(self) -> None:
        findings = audit_findings.detect_findings(
            {"containers": {"nvidiaContainerToolkit": False}}
        )
        self.assertIn("NVIDIA Container Toolkit not installed", titles(findings))

    def test_source_is_stamped_on_each_finding(self) -> None:
        src = "runs/oracle-gb300/20260612-185451/audit/audit.values.json"
        findings = audit_findings.detect_findings(
            {"audit_data": {"containers": {"nvidiaContainerToolkit": False}}},
            source=src,
        )
        self.assertTrue(findings)
        self.assertTrue(all(f.source == src for f in findings))

    def test_uppercase_fail_status_is_treated_as_fail(self) -> None:
        findings = audit_findings.detect_findings(
            {"audit_data": {"software": {"nvhpc": {"status": "FAIL"}}}}
        )
        self.assertIn(
            "NVIDIA HPC SDK is incomplete or outside the supported release window",
            titles(findings),
        )

    def test_oci_gb300_style_values_surface_expected_findings(self) -> None:
        # Mirrors the shape of the real OCI GB300 run that motivated this report.
        audit_data = {
            "containers": {
                "dockerVersionOk": True,
                "nvidiaContainerToolkit": False,
                "nvidiaContainerToolkitVersionOk": False,
                "singularity": False,
            },
            "software": {"nvhpc": {"status": "fail"}},
            "gpus": {"gdrcopy": {"installed": False}},
            "gpu_controls": {"vboost": {"allowed": False}},
        }
        keyed = by_key(audit_findings.detect_findings({"audit_data": audit_data}))
        for key in (
            "containers.nvidiaContainerToolkit",
            "software.nvhpc.status",
            "gpus.gdrcopy.installed",
            "gpu_controls.vboost.allowed",
        ):
            self.assertIn(key, keyed)
        # Singularity / Apptainer is back on the dashboard criteria page
        # (id "singularity", coverage "audit"), so a missing install on an
        # inspected worker is a finding again.
        self.assertIn("containers.singularity", keyed)
        self.assertEqual(
            keyed["containers.singularity"].severity,
            audit_findings.MISSING,
        )


class DpuAndDcgmFindingTests(unittest.TestCase):
    """The four components added with the July 2026 bulletins must reach the block."""

    @staticmethod
    def detect(security_versions: dict):
        return audit_findings.detect_findings(
            {"audit_data": {"securityVersions": security_versions}}
        )

    def test_running_below_minimum_controller_is_a_version_finding(self) -> None:
        keyed = by_key(
            self.detect(
                {
                    "virtioNetBluefield": {
                        "status": "fail",
                        "exposure": "live",
                        "platformMode": "dpu",
                        "gradedVersion": "25.10.1",
                        "floorStatus": "fail",
                    }
                }
            )
        )
        self.assertIn("securityVersions.virtioNetBluefield.status", keyed)
        finding = keyed["securityVersions.virtioNetBluefield.status"]
        self.assertEqual(finding.severity, audit_findings.VERSION)
        self.assertEqual(
            finding.title,
            "BlueField VIRTIO-Net controller below security minimum",
        )
        self.assertEqual(finding.cves, ("CVE-2026-65094",))

    def test_latent_exposure_reaches_the_block_marked_not_urgent(self) -> None:
        """A below-minimum controller idle in NIC mode must not be dropped.

        Its status is a warning rather than a failure, so a rule keyed only on
        status would let a real below-minimum finding leave the report entirely.
        """
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "25.10.1",
                    "floorStatus": "fail",
                }
            }
        )
        keyed = by_key(findings)
        self.assertIn("securityVersions.virtioNetBluefield.exposure", keyed)
        finding = keyed["securityVersions.virtioNetBluefield.exposure"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertEqual(finding.value, "latent")
        self.assertIn("not immediately urgent", finding.title)
        self.assertIn("DPU mode would", finding.title)
        self.assertIn("below its security minimum", finding.title)
        # The version was read, so neither the "could not be read" note nor the
        # unread-latent rule may fire beside it.
        self.assertNotIn("securityVersions.virtioNetBluefield.status", keyed)
        self.assertEqual(len(findings), 1)
        grace_findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "pass",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "25.10.1",
                    "floorStatus": "fail",
                    "gracePeriod": {"active": True},
                }
            }
        )
        self.assertEqual(grace_findings, [])

    def test_unread_latent_state_never_claims_the_firmware_is_below_minimum(self) -> None:
        """The vendor-facing half: never accuse from a version we did not read.

        NIC mode produces exposure "latent" for two different outcomes. Only
        one of them read a version. The other must still appear, because an
        idle card can be switched to DPU mode, but it may not carry the
        below-minimum claim, since this text is pasted into pull request
        comments as evidence for a provider.
        """
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "unknown",
                    "versionUnavailableReason": "not-observed",
                }
            }
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.key, "securityVersions.virtioNetBluefield.exposure")
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertNotIn("below its security minimum", finding.title)
        self.assertIn("could not be read", finding.title)
        self.assertIn("NIC mode", finding.title)
        self.assertIn("nothing is running now", finding.title)
        self.assertIn("not immediately urgent", finding.title)
        self.assertIn("DPU mode would activate", finding.title)
        self.assertIn("attestation", finding.title.lower())

    def test_a_hardened_dpu_also_reaches_the_unread_latent_wording(self) -> None:
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "unknown",
                    "versionUnavailableReason": "dpu-hardened",
                }
            }
        )
        self.assertEqual(len(findings), 1)
        self.assertNotIn("below its security minimum", findings[0].title)

    def test_an_ungradable_version_keeps_the_mode_change_warning(self) -> None:
        """A version read inside the interleaved release window owns no rule.

        The GA and newest LTS lines share a year.month prefix, so a version in
        that window grades neither pass nor fail when the collector cannot name
        the line. On a NIC-mode card that is exposure "latent" with a graded
        version present, which the below-minimum rule rejects on floorStatus and
        the unread rule rejects on the version being proven. The state fell
        through to the plain attestation note, which carries no mode-change
        warning, so an ungraded version was reported as less urgent than an
        unread one although neither is proven patched.
        """
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "25.10.4",
                    "versionUnavailableReason": None,
                    "floorStatus": "unknown",
                }
            }
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.key, "securityVersions.virtioNetBluefield.exposure")
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("could not be graded against a single release line", finding.title)
        self.assertIn("DPU mode would activate", finding.title)
        self.assertIn("attestation", finding.title.lower())
        # The version was read, and it was not proven below anything.
        self.assertNotIn("below its security minimum", finding.title)
        self.assertNotIn("could not be read", finding.title)

    def test_an_unusable_minimum_table_is_not_a_release_line_question(self) -> None:
        """The vendor-facing block must name the right party.

        An unusable minimum table produces the same triple as the interleaved
        window above: latent exposure, a version that parsed, and a floorStatus
        that is neither fail nor pass. The verdict detail was corrected for it,
        but a Finding carries only a title, a key and an observed value, so that
        correction never reaches this block and the release-line title stood.

        This block is pasted into pull request comments as vendor-facing
        evidence, so the title asked a provider to attest a release line for a
        fault in the table this repository ships. `minimum` is the field that
        separates the two states.
        """
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "24.10.17",
                    "versionUnavailableReason": None,
                    "floorStatus": "unknown",
                    "minimum": "unavailable",
                }
            }
        )
        self.assertEqual(len(findings), 1)
        title = findings[0].title
        self.assertIn("minimum table", title)
        self.assertIn("ClusterMAX fault", title)
        # It still carries the mode-change warning the latent state exists for.
        self.assertIn("DPU mode would activate", title)
        # And it never sends the provider after the wrong thing.
        self.assertNotIn("release line", title)
        self.assertNotIn("below its security minimum", title)

    def test_the_unusable_table_owns_every_shape_it_produces(self) -> None:
        """One rule per record, in every mode, when nothing was compared.

        `_virtio_running_verdict` returns the minimums-unavailable verdict before
        it parses the version, so an unread version carries the sentinel too.
        The unread rule had no table exclusion and the table rule had no proven
        requirement, so their intersection fired two contradictory findings for
        one record. A DPU-mode card grades exposure "unknown" rather than
        "latent", so no latent rule reached it and it fell to the attestation
        note, asking a provider to attest a version the audit already holds.
        """
        for label, block in {
            "unread, idle": {"gradedVersion": None, "exposure": "latent",
                             "versionUnavailableReason": "not-observed"},
            "read, idle": {"gradedVersion": "24.10.17", "exposure": "latent",
                           "versionUnavailableReason": None},
            "read, running": {"gradedVersion": "24.10.17", "exposure": "unknown",
                              "versionUnavailableReason": None},
            "unread, running": {"gradedVersion": None, "exposure": "unknown",
                                "versionUnavailableReason": "not-observed"},
        }.items():
            with self.subTest(case=label):
                findings = self.detect(
                    {
                        "virtioNetBluefield": {
                            "status": "unknown",
                            "platformMode": "nic" if "idle" in label else "dpu",
                            "floorStatus": "unknown",
                            "minimum": "unavailable",
                            **block,
                        }
                    }
                )
                self.assertEqual(len(findings), 1, [f.title for f in findings])
                title = findings[0].title
                self.assertIn("minimum table", title)
                self.assertIn("ClusterMAX fault", title)
                # Never sends the provider after something we broke.
                self.assertNotIn("requires provider attestation", title)
                self.assertNotIn("release line", title)

    def test_only_the_unproven_latent_rules_ask_for_attestation(self) -> None:
        """Derive the attestation split from the titles, not from a comment.

        The `_virtio_latent_exposure` docstring has miscounted this twice: the
        three-way version said all three latent rules carry the attestation ask,
        and the four-way rewrite said three of four. Two do. A prose claim about
        the rules that nothing checks is how the partition story goes stale, and
        a stale partition story in this file produced an overlap defect.

        An attestation ask belongs only where something is unproven. A proven
        below-minimum controller leaves the provider nothing to attest, and an
        unusable minimum table is our fault, not theirs.
        """
        asks = {
            rule.title
            for rule in audit_findings.RULES
            if rule.key.startswith("securityVersions.virtioNetBluefield")
            and "attest" in rule.title.lower()
        }
        self.assertEqual(len(asks), 3, sorted(asks))
        # Two latent rules, plus the plain attestation note outside the state.
        self.assertTrue(any("could not be read" in t for t in asks))
        self.assertTrue(any("could not be graded" in t for t in asks))
        self.assertTrue(any("requires provider attestation" in t for t in asks))
        # A proven failure and a broken table never ask the provider to attest.
        for title in asks:
            self.assertNotIn("is below its security minimum", title)
            self.assertNotIn("was not compared against any minimum", title)

    def test_the_latent_rules_are_mutually_exclusive(self) -> None:
        for label, block in {
            "version read": {
                "gradedVersion": "25.10.1",
                "versionUnavailableReason": None,
                "floorStatus": "fail",
            },
            "version unread": {
                "gradedVersion": "unknown",
                "versionUnavailableReason": "not-observed",
            },
            "version ungradable": {
                "gradedVersion": "25.10.4",
                "versionUnavailableReason": None,
                "floorStatus": "unknown",
            },
        }.items():
            with self.subTest(case=label):
                findings = self.detect(
                    {
                        "virtioNetBluefield": {
                            "status": "unknown",
                            "exposure": "latent",
                            "platformMode": "nic",
                            **block,
                        }
                    }
                )
                self.assertEqual(len(findings), 1)

    def test_patched_idle_firmware_is_never_called_below_its_minimum(self) -> None:
        """FINDING 1: a coverage gap withdrew a pass, and the block accused it.

        Firmware read on a NIC-mode host, proved patched against its own minimum,
        beside one unread peer. The coverage rule correctly withdraws the pass
        to unknown, which left exposure latent and a graded version present, so
        the below-minimum rule fired on firmware the audit proved is fine, and
        the attestation note was suppressed so the false claim stood alone.
        """
        findings = self.detect(
            {
                "virtioNetBluefield": {
                    "status": "unknown",
                    "exposure": "latent",
                    "platformMode": "nic",
                    "gradedVersion": "25.10.6",
                    "versionUnavailableReason": None,
                    "floorStatus": "pass",
                    "coverageComplete": False,
                }
            }
        )
        titles_seen = titles(findings)
        for claim in ("below its security minimum", "could not be read"):
            self.assertFalse(
                any(claim in title for title in titles_seen),
                f"a patched controller must never be reported as {claim!r}",
            )
        # One entry, and it asks for attestation instead of accusing. The
        # latent state is partitioned by the four latent rules, so this
        # combination is owned by the read-but-ungraded one; `_virtio_exposure`
        # no longer reports latent for a floorStatus of "pass", so the input is
        # kept only as the pin on the historical defect.
        self.assertEqual(len(findings), 1)
        self.assertIn("attestation", findings[0].title.lower())

    def test_unreadable_controller_version_on_a_bluefield_asks_for_attestation(self) -> None:
        keyed = by_key(
            self.detect(
                {
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                        "platformMode": "dpu",
                    }
                }
            )
        )
        finding = keyed["securityVersions.virtioNetBluefield.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("attestation", finding.title.lower())
        self.assertIn("found a BlueField device in DPU mode", finding.detected)
        self.assertIn("Attest the controller version", finding.recommendation)
        self.assertNotIn("Complete the BlueField inventory", finding.recommendation)

    def test_reachable_dpu_control_plane_names_the_remediation(self) -> None:
        keyed = by_key(
            self.detect(
                {
                    "dpuHostIsolation": {
                        "status": "fail",
                        "bluefieldPresent": True,
                        "detail": "INTERNAL_CPU_RSHIM=0 permits host access.",
                        "remediation": "mlxprivhost -d 03:00.0 r --disable_rshim",
                    }
                }
            )
        )
        finding = keyed["securityVersions.dpuHostIsolation.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("zero-trust", finding.title)
        self.assertIn("mlxprivhost", finding.title)
        self.assertIn("--disable_rshim", finding.title)
        self.assertIn("INTERNAL_CPU_RSHIM=0", finding.detected)
        self.assertIn("mlxprivhost -d 03:00.0", finding.recommendation)
        self.assertIn("INTERNAL_CPU_RSHIM=1", finding.recommendation)

    def test_perf_controls_name_values_and_persistent_actions(self) -> None:
        keyed = by_key(
            audit_findings.detect_findings(
                {
                    "audit_data": {
                        "software": {
                            "perf": {
                                "installed": True,
                                "perfEventParanoid": "4",
                                "kptrRestrict": "1",
                            }
                        }
                    }
                }
            )
        )

        paranoid = keyed["software.perf.perfEventParanoid"]
        self.assertIn("kernel.perf_event_paranoid is 4", paranoid.detected)
        self.assertIn("kernel.perf_event_paranoid=1", paranoid.recommendation)
        self.assertIn("persist", paranoid.recommendation)
        kptr = keyed["software.perf.kptrRestrict"]
        self.assertIn("kernel.kptr_restrict is 1", kptr.detected)
        self.assertIn("kernel.kptr_restrict=0", kptr.recommendation)
        self.assertIn("persist", kptr.recommendation)

    def test_unverifiable_dpu_isolation_asks_for_attestation(self) -> None:
        keyed = by_key(
            self.detect(
                {"dpuHostIsolation": {"status": "unknown", "bluefieldPresent": True}}
            )
        )
        finding = keyed["securityVersions.dpuHostIsolation.status"]
        self.assertEqual(finding.severity, audit_findings.CONFIG)
        self.assertIn("root", finding.title)
        self.assertIn("found a BlueField device", finding.detected)
        self.assertIn("Attest the isolation posture", finding.recommendation)
        self.assertNotIn("Complete the BlueField inventory", finding.recommendation)

    def test_dcgm_pair_fail_and_unknown_follow_the_other_version_components(self) -> None:
        keyed = by_key(self.detect({"dcgm": {"status": "fail"}, "dcgmExporter": {"status": "fail"}}))
        self.assertEqual(
            keyed["securityVersions.dcgm.status"].severity, audit_findings.VERSION
        )
        self.assertEqual(
            keyed["securityVersions.dcgmExporter.status"].severity, audit_findings.VERSION
        )
        keyed = by_key(
            self.detect({"dcgm": {"status": "unknown"}, "dcgmExporter": {"status": "unknown"}})
        )
        for key in ("securityVersions.dcgm.status", "securityVersions.dcgmExporter.status"):
            self.assertEqual(keyed[key].severity, audit_findings.CONFIG)
            self.assertIn("attestation", keyed[key].title.lower())

    def test_not_applicable_never_produces_a_finding(self) -> None:
        """Most clusters have no BlueField and some have no DCGM.

        A permanent entry on all of them would train readers to skip the block.
        """
        self.assertEqual(
            self.detect(
                {
                    "virtioNetBluefield": {
                        "status": "not_applicable",
                        "exposure": "none",
                        "platformMode": "absent",
                    },
                    "dpuHostIsolation": {
                        "status": "not_applicable",
                        "bluefieldPresent": False,
                    },
                    "dcgm": {"status": "not_applicable"},
                    "dcgmExporter": {"status": "not_applicable"},
                }
            ),
            [],
        )

    def test_passing_components_never_produce_a_finding(self) -> None:
        self.assertEqual(
            self.detect(
                {
                    "virtioNetBluefield": {
                        "status": "pass",
                        "exposure": "none",
                        "platformMode": "dpu",
                        "gradedVersion": "25.10.6",
                    },
                    "dpuHostIsolation": {"status": "pass", "bluefieldPresent": True},
                    "dcgm": {"status": "pass"},
                    "dcgmExporter": {"status": "pass"},
                }
            ),
            [],
        )

    def test_incomplete_bluefield_scan_requests_complete_inventory(self) -> None:
        keyed = by_key(
            self.detect(
                {
                    "virtioNetBluefield": {
                        "status": "unknown",
                        "exposure": "unknown",
                        "platformMode": "unknown",
                    },
                    "dpuHostIsolation": {
                        "status": "unknown",
                        "bluefieldPresent": None,
                        "scanComplete": False,
                    },
                    "dcgm": {"status": "unknown"},
                }
            )
        )
        self.assertIn("securityVersions.virtioNetBluefield.status", keyed)
        self.assertIn("securityVersions.dpuHostIsolation.status", keyed)
        for key in (
            "securityVersions.virtioNetBluefield.status",
            "securityVersions.dpuHostIsolation.status",
        ):
            self.assertIn("Complete the BlueField inventory", keyed[key].recommendation)
            self.assertNotIn("or later", keyed[key].recommendation)
        self.assertIn("securityVersions.dcgm.status", keyed)


class FormatReportTests(unittest.TestCase):
    def test_zero_findings_report_says_no_findings(self) -> None:
        report = audit_findings.format_report([])
        self.assertIn("AUDIT FINDINGS (0)", report)
        self.assertIn("No findings", report)

    def test_report_header_carries_count_and_actions(self) -> None:
        findings = audit_findings.detect_findings(
            {
                "audit_data": {
                    "containers": {"nvidiaContainerToolkit": False},
                    "securityVersions": {
                        "runc": {
                            "status": "fail",
                            "version": "1.4.2",
                            "minimum": "1.4.3",
                        }
                    },
                }
            },
            source="runs/x/audit/audit.values.json",
        )
        report = audit_findings.format_report(findings, source="runs/x/audit/audit.values.json")
        self.assertIn("AUDIT FINDINGS (2)", report)
        self.assertIn("[MISSING]", report)
        # The report intentionally omits raw evidence keys and source paths;
        # it carries direct Detected / Recommendation lines instead.
        self.assertIn("Detected: Not installed", report)
        self.assertIn("Recommendation:", report)
        self.assertIn("GHSA-9493-h29p-rfm2", report)
        self.assertNotIn("https://", report)

        linked = audit_findings.format_report(findings, hyperlinks=True)
        self.assertIn("\x1b]8;;https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2", linked)
        self.assertIn("\x1b[4mGHSA-9493-h29p-rfm2\x1b[24m", linked)


class MainExitCodeTests(unittest.TestCase):
    def _write(self, tmp: Path, values: dict) -> Path:
        import json

        path = tmp / "audit.values.json"
        path.write_text(json.dumps(values))
        return path

    def test_default_is_report_only_even_with_findings(self) -> None:
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                Path(tmp),
                {"audit_data": {"containers": {"nvidiaContainerToolkit": False}}},
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(audit_findings.main(["prog", str(path)]), 0)

    def test_exit_code_flag_returns_nonzero_when_findings_exist(self) -> None:
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                Path(tmp),
                {"audit_data": {"containers": {"nvidiaContainerToolkit": False}}},
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    audit_findings.main(["prog", "--exit-code", str(path)]), 1
                )

    def test_exit_code_flag_returns_zero_on_a_clean_audit(self) -> None:
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                Path(tmp),
                {"audit_data": {"containers": {"nvidiaContainerToolkit": True}}},
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    audit_findings.main(["prog", "--exit-code", str(path)]), 0
                )


class ExemplarPlatformFindingTests(unittest.TestCase):
    """The Exemplar Cloud checks must not read a skip as a provider fault.

    The check reports ``not_applicable`` on a platform the check does not cover
    and ``unknown`` when the platform could not be read, so both must stay
    silent. The one exception is a Slurm run that holds a host topology file and
    could not start its container arm: the mount is unverified rather than
    absent, and PR #1357 established that such a gap becomes an
    attestation-required note.
    """

    def _findings(self, audit_data: dict) -> list:
        return audit_findings.detect_findings({"audit_data": audit_data})

    def test_a_host_topology_file_that_misses_the_container_is_a_finding(self) -> None:
        findings = self._findings(
            {"nccl_topo_file": {"status": "fail", "container": {"available": True, "reason_code": ""}}}
        )
        self.assertIn("Host NCCL topology file does not reach the benchmark container", titles(findings))

    def test_an_srun_launch_failure_asks_for_attestation_rather_than_failing(self) -> None:
        for reason_code in ("launch_failed", "check_incomplete", "no_allocation", "no_srun", "check_disabled"):
            with self.subTest(reason_code=reason_code):
                findings = self._findings(
                    {
                        "nccl_topo_file": {
                            "status": "unknown",
                            "container": {"available": False, "reason_code": reason_code},
                        }
                    }
                )
                note = by_key(findings)["nccl_topo_file.status"]
                self.assertEqual(note.severity, audit_findings.CONFIG)
                self.assertIn("attestation", note.title.lower())

    def test_a_harness_with_no_launcher_leaves_nothing_pending(self) -> None:
        """k8s and standalone have no pyxis launcher, so nothing is owed."""
        findings = self._findings(
            {
                "nccl_topo_file": {
                    "status": "unknown",
                    "container": {"available": False, "reason_code": "no_launcher_on_harness"},
                }
            }
        )
        self.assertNotIn("nccl_topo_file.status", by_key(findings))

    def test_a_not_applicable_topology_check_is_silent(self) -> None:
        findings = self._findings(
            {
                "nccl_topo_file": {
                    "status": "not_applicable",
                    "container": {"available": False, "reason_code": "no_host_topo_file"},
                }
            }
        )
        self.assertEqual(findings, [])

    def test_the_queue_pair_advisory_fires_on_a_warning_only(self) -> None:
        self.assertIn(
            "NCCL_IB_QPS_PER_CONNECTION is at the default on a multi-tier Clos fabric; sweep it (advisory)",
            titles(self._findings({"nccl_ib_qps": {"status": "warning"}})),
        )
        for status in ("pass", "not_applicable", "unknown"):
            with self.subTest(status=status):
                self.assertEqual(self._findings({"nccl_ib_qps": {"status": status}}), [])


if __name__ == "__main__":
    unittest.main()
