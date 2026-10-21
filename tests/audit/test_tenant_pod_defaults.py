#!/usr/bin/env python3
"""Tenant pod parsing, admission, manifests, and report integration."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import pytest

from cmax import audit_report, runtime_paths

SCRIPT_DIR = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit"
)

CHECK_PATH = SCRIPT_DIR / "checks" / "system" / "tenant_pod_defaults.py"


def load_check_module():
    name = "tenant_pod_defaults_under_test"
    spec = importlib.util.spec_from_file_location(name, CHECK_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check = load_check_module()
REPORT_RUNTIME_ROOT = runtime_paths.package_runtime_root()

STOCK_DEFAULTS_STDOUT = """\
TENANT_MEMLOCK_SOFT_KB=8192
TENANT_MEMLOCK_HARD_KB=8192
TENANT_SHM_KB=65536
TENANT_CAP_EFF=00000000a80425fb
TENANT_IB_UVERBS=0
TENANT_RDMA_CM=false
TENANT_GDRDRV=false
TENANT_NVIDIA_DEVS=8
TENANT_UID=0
"""

EMPTY_TUNED = {
    "attempted": False,
    "admitted": False,
    "ready": False,
    "reason": "",
    "node": "",
    "rdmaResourceRequested": "",
    "facts": None,
}


def stock_facts():
    return check.pod_facts(check.parse_facts(STOCK_DEFAULTS_STDOUT))


def evaluate(default_facts, tuned=EMPTY_TUNED, *, gpu_requested=True, rdma_resources=()):
    return check.evaluate_checks(
        default_facts,
        dict(tuned),
        gpu_requested=gpu_requested,
        rdma_resources=list(rdma_resources),
        memlock_min_mb=65536,
        shm_min_mb=1024,
    )


class ParseFactsTests(unittest.TestCase):
    def test_parses_stock_defaults(self) -> None:
        facts = stock_facts()
        self.assertEqual(facts["memlockHardKb"], "8192")
        self.assertFalse(facts["memlockUnlimited"])
        self.assertEqual(facts["shmMb"], 64)
        self.assertIs(facts["capIpcLock"], False)
        self.assertIs(facts["capSysAdmin"], False)
        self.assertIs(facts["capSysResource"], False)
        self.assertEqual(facts["ibUverbsDevices"], 0)
        self.assertFalse(facts["gdrdrvDevice"])
        self.assertEqual(facts["nvidiaDevices"], 8)

    def test_ignores_non_tenant_lines(self) -> None:
        facts = check.parse_facts("noise\nTENANT_SHM_KB=1024\nOTHER=x\n")
        self.assertEqual(facts, {"TENANT_SHM_KB": "1024"})

    def test_unlimited_memlock(self) -> None:
        facts = check.pod_facts({"TENANT_MEMLOCK_HARD_KB": "unlimited"})
        self.assertTrue(facts["memlockUnlimited"])


class DecodeCapsTests(unittest.TestCase):
    def test_capability_masks(self) -> None:
        for mask, expected in (
            ("00000000a80425fb", (False, False, False)),
            ("000001ffffffffff", (True, True, True)),
            ("0x4000", (True, False, False)),
            ("unknown", (None, None, None)),
        ):
            with self.subTest(mask=mask):
                self.assertEqual(
                    check.decode_caps(mask),
                    dict(zip(("ipc_lock", "sys_admin", "sys_resource"), expected)),
                )


class NodeScanTests(unittest.TestCase):
    def test_rdma_resource_discovery(self) -> None:
        cases = (
            ("any-node", [
                {"nvidia.com/gpu": "8"},
                {"rdma/hca_shared_devices_a": "63", "nvidia.com/rdma_ib": "2"},
            ], ["nvidia.com/rdma_ib", "rdma/hca_shared_devices_a"]),
            ("non-rdma-names", [
                {"vpc.amazonaws.com/efa": "4", "nvidia.com/gpu": "8"},
                {"nvidia.com/mlnxics": "8"},
                {"nvidia.com/hostdev": "8"},
                {"nvidia.com/switchdev": "8"},
            ], ["nvidia.com/hostdev", "nvidia.com/mlnxics",
                "nvidia.com/switchdev", "vpc.amazonaws.com/efa"]),
            ("unrelated", [{"nvidia.com/gpu": "8", "cpu": "128",
                           "hugepages-2Mi": "4Gi", "nvidia.com/mig-1g.10gb": "7"}], []),
            ("zero", [{"rdma/rdma_nic": "0"}], []),
        )
        for name, resources, expected in cases:
            with self.subTest(case=name):
                nodes = {"items": [
                    {"status": {"allocatable": values}} for values in resources
                ]}
                self.assertEqual(check.cluster_rdma_resources(nodes), expected)

    def test_dra_class_name_filter_matches_public_resource_tokens(self) -> None:
        self.assertEqual(
            check.filter_dra_rdma_class_names(
                ["mrdma.google.com", "dranet.net", "gpu.dra.net", "gpu.nvidia.com", ""]
            ),
            ["dranet.net", "gpu.dra.net", "mrdma.google.com"],
        )

    def test_gpu_resource_key(self) -> None:
        for resources, expected in (
            ({"nvidia.com/gpu": "8"}, "nvidia.com/gpu"),
            ({"cpu": "128"}, ""),
        ):
            with self.subTest(resources=resources):
                nodes = {"items": [{"status": {"allocatable": resources}}]}
                self.assertEqual(check.gpu_resource_key(nodes), expected)


class EvaluateChecksTests(unittest.TestCase):
    def test_memlock_remedies_pass(self) -> None:
        for remedy in (
            {"memlockHardKb": "unlimited", "memlockUnlimited": True},
            {"capIpcLock": True},
            {"memlockHardKb": str(128 * 1024 * 1024)},
        ):
            with self.subTest(remedy=remedy):
                facts = {**stock_facts(), **remedy}
                self.assertEqual(evaluate(facts)["memlock"]["status"], "pass")

    def test_large_shm_passes(self) -> None:
        facts = stock_facts()
        facts["shmMb"] = 32768
        self.assertEqual(evaluate(facts)["shm"]["status"], "pass")

    def test_rdma_devices_requestable_via_tuned_pod(self) -> None:
        tuned_facts = stock_facts()
        tuned_facts["ibUverbsDevices"] = 9
        tuned = {
            "attempted": True,
            "admitted": True,
            "ready": True,
            "reason": "",
            "node": "n1",
            "rdmaResourceRequested": "rdma/hca_shared_devices_a",
            "facts": tuned_facts,
        }
        checks = evaluate(stock_facts(), tuned, rdma_resources=["rdma/hca_shared_devices_a"])
        self.assertEqual(checks["rdmaDevices"]["status"], "requestable")

    def test_rdma_devices_unknown_when_advertised_but_unverified(self) -> None:
        checks = evaluate(stock_facts(), rdma_resources=["rdma/rdma_nic"])
        self.assertEqual(checks["rdmaDevices"]["status"], "unknown")

    def test_dra_only_rdma_exposure_is_unknown_not_absent(self) -> None:
        checks = check.evaluate_checks(
            stock_facts(),
            dict(EMPTY_TUNED),
            gpu_requested=True,
            rdma_resources=[],
            memlock_min_mb=65536,
            shm_min_mb=1024,
            dra_rdma_classes=["mrdma.google.com"],
        )
        self.assertEqual(checks["rdmaDevices"]["status"], "unknown")
        self.assertIn("mrdma.google.com", checks["rdmaDevices"]["detail"])

    def test_privileged_namespace_voids_the_admission_signal(self) -> None:
        tuned_facts = stock_facts()
        tuned_facts["capIpcLock"] = True
        tuned_facts["shmMb"] = 8192
        tuned = {
            "attempted": True,
            "admitted": True,
            "ready": True,
            "reason": "",
            "node": "n1",
            "rdmaResourceRequested": "",
            "facts": tuned_facts,
        }
        checks = check.evaluate_checks(
            stock_facts(),
            tuned,
            gpu_requested=True,
            rdma_resources=[],
            memlock_min_mb=65536,
            shm_min_mb=1024,
            privileged_namespace=True,
        )
        self.assertEqual(checks["tunedPodAdmission"]["status"], "unknown")
        self.assertIn("privileged pod-security profile", checks["tunedPodAdmission"]["detail"])

    def test_tuned_pod_admission_states(self) -> None:
        for name, state, fact_updates, status, detail in (
            ("denied", {"attempted": True, "reason": "IPC_LOCK forbidden by policy"},
             None, "warning", "IPC_LOCK forbidden by policy"),
            ("unschedulable", {"attempted": True, "admitted": True,
                              "reason": "0/2 nodes available"}, None, "unknown", None),
            ("effective", {"attempted": True, "admitted": True, "ready": True,
                           "node": "n1"}, {"capIpcLock": True, "shmMb": 8192}, "pass", None),
            ("ineffective", {"attempted": True, "admitted": True, "ready": True,
                             "node": "n1"}, {}, "warning", None),
        ):
            with self.subTest(case=name):
                facts = None if fact_updates is None else {**stock_facts(), **fact_updates}
                tuned = {**EMPTY_TUNED, **state, "facts": facts}
                result = evaluate(stock_facts(), tuned)["tunedPodAdmission"]
                self.assertEqual(result["status"], status)
                if detail is not None:
                    self.assertIn(detail, result["detail"])

    def test_missing_facts_grade_unknown(self) -> None:
        checks = evaluate(None)
        self.assertNotIn("fail", {entry["status"] for entry in checks.values()})
        for name in ("memlock", "shm", "rdmaDevices", "gdrcopyDevice"):
            self.assertEqual(checks[name]["status"], "unknown")


class AggregateTests(unittest.TestCase):
    def test_stock_defaults_aggregate_to_warning_with_no_failures(self) -> None:
        checks = evaluate(stock_facts())
        self.assertEqual(checks["memlock"]["status"], "warning")
        self.assertIn("8 MiB", checks["memlock"]["detail"])
        self.assertEqual(checks["shm"]["status"], "warning")
        self.assertIn("64 MiB", checks["shm"]["detail"])
        self.assertEqual(checks["rdmaDevices"]["status"], "absent")
        self.assertEqual(checks["gdrcopyDevice"]["status"], "absent")
        self.assertNotIn("fail", {entry["status"] for entry in checks.values()})
        result = check.aggregate(
            checks,
            default_pod={"admitted": True, "ready": True, "reason": "", "node": "n1", "facts": stock_facts()},
            tuned=dict(EMPTY_TUNED),
            errors=[],
            context={},
        )
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["failures"], [])
        self.assertTrue(result["warnings"])

    def test_check_that_never_ran_is_unknown(self) -> None:
        result = check.aggregate(
            {},
            default_pod={"admitted": False, "ready": False, "reason": "kubectl get nodes failed", "node": "", "facts": None},
            tuned=dict(EMPTY_TUNED),
            errors=[],
            context={},
        )
        self.assertEqual(result["status"], "unknown")
        self.assertIn("kubectl get nodes failed", result["message"])

    def test_clean_pod_aggregates_to_pass(self) -> None:
        facts = stock_facts()
        facts.update(memlockHardKb="unlimited", memlockUnlimited=True, shmMb=32768, ibUverbsDevices=9, gdrdrvDevice=True)
        checks = evaluate(facts)
        result = check.aggregate(
            checks,
            default_pod={"admitted": True, "ready": True, "reason": "", "node": "n1", "facts": facts},
            tuned=dict(EMPTY_TUNED),
            errors=[],
            context={},
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["failures"], [])


class PodManifestTests(unittest.TestCase):
    def test_default_pod_has_no_privileged_context_or_host_network(self) -> None:
        for gpu_key in ("nvidia.com/gpu", ""):
            with self.subTest(gpu_key=gpu_key):
                manifest = check.pod_manifest(
                    "default", "cmax-tenant-default-x", "img",
                    gpu_key=gpu_key, tuned=False, rdma_resource="", tuned_shm="8Gi",
                )
                container = manifest["spec"]["containers"][0]
                self.assertNotIn("securityContext", container)
                self.assertNotIn("volumes", manifest["spec"])
                self.assertFalse(manifest["spec"].get("hostNetwork", False))
                if gpu_key:
                    self.assertEqual(container["resources"]["limits"], {gpu_key: "1"})
                else:
                    self.assertNotIn("resources", container)

    def test_tuned_pod_adds_only_the_documented_remedies(self) -> None:
        manifest = check.pod_manifest(
            "default", "cmax-tenant-tuned-x", "img", gpu_key="nvidia.com/gpu", tuned=True, rdma_resource="rdma/rdma_nic", tuned_shm="8Gi"
        )
        container = manifest["spec"]["containers"][0]
        self.assertEqual(container["securityContext"], {"capabilities": {"add": ["IPC_LOCK"]}})
        self.assertEqual(
            manifest["spec"]["volumes"],
            [{"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "8Gi"}}],
        )
        self.assertEqual(
            container["resources"]["limits"],
            {"nvidia.com/gpu": "1", "rdma/rdma_nic": "1"},
        )


class HarnessGateTests(unittest.TestCase):
    def test_non_k8s_harness_is_not_applicable(self) -> None:
        result = check.run_default_check("slurm")["tenant_pod_defaults"]
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["failures"], [])

    def test_check_disable_switch_grades_unknown(self) -> None:
        with mock.patch.dict(os.environ, {"CLUSTERMAX_AUDIT_TENANT_POD_CHECK": "0"}):
            result = check.run_default_check("k8s")["tenant_pod_defaults"]
        self.assertEqual(result["status"], "unknown")


def test_tenant_check_is_executable_and_excluded_from_security():
    spec = importlib.util.spec_from_file_location("tenant_run_checks", SCRIPT_DIR / "run_checks.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    path = SCRIPT_DIR / "checks/system/tenant_pod_defaults.py"
    assert path in runner.iter_checks(SCRIPT_DIR / "checks", "k8s", "orchestration")
    assert path not in runner.iter_checks(SCRIPT_DIR / "checks", "k8s", "security")
    assert path not in runner.iter_checks(SCRIPT_DIR / "checks", "slurm")


def test_tenant_warning_preserves_detail_and_recommendation():
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "warning", "checks": {"memlock": {
            "status": "warning", "detail": "The pod has an 8 MiB limit."
        }}
    }}}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    result = next(c for c in checks if c.key == "tenant_pod_defaults.checks.memlock.status")
    assert result.status == audit_report.WARNING
    assert result.assessment == "The pod has an 8 MiB limit."
    assert result.recommendation


@pytest.mark.parametrize("ports", [None, "unknown", 0, "2", 2])
def test_absent_rdma_devices_do_not_crash_report(ports):
    values = {"audit_data": {
        "networking": {"hostRdma": {"activePorts": ports}},
        "tenant_pod_defaults": {"checks": {"rdmaDevices": {"status": "absent"}}},
    }}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    check = next(c for c in checks if c.key == "tenant_pod_defaults.checks.rdmaDevices.status")
    assert check.status == (audit_report.WARNING if ports in (2, "2") else audit_report.SKIPPED)
    if ports == 0:
        assert "no active RDMA" in check.assessment
    elif ports in (None, "unknown"):
        assert "unverified" in check.assessment.lower()


@pytest.mark.parametrize("loaded", [False, "false", None])
def test_gdrcopy_skip_uses_collected_host_path(loaded):
    values = {"audit_data": {
        "gpus": {"gdrcopy": {"gdrdrvLoaded": loaded}},
        "tenant_pod_defaults": {"checks": {"gdrcopyDevice": {"status": "absent"}}},
    }}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    check = next(c for c in checks if c.key == "tenant_pod_defaults.checks.gdrcopyDevice.status")
    assert check.status == audit_report.SKIPPED
    if loaded is None:
        assert "unverified" in check.assessment.lower()
    else:
        assert "gdrdrv is not loaded" in check.assessment


if __name__ == "__main__":
    unittest.main()


def test_unreadable_namespace_policy_never_renders_as_pass():
    detail = "the namespace pod-security policy could not be read"
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "unknown", "message": detail, "namespaceEnforcesPrivileged": None,
        "checks": {"tunedPodAdmission": {"status": "unknown", "detail": detail}},
    }}}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    rows = [row for row in checks if row.key in {
        "tenant_pod_defaults.status", "tenant_pod_defaults.checks.tunedPodAdmission.status",
    }]
    assert len(rows) == 2
    assert all(row.status != audit_report.PASS for row in rows)
    assert any("policy could not be read" in row.assessment for row in rows)


def test_aggregate_warning_never_renders_as_pass():
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "warning",
        "message": "shm: /dev/shm is 64 MiB; multi-GPU shared-memory transports need at least 1024 MiB",
        "checks": {"shm": {"status": "warning", "detail": "/dev/shm is 64 MiB"}},
    }}}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    row = next(c for c in checks if c.key == "tenant_pod_defaults.status")
    assert row.status == audit_report.WARNING
    assert "64 MiB" in row.assessment
    assert row.recommendation


def test_aggregate_pass_still_renders_as_pass():
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "pass", "checks": {"shm": {"status": "pass", "detail": "8192 MiB"}},
    }}}
    checks = audit_report.evaluate(values, REPORT_RUNTIME_ROOT, harness="k8s")
    row = next(c for c in checks if c.key == "tenant_pod_defaults.status")
    assert row.status == audit_report.PASS
