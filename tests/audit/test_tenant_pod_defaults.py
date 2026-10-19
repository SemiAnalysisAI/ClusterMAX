#!/usr/bin/env python3
"""Unit tests for the tenant pod defaults check (pure helpers only).

The kubectl plumbing follows the hbm_memory_exposure check verbatim and is
not exercised here. These tests cover the fact parsing, the capability
decoding, and the check evaluation, which carry the grading decisions:

- The restricted-runtime fixture (8 MiB memlock,
  64 MiB /dev/shm, no CAP_IPC_LOCK, no /dev/infiniband, no /dev/gdrdrv)
  must each produce their warning or absent verdict.
- No check may ever emit `fail`; the whole check grades at most `warning`.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

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

# The restricted containerd fixture uses 8192 KiB memlock,
# 64 MiB CRI sandbox /dev/shm, the default Docker/containerd capability mask
# (no IPC_LOCK, no SYS_ADMIN, no SYS_RESOURCE), and no RDMA / GDRCopy devices.
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
    def test_stock_docker_mask_has_no_rdma_caps(self) -> None:
        caps = check.decode_caps("00000000a80425fb")
        self.assertEqual(caps, {"ipc_lock": False, "sys_admin": False, "sys_resource": False})

    def test_full_root_mask_has_all(self) -> None:
        caps = check.decode_caps("000001ffffffffff")
        self.assertEqual(caps, {"ipc_lock": True, "sys_admin": True, "sys_resource": True})

    def test_ipc_lock_bit_alone(self) -> None:
        caps = check.decode_caps(hex(1 << check.CAP_IPC_LOCK))
        self.assertEqual(caps, {"ipc_lock": True, "sys_admin": False, "sys_resource": False})

    def test_unparseable_mask_is_none(self) -> None:
        caps = check.decode_caps("unknown")
        self.assertEqual(caps, {"ipc_lock": None, "sys_admin": None, "sys_resource": None})


class NodeScanTests(unittest.TestCase):
    def test_rdma_resources_from_any_node(self) -> None:
        nodes = {
            "items": [
                {"status": {"allocatable": {"nvidia.com/gpu": "8"}}},
                {"status": {"allocatable": {"rdma/hca_shared_devices_a": "63", "nvidia.com/rdma_ib": "2"}}},
            ]
        }
        self.assertEqual(
            check.cluster_rdma_resources(nodes),
            ["nvidia.com/rdma_ib", "rdma/hca_shared_devices_a"],
        )

    def test_non_rdma_named_fabric_resources_match(self) -> None:
        """EFA, SR-IOV IB, SR-IOV host device, and OVS offload carry no rdma substring."""
        nodes = {
            "items": [
                {"status": {"allocatable": {"vpc.amazonaws.com/efa": "4", "nvidia.com/gpu": "8"}}},
                {"status": {"allocatable": {"nvidia.com/mlnxics": "8"}}},
                {"status": {"allocatable": {"nvidia.com/hostdev": "8"}}},
                {"status": {"allocatable": {"nvidia.com/switchdev": "8"}}},
            ]
        }
        self.assertEqual(
            check.cluster_rdma_resources(nodes),
            ["nvidia.com/hostdev", "nvidia.com/mlnxics", "nvidia.com/switchdev", "vpc.amazonaws.com/efa"],
        )

    def test_dra_class_name_filter_matches_public_resource_tokens(self) -> None:
        """Construct resource keys independently of any deployment."""
        self.assertEqual(
            check.filter_dra_rdma_class_names(
                ["mrdma.google.com", "dranet.net", "gpu.dra.net", "gpu.nvidia.com", ""]
            ),
            ["dranet.net", "gpu.dra.net", "mrdma.google.com"],
        )

    def test_gpu_and_other_resources_do_not_match(self) -> None:
        nodes = {
            "items": [
                {"status": {"allocatable": {"nvidia.com/gpu": "8", "cpu": "128", "hugepages-2Mi": "4Gi", "nvidia.com/mig-1g.10gb": "7"}}}
            ]
        }
        self.assertEqual(check.cluster_rdma_resources(nodes), [])

    def test_zero_quantity_rdma_resource_is_ignored(self) -> None:
        nodes = {"items": [{"status": {"allocatable": {"rdma/rdma_nic": "0"}}}]}
        self.assertEqual(check.cluster_rdma_resources(nodes), [])

    def test_gpu_resource_key(self) -> None:
        nodes = {"items": [{"status": {"allocatable": {"nvidia.com/gpu": "8"}}}]}
        self.assertEqual(check.gpu_resource_key(nodes), "nvidia.com/gpu")

    def test_gpu_resource_key_dra_cluster(self) -> None:
        nodes = {"items": [{"status": {"allocatable": {"cpu": "128"}}}]}
        self.assertEqual(check.gpu_resource_key(nodes), "")


class EvaluateChecksTests(unittest.TestCase):
    def test_stock_defaults_warn_on_memlock_and_shm(self) -> None:
        checks = evaluate(stock_facts())
        self.assertEqual(checks["memlock"]["status"], "warning")
        self.assertIn("8 MiB", checks["memlock"]["detail"])
        self.assertEqual(checks["shm"]["status"], "warning")
        self.assertIn("64 MiB", checks["shm"]["detail"])

    def test_stock_defaults_report_absent_devices(self) -> None:
        checks = evaluate(stock_facts())
        self.assertEqual(checks["rdmaDevices"]["status"], "absent")
        self.assertEqual(checks["gdrcopyDevice"]["status"], "absent")

    def test_no_check_ever_fails(self) -> None:
        for facts in (None, stock_facts()):
            checks = evaluate(facts)
            self.assertNotIn("fail", {check["status"] for check in checks.values()})

    def test_unlimited_memlock_passes(self) -> None:
        facts = stock_facts()
        facts["memlockHardKb"] = "unlimited"
        facts["memlockUnlimited"] = True
        self.assertEqual(evaluate(facts)["memlock"]["status"], "pass")

    def test_ipc_lock_capability_passes_memlock(self) -> None:
        facts = stock_facts()
        facts["capIpcLock"] = True
        self.assertEqual(evaluate(facts)["memlock"]["status"], "pass")

    def test_finite_memlock_above_minimum_passes(self) -> None:
        facts = stock_facts()
        facts["memlockHardKb"] = str(128 * 1024 * 1024)  # 128 GiB in KiB
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
        """GKE DRANET style: no extended resource, an mrdma DRA device class."""
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

    def test_admission_denial_warns(self) -> None:
        tuned = dict(EMPTY_TUNED)
        tuned.update(attempted=True, admitted=False, reason="IPC_LOCK forbidden by policy")
        checks = evaluate(stock_facts(), tuned)
        self.assertEqual(checks["tunedPodAdmission"]["status"], "warning")
        self.assertIn("IPC_LOCK forbidden by policy", checks["tunedPodAdmission"]["detail"])

    def test_unschedulable_tuned_pod_is_unknown_not_warning(self) -> None:
        tuned = dict(EMPTY_TUNED)
        tuned.update(attempted=True, admitted=True, ready=False, reason="0/2 nodes available")
        checks = evaluate(stock_facts(), tuned)
        self.assertEqual(checks["tunedPodAdmission"]["status"], "unknown")

    def test_effective_tuned_pod_passes(self) -> None:
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
        checks = evaluate(stock_facts(), tuned)
        self.assertEqual(checks["tunedPodAdmission"]["status"], "pass")

    def test_ineffective_tuned_pod_warns(self) -> None:
        tuned = {
            "attempted": True,
            "admitted": True,
            "ready": True,
            "reason": "",
            "node": "n1",
            "rdmaResourceRequested": "",
            "facts": stock_facts(),
        }
        checks = evaluate(stock_facts(), tuned)
        self.assertEqual(checks["tunedPodAdmission"]["status"], "warning")

    def test_missing_facts_grade_unknown(self) -> None:
        checks = evaluate(None)
        for name in ("memlock", "shm", "rdmaDevices", "gdrcopyDevice"):
            self.assertEqual(checks[name]["status"], "unknown")


class AggregateTests(unittest.TestCase):
    def test_stock_defaults_aggregate_to_warning_with_no_failures(self) -> None:
        checks = evaluate(stock_facts())
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
    def test_default_pod_is_unprivileged_with_no_security_context(self) -> None:
        manifest = check.pod_manifest(
            "default", "cmax-tenant-default-x", "img", gpu_key="nvidia.com/gpu", tuned=False, rdma_resource="", tuned_shm="8Gi"
        )
        container = manifest["spec"]["containers"][0]
        self.assertNotIn("securityContext", container)
        self.assertNotIn("volumes", manifest["spec"])
        self.assertEqual(container["resources"]["limits"], {"nvidia.com/gpu": "1"})
        self.assertFalse(manifest["spec"].get("hostNetwork", False))

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
        self.assertNotIn("privileged", str(manifest))

    def test_dra_cluster_pod_requests_no_gpu(self) -> None:
        manifest = check.pod_manifest(
            "default", "cmax-tenant-default-x", "img", gpu_key="", tuned=False, rdma_resource="", tuned_shm="8Gi"
        )
        self.assertNotIn("resources", manifest["spec"]["containers"][0])


class HarnessGateTests(unittest.TestCase):
    def test_non_k8s_harness_is_not_applicable(self) -> None:
        result = check.run_default_check("slurm")["tenant_pod_defaults"]
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["failures"], [])

    def test_check_disable_switch_grades_unknown(self) -> None:
        import os

        os.environ["CLUSTERMAX_AUDIT_TENANT_POD_CHECK"] = "0"
        try:
            result = check.run_default_check("k8s")["tenant_pod_defaults"]
        finally:
            del os.environ["CLUSTERMAX_AUDIT_TENANT_POD_CHECK"]
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
