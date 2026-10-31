#!/usr/bin/env python3
"""Synthetic metadata and runner contracts for passive VF/interface exposure."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
CHECK = AUDIT_SCRIPTS / "checks" / "fabric" / "vf-interface-exposure.py"
SPEC = importlib.util.spec_from_file_location("vf_exposure_under_test", CHECK)
assert SPEC and SPEC.loader
exposure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exposure)

MERGE_SPEC = importlib.util.spec_from_file_location(
    "vf_exposure_merge", AUDIT_SCRIPTS / "merge_audit.py"
)
assert MERGE_SPEC and MERGE_SPEC.loader
merge = importlib.util.module_from_spec(MERGE_SPEC)
MERGE_SPEC.loader.exec_module(merge)

RUNNER_SPEC = importlib.util.spec_from_file_location(
    "vf_exposure_runner", AUDIT_SCRIPTS / "run_checks.py"
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner_module = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner_module)


def write(root: Path, name: str, text: str = "") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def fixture(root: Path) -> Path:
    """Synthetic PCI/VF/HCA inventory, never recorded as cluster data."""
    pci = root / "sys/bus/pci/devices/0000:03:00.1"
    write(root, str(pci.relative_to(root) / "vendor"), "0x15b3\n")
    write(root, str(pci.relative_to(root) / "device"), "0x101e\n")
    pf = root / "sys/bus/pci/devices/0000:03:00.0"
    pf.mkdir(parents=True)
    (pci / "physfn").symlink_to(pf)
    driver = root / "sys/bus/pci/drivers/mlx5_core"
    driver.mkdir(parents=True)
    (pci / "driver").symlink_to(driver)
    group = root / "sys/kernel/iommu_groups/7"
    group.mkdir(parents=True)
    (pci / "iommu_group").symlink_to(group)
    hca = root / "sys/class/infiniband/mlx5_test"
    hca.mkdir(parents=True)
    (hca / "device").symlink_to(pci)
    write(root, "sys/class/infiniband/mlx5_test/fw_ver", "32.44.1000\n")
    verbs = root / "sys/class/infiniband_verbs/uverbs7"
    verbs.mkdir(parents=True)
    # Linux uverbs ibdev_show emits a text attribute, not a symlink.
    (verbs / "ibdev").write_text("mlx5_test\n")
    write(root, "dev/infiniband/uverbs7")
    write(root, "dev/vfio/7")
    write(root, "proc/self/status", "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0\nSeccomp:\t2\n")
    write(root, "proc/self/uid_map", "0 100000 65536\n")
    return pci


class MetadataTests(unittest.TestCase):
    def test_maps_vf_firmware_and_device_nodes_without_open_or_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            original_open = Path.open

            def metadata_only(path, *args, **kwargs):
                self.assertNotIn("/dev/", str(path))
                return original_open(path, *args, **kwargs)

            with mock.patch.object(Path, "open", metadata_only), mock.patch.object(
                exposure.subprocess, "run", side_effect=AssertionError("no commands")
            ):
                record = exposure.collect(root=root)
        vf = next(d for d in record["devices"] if d["pci_address"] == "0000:03:00.1")
        self.assertEqual(vf["function_type"], "vf")
        self.assertEqual(vf["physical_function"], "0000:03:00.0")
        self.assertEqual(vf["driver"], "mlx5_core")
        self.assertEqual(vf["hcas"][0]["firmware"], "32.44.1000")
        self.assertEqual(vf["hcas"][0]["name"], "mlx5_test")
        self.assertEqual(
            {n["path"] for n in vf["interfaces"]},
            {"/dev/infiniband/uverbs7", "/dev/vfio/7"},
        )
        self.assertEqual(record["identity"]["process_status"]["CapEff"], "0")
        self.assertEqual(record["evidence"]["command_submission"], "not_tested")
        self.assertEqual(record["evidence"]["vulnerable_handler"], "unverified")
        self.assertEqual(record["evidence"]["device_code_execution"], "unverified")
        self.assertNotIn("pass", json.dumps(record))

    def test_class_attribute_files_do_not_fail_the_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            # Real kernels expose plain attribute files such as abi_version
            # next to the interface directories; they are not interfaces.
            (root / "sys/class/infiniband_verbs/abi_version").write_text("6\n")
            write(root, "sys/bus/pci/devices/0000:03:00.0/vendor", "0x15b3\n")
            record = exposure.collect(root=root)

        self.assertEqual(record["errors"], [])
        self.assertEqual(record["status"], "observed")

    def test_hidden_physfn_is_unknown_not_physical_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pci = fixture(root)
            (pci / "physfn").unlink()
            record = exposure.collect(root=root)
        vf = next(d for d in record["devices"] if d["pci_address"] == "0000:03:00.1")
        self.assertEqual(vf["function_type"], "unknown")

    def test_missing_sysfs_is_unknown_and_preserves_unmapped_device_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "dev/infiniband/uverbs0")
            record = exposure.collect(root=root)
        self.assertEqual(record["status"], "unknown")
        self.assertEqual(record["devices"], [])
        self.assertEqual(record["visible_interfaces"][0]["path"], "/dev/infiniband/uverbs0")
        self.assertTrue(record["errors"])

    def test_denied_sysfs_and_truncated_inventory_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            with mock.patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
                record = exposure.collect(root=root)
            self.assertEqual(record["status"], "unknown")
            self.assertTrue(record["errors"])
            with mock.patch.object(exposure, "MAX_ENTRIES", 1):
                record = exposure.collect(root=root)
            self.assertEqual(record["status"], "unknown")
            self.assertTrue(any("limit" in error for error in record["errors"]))


class HarnessTests(unittest.TestCase):
    def pod(self, privileged=False):
        return {
            "metadata": {"uid": "synthetic-pod-id"},
            "spec": {"nodeName": "synthetic-node", "containers": [
                {"name": "worker", "securityContext": {"privileged": privileged}},
            ]},
        }

    def record(self, host="worker-a"):
        return {
            "kind": "vf_interface_exposure", "host": host, "status": "observed",
            "devices": [], "visible_interfaces": [], "errors": [],
        }

    def test_no_controller_fallback_or_implicit_kubernetes_target(self):
        for harness in ("slurm", "k8s", "unsupported"):
            with self.subTest(harness=harness), mock.patch.object(
                exposure, "collect", side_effect=AssertionError("no local fallback")
            ):
                run = mock.Mock(side_effect=AssertionError("no remote call"))
                payload = exposure.build_payload(harness, env={}, runner=run)
                self.assertEqual(payload["vf_interface_exposure"]["status"], "unknown")
                self.assertEqual(payload["vf_interface_exposure"]["records"], [])

    def test_slurm_preserves_partial_failure_and_sends_source_on_stdin(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, json.dumps(self.record()) + "\n", "task failed"
        ))
        payload = exposure.build_payload(
            "slurm", env={"SLURM_JOB_ID": "123", "SLURM_NNODES": "2"}, runner=run
        )["vf_interface_exposure"]
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["srun", "--overlap", "--input=all"])
        self.assertIn("--collect-local", command)
        self.assertEqual(run.call_args.kwargs["input"], CHECK.read_text())
        self.assertEqual(payload["status"], "unknown")
        self.assertEqual(len(payload["records"]), 1)
        self.assertTrue(any("2" in error for error in payload["errors"]))

    def test_kubernetes_uses_only_explicit_container_without_privileged_pod(self):
        run = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(self.pod()), ""),
            subprocess.CompletedProcess([], 0, json.dumps(self.record()) + "\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps(self.pod()), ""),
        ])
        payload = exposure.build_payload("k8s", env={
            "CLUSTERMAX_AUDIT_VF_NAMESPACE": "tenant",
            "CLUSTERMAX_AUDIT_K8S_NAMESPACE": "audit-privileged",
            "CLUSTERMAX_AUDIT_VF_POD": "job-pod",
            "CLUSTERMAX_AUDIT_VF_CONTAINER": "worker",
        }, runner=run)["vf_interface_exposure"]
        self.assertEqual(run.call_args_list[1].args[0], [
            "kubectl", "-n", "tenant", "exec", "-i", "job-pod", "-c", "worker",
            "--", "python3", "-", "--collect-local",
        ])
        self.assertEqual(payload["status"], "observed")
        self.assertEqual(payload["scope"]["container"], "worker")
        self.assertEqual(payload["scope"]["coverage"], "selected_container_only")
        self.assertEqual(payload["scope"]["pod_uid"], "synthetic-pod-id")
        self.assertEqual(payload["scope"]["node"], "synthetic-node")
        self.assertTrue(payload["scope"]["pod_uid_stable"])

    def test_kubernetes_replaced_pod_keeps_partial_evidence_but_is_unknown(self):
        replaced = self.pod()
        replaced["metadata"]["uid"] = "replacement"
        run = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(self.pod()), ""),
            subprocess.CompletedProcess([], 0, json.dumps(self.record()), ""),
            subprocess.CompletedProcess([], 0, json.dumps(replaced), ""),
        ])
        payload = exposure.build_payload("k8s", env={
            "CLUSTERMAX_AUDIT_VF_POD": "job-pod",
            "CLUSTERMAX_AUDIT_VF_CONTAINER": "worker",
        }, runner=run)["vf_interface_exposure"]
        self.assertEqual(payload["status"], "unknown")
        self.assertEqual(len(payload["records"]), 1)
        self.assertFalse(payload["scope"]["pod_uid_stable"])

    def test_kubernetes_privileged_or_unreadable_target_never_becomes_tenant_evidence(self):
        for response in (
            subprocess.CompletedProcess([], 0, json.dumps(self.pod(privileged=True)), ""),
            subprocess.CompletedProcess([], 1, "", "Forbidden"),
            subprocess.CompletedProcess([], 0, "invalid JSON", ""),
        ):
            with self.subTest(response=response):
                run = mock.Mock(return_value=response)
                payload = exposure.build_payload("k8s", env={
                    "CLUSTERMAX_AUDIT_VF_NAMESPACE": "tenant",
                    "CLUSTERMAX_AUDIT_VF_POD": "job-pod",
                    "CLUSTERMAX_AUDIT_VF_CONTAINER": "worker",
                }, runner=run)["vf_interface_exposure"]
                self.assertEqual(payload["status"], "unknown")
                self.assertEqual(payload["records"], [])
                self.assertEqual(run.call_count, 1)
                self.assertNotIn("exec", run.call_args.args[0])

    def test_timeout_malformed_or_duplicate_worker_outputs_are_unknown(self):
        cases = [
            subprocess.TimeoutExpired("srun", 120),
            subprocess.CompletedProcess([], 0, '{"host":"wrong-record"}', ""),
            subprocess.CompletedProcess(
                [], 0, (json.dumps(self.record()) + "\n") * 2, ""
            ),
        ]
        for case in cases:
            with self.subTest(case=case):
                run = mock.Mock(**(
                    {"side_effect": case} if isinstance(case, Exception)
                    else {"return_value": case}
                ))
                result = exposure.build_payload(
                    "slurm", env={"SLURM_JOB_ID": "1", "SLURM_NNODES": "2"},
                    runner=run,
                )["vf_interface_exposure"]
                self.assertEqual(result["status"], "unknown")
                self.assertTrue(result["errors"])

    def test_discovery_merge_and_real_entrypoint_preserve_evidence(self):
        self.assertIn(
            CHECK, runner_module.iter_checks(AUDIT_SCRIPTS / "checks/fabric", "k8s")
        )
        proc = subprocess.run(
            [sys.executable, str(CHECK)],
            env={**os.environ, "CLUSTERMAX_AUDIT_HARNESS": "k8s",
                 "CLUSTERMAX_AUDIT_VF_POD": "", "CLUSTERMAX_AUDIT_VF_CONTAINER": ""},
            text=True, capture_output=True, timeout=10, check=True,
        )
        data = json.loads(proc.stdout)
        values = merge.build_values({}, harness="standalone", check_data=data)
        self.assertEqual(
            values["audit_data"]["vf_interface_exposure"], data["vf_interface_exposure"]
        )


if __name__ == "__main__":
    unittest.main()
