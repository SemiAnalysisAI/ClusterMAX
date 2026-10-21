"""Platform configuration and executable check entrypoints."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import json
import sys

CHECK_PATH = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
    / "platform_config.py"
)

SPEC = importlib.util.spec_from_file_location("platform_config", CHECK_PATH)

assert SPEC and SPEC.loader

platform_config = importlib.util.module_from_spec(SPEC)

SPEC.loader.exec_module(platform_config)

def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

def write_pci_device(root: Path, bdf: str, *, vendor: str, pci_class: str, group: str | None) -> None:
    device = root / "sys/bus/pci/devices" / bdf
    write(device / "vendor", f"{vendor}\n")
    write(device / "class", f"{pci_class}\n")
    write(device / "device", "0x2330\n")
    if group is None:
        return
    group_dir = root / "sys/kernel/iommu_groups" / group
    group_dir.mkdir(parents=True, exist_ok=True)
    (device / "iommu_group").symlink_to(group_dir)

def write_host_trees(root: Path) -> None:
    # Missing trees mean a partial vantage, not an empty host.
    for tree in ("etc", "var/run"):
        (root / tree).mkdir(parents=True, exist_ok=True)

def write_vm_guest(root: Path) -> None:
    write_host_trees(root)
    write(root / "sys/class/dmi/id/sys_vendor", "QEMU\n")
    write(root / "sys/class/dmi/id/product_name", "Standard PC (Q35 + ICH9, 2009)\n")
    write(root / "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme de pse hypervisor lm\n")

def write_bare_metal_identity(root: Path) -> None:
    write(root / "sys/class/dmi/id/sys_vendor", "Supermicro\n")
    write(root / "sys/class/dmi/id/product_name", "AS-8125GS-TNHR\n")
    write(root / "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme de pse lm\n")

def write_bare_metal(root: Path) -> None:
    write_host_trees(root)
    write_bare_metal_identity(root)

def collect(root: Path, **kwargs):
    kwargs.setdefault("harness", "standalone")
    kwargs.setdefault("machine", "x86_64")
    kwargs.setdefault("env", {})
    kwargs.setdefault("hostname", "node-0")

    kwargs.setdefault("runner", _never_run)
    return platform_config.collect_host(root=root, **kwargs)

def _never_run(command, **kwargs):  # pragma: no cover - guards accidental exec
    raise AssertionError(f"the check must not run {command} against a fake root")

class VirtualizationDetectionTests(unittest.TestCase):
    def test_qemu_dmi_and_hypervisor_flag_report_a_guest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], True)
            self.assertEqual(result["type"], "qemu")

    def test_bare_metal_dmi_without_hypervisor_flag_reports_no_guest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], False)

    def test_cloud_dmi_on_a_metal_instance_does_not_override_the_bare_metal_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/class/dmi/id/sys_vendor", "Amazon EC2\n")
            write(root / "sys/class/dmi/id/product_name", "p5.48xlarge.metal\n")
            write(root / "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme de pse lm\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], False)
            self.assertEqual(result["type"], "none")

            write(root / "proc/cmdline", "ro\n")
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")
            summaries = collect(root, machine="aarch64")["summaries"]

            self.assertEqual(summaries["vm_iommu"]["status"], "warning")
            self.assertIs(summaries["vm_iommu"]["evidence"]["virtualization"]["detected"], False)

            self.assertEqual(summaries["arm_smmu_virtualization"]["status"], "not_applicable")

    def test_hypervisor_sysfs_does_not_override_a_bare_metal_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "sys/hypervisor/type", "xen\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], False)
            self.assertEqual(result["type"], "none")

            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            summaries = collect(root, machine="aarch64")["summaries"]
            self.assertEqual(summaries["arm_smmu_virtualization"]["status"], "not_applicable")

    def test_the_host_detector_outranks_every_weaker_signal_on_xen_dom0(self) -> None:

        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "none\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_host_trees(root)
            write(root / "proc/1/ns/mnt", "")
            write(root / "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme de pse lm hypervisor\n")
            write(root / "sys/hypervisor/type", "xen\n")
            write(root / "sys/class/dmi/id/sys_vendor", "Xen\n")
            result = platform_config.detect_virtualization(root, runner=runner)
            self.assertIs(result["detected"], False)
            self.assertEqual(result["type"], "none")

    def test_hypervisor_sysfs_decides_when_nothing_stronger_is_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/hypervisor/type", "xen\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], True)
            self.assertEqual(result["type"], "xen")

    def test_dmi_still_decides_when_no_stronger_signal_is_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/class/dmi/id/sys_vendor", "QEMU\n")
            write(root / "sys/class/dmi/id/product_name", "KVM Virtual Machine\n")
            write(root / "proc/cpuinfo", "processor\t: 0\nFeatures\t: fp asimd\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], True)
            self.assertEqual(result["type"], "qemu")

    def test_a_cloud_vendor_string_alone_never_asserts_a_guest(self) -> None:
        for vendor, product in (
            ("Amazon EC2", "c7g.metal"),
            ("Google Compute Engine", "Google Compute Engine"),
            ("Alibaba Cloud", "Alibaba Cloud ECS"),
        ):
            with self.subTest(vendor=vendor), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write(root / "sys/class/dmi/id/sys_vendor", f"{vendor}\n")
                write(root / "sys/class/dmi/id/product_name", f"{product}\n")
                write(root / "proc/cpuinfo", "processor\t: 0\nFeatures\t: fp asimd\n")
                result = platform_config.detect_virtualization(root, runner=_never_run)
                self.assertIsNone(result["detected"])

                (root / "sys/class/iommu/smmu3.0x0000000012000000").mkdir(parents=True)
                summary = collect(root, machine="aarch64")["summaries"]["arm_smmu_virtualization"]
                self.assertEqual(summary["status"], "unknown")

    def test_a_cloud_vendor_string_still_names_a_guest_found_by_another_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/class/dmi/id/sys_vendor", "Amazon EC2\n")
            write(root / "sys/class/dmi/id/product_name", "c7g.8xlarge\n")
            write(root / "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu hypervisor lm\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], True)
            self.assertEqual(result["type"], "amazon")

    def test_a_chrooted_read_asks_the_host_through_its_init_mount_namespace(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            calls.append(list(command))
            return subprocess.CompletedProcess(command, 0, "kvm\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "proc/1/ns/mnt", "")
            write(root / "sys/class/dmi/id/sys_vendor", "Amazon EC2\n")
            write(root / "proc/cpuinfo", "processor\t: 0\nFeatures\t: fp asimd\n")
            result = platform_config.detect_virtualization(root, runner=runner)

        self.assertEqual(calls, [["nsenter", "--target", "1", "--mount", "--", "systemd-detect-virt"]])
        self.assertIs(result["detected"], True)
        self.assertEqual(result["type"], "kvm")

    def test_a_chrooted_read_without_host_pid_does_not_shell_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/class/dmi/id/sys_vendor", "Supermicro\n")
            platform_config.detect_virtualization(root, runner=_never_run)

    def test_unreadable_host_leaves_virtualization_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = platform_config.detect_virtualization(Path(tmp), runner=_never_run)
            self.assertIsNone(result["detected"])

class KernelCmdlineTests(unittest.TestCase):
    def test_last_value_of_a_repeated_parameter_wins(self) -> None:
        params = platform_config.parse_kernel_cmdline("ro iommu=pt quiet iommu=off")
        self.assertEqual(params["iommu"], "off")
        self.assertEqual(params["quiet"], "")

    def test_passthrough_is_recognized_from_every_spelling(self) -> None:
        for cmdline in ("iommu=pt", "intel_iommu=pt", "amd_iommu=pt", "iommu.passthrough=1"):
            with self.subTest(cmdline=cmdline):
                params = platform_config.parse_kernel_cmdline(cmdline)
                self.assertTrue(platform_config.iommu_passthrough_requested(params))

class VmIommuTests(unittest.TestCase):
    def test_guest_with_full_dma_translation_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            write_pci_device(
                root,
                "0000:07:00.0",
                vendor="0x10de",
                pci_class="0x030200",
                group="12",
            )
            write_pci_device(
                root,
                "0000:08:00.0",
                vendor="0x15b3",
                pci_class="0x020700",
                group="13",
            )

            report = collect(root)
            self.assertEqual(report["iommu"]["mode"], "translated")
            self.assertEqual(report["summaries"]["vm_iommu"]["status"], "warning")
            self.assertIs(report["summaries"]["vm_iommu"]["evidence"]["virtualization"]["detected"], True)
            groups = {device["bdf"]: device["iommu_group"] for device in report["iommu"]["devices"]}
            self.assertEqual(groups, {"0000:07:00.0": "12", "0000:08:00.0": "13"})

    def test_guest_with_passthrough_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on iommu=pt\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")

            report = collect(root)
            self.assertEqual(report["iommu"]["mode"], "passthrough")
            self.assertEqual(report["summaries"]["vm_iommu"]["status"], "pass")

    def test_host_without_gpu_or_rdma_devices_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            write_pci_device(root, "0000:00:1f.0", vendor="0x8086", pci_class="0x060100", group="1")

            report = collect(root)
            self.assertEqual(report["summaries"]["vm_iommu"]["status"], "not_applicable")

    def test_unreadable_pci_bus_is_unknown_not_absent_hardware(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)

            report = collect(root)
            self.assertIs(report["iommu"]["devices_read"], False)
            verdict = report["summaries"]["vm_iommu"]
            self.assertEqual(verdict["status"], "unknown")

    def test_unreadable_cmdline_and_sysfs_report_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group=None)

            report = collect(root)
            self.assertEqual(report["iommu"]["mode"], "unknown")
            self.assertEqual(report["summaries"]["vm_iommu"]["status"], "unknown")

class ArmSmmuTests(unittest.TestCase):
    def test_x86_host_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            report = collect(root, machine="x86_64")
            self.assertEqual(report["summaries"]["arm_smmu_virtualization"]["status"], "not_applicable")

    def test_bare_metal_arm_host_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            report = collect(root, machine="aarch64")
            self.assertEqual(report["summaries"]["arm_smmu_virtualization"]["status"], "not_applicable")

    def test_arm_guest_with_smmuv3_and_no_cmdqv_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "sys/class/dmi/id/product_name", "NVIDIA Grace Hopper\n")
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            report = collect(root, machine="aarch64")
            smmu = report["summaries"]["arm_smmu_virtualization"]
            self.assertEqual(smmu["status"], "warning")
            self.assertEqual(smmu["evidence"]["arm_smmu"]["smmuv3_units"], ["smmu3.0.auto"])
            self.assertIs(smmu["evidence"]["arm_smmu"]["vcmdq_exposed"], False)
            self.assertIs(smmu["evidence"]["arm_smmu"]["grace_platform"], True)

    def test_arm_guest_not_identified_as_grace_is_not_warned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "sys/class/dmi/id/sys_vendor", "Ampere Computing LLC\n")
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            report = collect(root, machine="aarch64")
            smmu = report["summaries"]["arm_smmu_virtualization"]
            self.assertEqual(smmu["status"], "unknown")
            self.assertEqual(smmu["warnings"], [])
            self.assertIs(smmu["evidence"]["arm_smmu"]["grace_platform"], False)

    def test_devicetree_naming_grace_identifies_the_platform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "sys/firmware/devicetree/base/compatible", "nvidia,tegra241\x00")
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            report = collect(root, machine="aarch64")
            smmu = report["summaries"]["arm_smmu_virtualization"]
            self.assertEqual(smmu["status"], "warning")
            self.assertIs(smmu["evidence"]["arm_smmu"]["grace_platform"], True)

    def test_grace_product_names_identify_the_platform(self) -> None:
        for product in ("NVIDIA GH200 480GB", "NVIDIA GB200 NVL72", "NVIDIA GB300 NVL72"):
            with self.subTest(product=product):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_vm_guest(root)
                    write(root / "sys/class/dmi/id/product_name", f"{product}\n")
                    (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
                    report = collect(root, machine="aarch64")
                    smmu = report["summaries"]["arm_smmu_virtualization"]
                    self.assertEqual(smmu["status"], "warning")
                    self.assertIs(smmu["evidence"]["arm_smmu"]["grace_platform"], True)

    def test_arm_guest_with_bound_cmdqv_driver_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            driver = root / "sys/bus/platform/drivers/tegra241_cmdqv"
            driver.mkdir(parents=True)
            device = root / "sys/devices/platform/tegra241_cmdqv.0"
            device.mkdir(parents=True)
            (driver / "tegra241_cmdqv.0").symlink_to(device)

            report = collect(root, machine="aarch64")
            self.assertEqual(report["summaries"]["arm_smmu_virtualization"]["status"], "pass")

    def test_arm_guest_with_cmdqv_devicetree_node_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            (root / "sys/class/iommu/smmu3.0.auto").mkdir(parents=True)
            write(
                root / "sys/firmware/devicetree/base/bus@0/iommu@8000000/compatible",
                "nvidia,tegra241-cmdqv\x00arm,smmu-v3\x00",
            )
            report = collect(root, machine="aarch64")
            self.assertEqual(report["summaries"]["arm_smmu_virtualization"]["status"], "pass")

    def test_arm_guest_without_any_smmu_evidence_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            report = collect(root, machine="aarch64")
            self.assertEqual(report["summaries"]["arm_smmu_virtualization"]["status"], "unknown")

class NcclTopoFileTests(unittest.TestCase):
    def _host_with_topo_file(self, root: Path, env: dict[str, str]) -> dict:
        write(root / "etc/nccl/topo.xml", "<system version=\"1\"/>\n")
        write_bare_metal(root)
        return collect(root, env=env)

    def test_no_host_topology_file_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            report = collect(root)
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "not_applicable")

    def test_a_tree_the_vantage_cannot_see_is_not_an_absent_topology_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for tree in ("proc", "sys", "etc"):
                (root / tree).mkdir()
            write_bare_metal_identity(root)
            report = collect(root)
            self.assertEqual(
                report["nccl"]["topo_candidates_unreachable"],
                [platform_config.NCCL_DEFAULT_TOPO_FILE],
            )
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(
                result["unreachable_topo_candidates"],
                [platform_config.NCCL_DEFAULT_TOPO_FILE],
            )

    def test_the_host_check_pod_reaches_every_tree_a_topology_file_can_live_in(self) -> None:
        manifest = platform_config.pod_manifest("audit", {"name": "node-0"}, "image:tag", "pod-0")
        container = manifest["spec"]["containers"][0]
        volumes = {volume["name"]: volume["hostPath"]["path"] for volume in manifest["spec"]["volumes"]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for mount in container["volumeMounts"]:
                path = mount["mountPath"]
                self.assertTrue(path.startswith("/host/"), path)
                self.assertEqual(volumes[mount["name"]], path[len("/host") :])
                (root / path[len("/host/") :]).mkdir(parents=True, exist_ok=True)
            write_bare_metal_identity(root)
            report = collect(root)
            self.assertEqual(report["nccl"]["topo_candidates_unreachable"], [])

    def test_a_nonstandard_name_in_etc_nccl_is_found_by_the_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl/site-fabric.xml", '<system version="1"/>\n')
            write_bare_metal(root)
            report = collect(root)
            self.assertEqual(report["nccl"]["topo_files_readable"], ["/etc/nccl/site-fabric.xml"])

    def test_the_host_read_records_size_digest_and_xml_shape(self) -> None:
        body = '<system version="1"/>\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl/topo.xml", body)
            write_bare_metal(root)
            evidence = collect(root)["nccl"]["topo_file_evidence"]["/etc/nccl/topo.xml"]
            self.assertEqual(evidence["size"], len(body))
            self.assertEqual(evidence["sha256"], hashlib.sha256(body.encode()).hexdigest())
            self.assertIs(evidence["xml_ok"], True)

    def test_a_declaration_pointing_at_nothing_is_not_applicable_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            (root / "var/run/nvidia-topologyd").mkdir(parents=True)
            report = collect(root, env={"NCCL_TOPO_FILE": "/etc/nccl/removed-last-week.xml"})
            self.assertEqual(report["nccl"]["topo_file_declared"], "/etc/nccl/removed-last-week.xml")
            self.assertEqual(report["nccl"]["topo_files_readable"], [])
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "not_applicable")

    def test_a_shadowed_file_at_the_right_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "topo_file_evidence": {
                        "/etc/nccl/topo.xml": {"size": 64, "sha256": "0" * 64, "xml": "ok"},
                    },
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")
            self.assertNotEqual(
                result["host_topo_file_evidence"]["/etc/nccl/topo.xml"]["sha256"],
                "0" * 64,
            )

    def test_per_node_topology_files_are_not_a_shadowed_mount(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            root_a, root_b = Path(tmp_a), Path(tmp_b)
            env = {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"}
            write(root_a / "etc/nccl/topo.xml", '<system version="1"><cpu numaid="0"/></system>\n')
            write(root_b / "etc/nccl/topo.xml", '<system version="1"><cpu numaid="1"/></system>\n')
            write_bare_metal(root_a)
            write_bare_metal(root_b)
            report_a, report_b = collect(root_a, env=env), collect(root_b, env=env)
            digests = [
                report["nccl"]["topo_file_evidence"]["/etc/nccl/topo.xml"]["sha256"]
                for report in (report_a, report_b)
            ]
            self.assertNotEqual(digests[0], digests[1])
            result = platform_config.summarize_nccl_topo_file(
                reports=[report_a, report_b],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "topo_file_evidence": {
                        "/etc/nccl/topo.xml": {"size": 46, "sha256": digests[0], "xml": "ok"},
                    },
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["failures"], [])
            self.assertEqual(sorted(result["host_topo_file_digests"]), sorted(digests))

    def test_content_no_checked_node_published_is_still_shadowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            root_a, root_b = Path(tmp_a), Path(tmp_b)
            env = {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"}
            write(root_a / "etc/nccl/topo.xml", '<system version="1"><cpu numaid="0"/></system>\n')
            write(root_b / "etc/nccl/topo.xml", '<system version="1"><cpu numaid="1"/></system>\n')
            write_bare_metal(root_a)
            write_bare_metal(root_b)
            result = platform_config.summarize_nccl_topo_file(
                reports=[collect(root_a, env=env), collect(root_b, env=env)],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "topo_file_evidence": {
                        "/etc/nccl/topo.xml": {"size": 64, "sha256": "0" * 64, "xml": "ok"},
                    },
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")

    def test_a_node_that_published_no_digest_withdraws_the_shadow_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            root_a, root_b = Path(tmp_a), Path(tmp_b)
            env = {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"}
            write(root_a / "etc/nccl/topo.xml", '<system version="1"><cpu numaid="0"/></system>\n')
            write_bare_metal(root_a)
            write_bare_metal(root_b)
            result = platform_config.summarize_nccl_topo_file(
                reports=[collect(root_a, env=env), collect(root_b, env=env)],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "topo_file_evidence": {
                        "/etc/nccl/topo.xml": {"size": 64, "sha256": "0" * 64, "xml": "ok"},
                    },
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "pass")

    def test_an_empty_or_unparseable_file_in_the_container_fails(self) -> None:
        for evidence, label in (
            ({"size": 0, "xml": "bad"}, "empty"),
            ({"size": 120, "xml": "bad"}, "not XML"),
        ):
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
                    result = platform_config.summarize_nccl_topo_file(
                        reports=[report],
                        container={
                            "available": True,
                            "topo_file_env": "/etc/nccl/topo.xml",
                            "topo_files_readable": ["/etc/nccl/topo.xml"],
                            "topo_file_evidence": {"/etc/nccl/topo.xml": evidence},
                            "completed": True,
                        },
                        errors=[],
                    )
                    self.assertEqual(result["status"], "fail")

    def test_a_launcher_that_drops_the_job_environment_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "",
                    "topo_file_conf": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["host_topo_file_env"], "/etc/nccl/topo.xml")

    def test_container_that_resolves_the_file_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            self.assertEqual(report["nccl"]["topo_files_readable"], ["/etc/nccl/topo.xml"])
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "pass")

    def test_container_that_declares_the_file_only_in_nccl_conf_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl.conf", "NCCL_TOPO_FILE=/etc/nccl/topo.xml\n")
            report = self._host_with_topo_file(root, {})
            self.assertEqual(report["nccl"]["topo_file_env"], "")
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "",
                    "topo_file_conf": "/etc/nccl/topo.xml",
                    "topo_files_readable": ["/etc/nccl/topo.xml"],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["container_topo_file_source"], platform_config.TOPO_SOURCE_CONF)
            self.assertEqual(result["container_topo_file"], "/etc/nccl/topo.xml")

    def test_conf_declared_file_that_is_not_mounted_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "",
                    "topo_file_conf": "/etc/nccl/topo.xml",
                    "topo_files_readable": [],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["container_topo_file_source"], platform_config.TOPO_SOURCE_CONF)
            self.assertEqual(result["container_topo_file"], "/etc/nccl/topo.xml")

    def test_env_propagated_but_file_not_mounted_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "/etc/nccl/topo.xml",
                    "topo_files_readable": [],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["container_topo_file_source"], platform_config.TOPO_SOURCE_ENV)
            self.assertEqual(result["container_topo_file"], "/etc/nccl/topo.xml")

    def test_env_not_propagated_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "fail")

            self.assertEqual(result["container_topo_file_source"], "")
            self.assertEqual(result["container_topo_file"], "")

    def test_container_resolves_the_nccl_built_in_default_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "",
                    "topo_file_conf": "",
                    "topo_files_readable": [platform_config.NCCL_DEFAULT_TOPO_FILE],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["container_topo_file_source"], platform_config.TOPO_SOURCE_DEFAULT)
            self.assertEqual(result["container_topo_file"], platform_config.NCCL_DEFAULT_TOPO_FILE)

    def test_no_declaration_and_no_default_path_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={
                    "available": True,
                    "topo_file_env": "",
                    "topo_file_conf": "",
                    "topo_files_readable": ["/etc/nccl/topo.xml.bak"],
                    "completed": True,
                },
                errors=[],
            )
            self.assertEqual(result["status"], "fail")

    def test_no_host_checked_is_unknown_not_absent_topology(self) -> None:
        result = platform_config.summarize_nccl_topo_file(
            reports=[],
            container={"available": False, "reason": "no host was checked"},
            errors=["all node check pods failed"],
        )
        self.assertEqual(result["status"], "unknown")

    def test_no_container_vantage_is_unknown_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host_with_topo_file(root, {"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})
            reason = "no container launcher vantage on the k8s harness"
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": False, "reason": reason},
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")

            self.assertIn(reason, result["message"])

    def test_topo_file_declared_in_nccl_conf_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl.conf", "# site defaults\nNCCL_TOPO_FILE=/etc/nccl/topo.xml\n")
            write(root / "etc/nccl/topo.xml", "<system version=\"1\"/>\n")
            write_bare_metal(root)
            report = collect(root)
            self.assertEqual(report["nccl"]["topo_file_declared"], "/etc/nccl/topo.xml")
            self.assertTrue(report["nccl"]["declared_topo_file_readable"])

    def test_enroot_hook_that_mounts_the_topology_file_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/enroot/mounts.d/10-nccl.fstab", "/etc/nccl/topo.xml /etc/nccl/topo.xml none bind\n")
            report = collect(root)
            self.assertEqual(
                report["nccl"]["enroot"]["files_mentioning_topology"],
                ["/etc/enroot/mounts.d/10-nccl.fstab"],
            )

    def test_an_unreadable_enroot_tree_costs_one_field_not_every_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/enroot/mounts.d/10-nccl.fstab", "/etc/nccl/topo.xml /etc/nccl/topo.xml none bind\n")
            write(root / "etc/nccl/topo.xml", "<system></system>\n")

            def raising_rglob(self, pattern):
                raise OSError(errno.EIO, "Input/output error")

            with mock.patch.object(Path, "rglob", raising_rglob):
                report = collect(root, env={"NCCL_TOPO_FILE": "/etc/nccl/topo.xml"})

            self.assertEqual(report["nccl"]["enroot"]["files_mentioning_topology"], [])
            self.assertEqual(report["nccl"]["enroot"]["present_paths"], ["/etc/enroot/mounts.d"])

            self.assertEqual(report["nccl"]["topo_file_declared"], "/etc/nccl/topo.xml")
            self.assertTrue(report["nccl"]["declared_topo_file_readable"])
            self.assertEqual(sorted(report["summaries"]), ["arm_smmu_virtualization", "vm_iommu"])

    def test_an_enroot_entry_that_cannot_be_stat_ed_costs_one_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/enroot/mounts.d/10-nccl.fstab", "/etc/nccl/topo.xml /etc/nccl/topo.xml none bind\n")

            def raising_is_file(self):
                raise OSError(errno.ESTALE, "Stale file handle")

            with mock.patch.object(Path, "is_file", raising_is_file):
                report = collect(root)

            self.assertEqual(report["nccl"]["enroot"]["present_paths"], ["/etc/enroot/mounts.d"])
            self.assertEqual(sorted(report["summaries"]), ["arm_smmu_virtualization", "vm_iommu"])

    def test_an_entry_that_cannot_be_stat_ed_is_unreachable_not_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/nccl/topo.xml", "<system version=\"1\"/>\n")

            def raising_is_file(self):
                raise OSError(errno.ESTALE, "Stale file handle")

            with mock.patch.object(Path, "is_file", raising_is_file):
                self.assertEqual(
                    platform_config.glob_topo_files(root),
                    ["/etc/nccl/topo.xml"],
                )
                report = collect(root)

            self.assertEqual(sorted(report["summaries"]), ["arm_smmu_virtualization", "vm_iommu"])
            self.assertEqual(report["nccl"]["topo_files_readable"], [])
            self.assertIn("/etc/nccl/topo.xml", report["nccl"]["topo_candidates_unreachable"])

            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")

    def test_a_tree_that_cannot_be_stat_ed_is_unreachable_not_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)

            def raising_is_dir(self):
                raise OSError(errno.EACCES, "Permission denied")

            with mock.patch.object(Path, "is_dir", raising_is_dir):
                report = collect(root)

            self.assertIn(
                platform_config.NCCL_DEFAULT_TOPO_FILE,
                report["nccl"]["topo_candidates_unreachable"],
            )
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")

class ContainerCheckTests(unittest.TestCase):
    def test_check_script_runs_in_a_real_shell_and_reports_a_readable_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            topo = Path(tmp) / "topo.xml"
            topo.write_text("<system version=\"1\"/>\n")
            script = platform_config.container_check_script([str(topo)])
            proc = subprocess.run(
                ["/bin/sh", "-c", script],
                stdout=subprocess.PIPE,
                text=True,
                env={"NCCL_TOPO_FILE": str(topo), "PATH": "/usr/bin:/bin"},
                check=True,
            )
            parsed = platform_config.parse_container_check(proc.stdout)
            self.assertTrue(parsed["completed"])
            self.assertEqual(parsed["topo_file_env"], str(topo))
            self.assertEqual(parsed["topo_files_readable"], [str(topo)])

    def test_check_script_reads_the_topology_file_declared_only_in_nccl_conf(self) -> None:
        for conf_body, label in (
            ("NCCL_TOPO_FILE={path}\n", "plain"),
            ('NCCL_TOPO_FILE="{path}"\n', "double quoted"),
            ("NCCL_TOPO_FILE = {path}   # site topology\n", "spaced and commented"),
            ("NCCL_DEBUG=INFO\nNCCL_TOPO_FILE={path}\n", "after another key"),
        ):
            with self.subTest(conf=label):
                with tempfile.TemporaryDirectory() as tmp:
                    topo = Path(tmp) / "topo.xml"
                    topo.write_text("<system version=\"1\"/>\n")
                    conf = Path(tmp) / "nccl.conf"
                    conf.write_text(conf_body.format(path=topo))
                    script = platform_config.container_check_script([], conf_path=str(conf))
                    proc = subprocess.run(
                        ["/bin/sh", "-c", script],
                        stdout=subprocess.PIPE,
                        text=True,
                        env={"PATH": "/usr/bin:/bin"},
                        check=True,
                    )
                    parsed = platform_config.parse_container_check(proc.stdout)
                    self.assertEqual(parsed["topo_file_env"], "")
                    self.assertEqual(parsed["topo_file_conf"], str(topo))
                    self.assertEqual(parsed["topo_files_readable"], [str(topo)])

    def test_shell_and_python_agree_on_the_conf_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            topo = Path(tmp) / "topo.xml"
            topo.write_text("<system version=\"1\"/>\n")
            body = f'NCCL_TOPO_FILE = "{topo}"  # site topology\n'
            conf = Path(tmp) / "nccl.conf"
            conf.write_text(body)
            script = platform_config.container_check_script([], conf_path=str(conf))
            proc = subprocess.run(
                ["/bin/sh", "-c", script], stdout=subprocess.PIPE, text=True,
                env={"PATH": "/usr/bin:/bin"}, check=True,
            )
            from_shell = platform_config.parse_container_check(proc.stdout)["topo_file_conf"]
            from_python = platform_config.parse_nccl_conf(body)["NCCL_TOPO_FILE"]
            self.assertEqual(from_shell, from_python)

    def test_check_script_reports_a_missing_mount(self) -> None:
        script = platform_config.container_check_script(["/etc/nccl/topo.xml"])
        proc = subprocess.run(
            ["/bin/sh", "-c", script],
            stdout=subprocess.PIPE,
            text=True,
            env={"NCCL_TOPO_FILE": "/etc/nccl/topo.xml", "PATH": "/usr/bin:/bin"},
            check=True,
        )
        parsed = platform_config.parse_container_check(proc.stdout)
        self.assertTrue(parsed["completed"])
        self.assertEqual(parsed["topo_file_env"], "/etc/nccl/topo.xml")
        self.assertEqual(parsed["topo_files_readable"], [])

    def test_the_shell_and_the_host_reader_agree_on_size_and_digest(self) -> None:
        body = '<system version="1"><cpu numaid="0"/></system>\n'
        with tempfile.TemporaryDirectory() as tmp:
            topo = Path(tmp) / "topo.xml"
            topo.write_text(body)
            script = platform_config.container_check_script([str(topo)])
            proc = subprocess.run(
                ["/bin/sh", "-c", script],
                stdout=subprocess.PIPE,
                text=True,
                env={"PATH": "/usr/bin:/bin", "NCCL_DEBUG": "INFO"},
                check=True,
            )
            parsed = platform_config.parse_container_check(proc.stdout)
            seen = parsed["topo_file_evidence"][str(topo)]
            host = platform_config.describe_topo_file(topo)
            self.assertEqual(seen["size"], host["size"])
            self.assertEqual(seen["xml"], "ok")
            if "sha256" in seen:
                self.assertEqual(seen["sha256"], host["sha256"])
            self.assertEqual(parsed["nccl_env"]["NCCL_DEBUG"], "INFO")

    def test_the_shell_reports_a_file_that_is_not_xml_as_bad(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            topo = Path(tmp) / "topo.xml"
            topo.write_text("this is not xml\n")
            script = platform_config.container_check_script([str(topo)])
            proc = subprocess.run(
                ["/bin/sh", "-c", script], stdout=subprocess.PIPE, text=True,
                env={"PATH": "/usr/bin:/bin"}, check=True,
            )
            parsed = platform_config.parse_container_check(proc.stdout)
            self.assertEqual(parsed["topo_file_evidence"][str(topo)]["xml"], "bad")
            self.assertIs(platform_config.describe_topo_file(topo)["xml_ok"], False)

    def test_a_launch_that_never_ran_is_no_vantage_not_a_missing_mount(self) -> None:
        def runner(command, **kwargs):
            raise OSError(errno.EAGAIN, "Resource temporarily unavailable")

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertIs(result["available"], False)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl/topo.xml", '<system version="1"/>\n')
            write_bare_metal(root)
            summary = platform_config.summarize_nccl_topo_file(
                reports=[collect(root)], container=result, errors=[]
            )
            self.assertEqual(summary["status"], "unknown")

    def test_candidate_with_shell_metacharacters_is_dropped(self) -> None:
        script = platform_config.container_check_script(["/etc/nccl/topo.xml", "/tmp/'; touch /tmp/pwned; '"])
        self.assertNotIn("pwned", script)
        subprocess.run(["/bin/sh", "-n", "-c", script], check=True)

    def test_no_usable_candidate_still_emits_valid_shell(self) -> None:
        script = platform_config.container_check_script([])
        proc = subprocess.run(
            ["/bin/sh", "-c", script],
            stdout=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
            check=True,
        )
        self.assertTrue(platform_config.parse_container_check(proc.stdout)["completed"])

    def test_container_check_is_skipped_off_slurm(self) -> None:
        result = platform_config.run_container_check(
            harness="k8s", env={}, candidates=["/etc/nccl/topo.xml"], runner=_never_run
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["reason_code"], "no_launcher_on_harness")
        self.assertEqual(result["harness"], "k8s")

    def test_the_disable_switch_does_not_invent_a_finding_off_slurm(self) -> None:
        for harness in ("k8s", "standalone"):
            with self.subTest(harness=harness):
                result = platform_config.run_container_check(
                    harness=harness,
                    env={"CLUSTERMAX_AUDIT_NCCL_CONTAINER_CHECK": "0"},
                    candidates=["/etc/nccl/topo.xml"],
                    runner=_never_run,
                )
                self.assertFalse(result["available"])
                self.assertEqual(result["reason_code"], "no_launcher_on_harness")

    def test_container_check_honors_the_disable_switch(self) -> None:
        result = platform_config.run_container_check(
            harness="slurm",
            env={"CLUSTERMAX_AUDIT_NCCL_CONTAINER_CHECK": "0", "SLURM_JOB_ID": "1"},
            candidates=["/etc/nccl/topo.xml"],
            runner=_never_run,
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["reason_code"], "check_disabled")

    def test_container_check_uses_pyxis_and_parses_the_worker_output(self) -> None:
        seen: dict[str, list[str]] = {}

        def runner(command, **kwargs):
            seen["command"] = command
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="topo_file_env=/etc/nccl/topo.xml\nreadable=/etc/nccl/topo.xml\ncheck=done\n",
                stderr="",
            )

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42", "CLUSTERMAX_PYXIS_CHECK_IMAGE": "nvcr.io#nvidia/pytorch:26.04-py3"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertTrue(result["available"])
        self.assertEqual(result["topo_files_readable"], ["/etc/nccl/topo.xml"])
        self.assertIn("--container-image=nvcr.io#nvidia/pytorch:26.04-py3", seen["command"])

    def test_incomplete_worker_output_is_not_available(self) -> None:
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="pyxis: image import failed\n")

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertFalse(result["available"])
        self.assertIn("image import failed", result["stderr"])

class NcclIbQpsTests(unittest.TestCase):
    def _host(self, root: Path, env: dict[str, str], *, rdma: bool = True) -> dict:
        write_bare_metal(root)
        if rdma:
            for device in ("mlx5_0", "mlx5_1"):
                write(root / f"sys/class/infiniband/{device}/ports/1/link_layer", "InfiniBand\n")
        return collect(root, env=env)

    def _qps(
        self,
        reports: list[dict],
        *,
        node_count: int,
        node_count_scope: str = "cluster",
        fabric_tiers: int = 0,
        clos_node_threshold: int = platform_config.DEFAULT_CLOS_NODE_THRESHOLD,
    ) -> dict:
        return platform_config.summarize_nccl_ib_qps(
            reports=reports,
            node_count=node_count,
            node_count_scope=node_count_scope,
            fabric_tiers=fabric_tiers,
            clos_node_threshold=clos_node_threshold,
            errors=[],
        )

    def test_default_qps_on_a_multi_tier_fabric_warns_and_never_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            self.assertEqual(report["nccl"]["qps_per_connection"], 1)
            self.assertEqual(report["nccl"]["rdma"]["fabric"], "InfiniBand")
            result = self._qps([report], node_count=128, fabric_tiers=3)
            self.assertEqual(result["status"], "warning")
            self.assertIs(result["multi_tier"], True)
            self.assertEqual(result["fabric_shape_basis"], "topology (3 tiers)")

            self.assertEqual(result["failures"], [])
            self.assertEqual(result["warnings"], [result["message"]])

    def test_a_single_tier_fabric_is_not_applicable_however_wide_it_is(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=128, fabric_tiers=1)
            self.assertEqual(result["status"], "not_applicable")
            self.assertIs(result["multi_tier"], False)
            self.assertEqual(result["fabric_shape_basis"], "topology (single tier)")

    def test_a_cluster_below_the_node_threshold_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=8, fabric_tiers=0)
            self.assertEqual(result["status"], "not_applicable")
            self.assertEqual(result["fabric_shape_basis"], "node count (8 <= 64)")

    def test_a_cluster_above_the_node_threshold_is_read_as_multi_tier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=128, fabric_tiers=0)
            self.assertEqual(result["status"], "warning")
            self.assertEqual(result["fabric_shape_basis"], "node count (128 > 64)")
            self.assertEqual(result["clos_node_threshold"], 64)

    def test_the_node_threshold_moves_the_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            self.assertEqual(
                self._qps([report], node_count=40, clos_node_threshold=32)["status"], "warning"
            )
            self.assertEqual(
                self._qps([report], node_count=40, clos_node_threshold=64)["status"], "not_applicable"
            )

    def test_tuned_qps_passes_on_a_multi_tier_fabric(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {"NCCL_IB_QPS_PER_CONNECTION": "4"})
            self.assertEqual(report["nccl"]["qps_per_connection"], 4)
            self.assertEqual(report["nccl"]["qps_source"], "environment")
            result = self._qps([report], node_count=128, fabric_tiers=3)
            self.assertEqual(result["status"], "pass")

    def test_the_recommended_minimum_passes_and_one_below_it_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            at_minimum = self._host(root / "at-minimum", {"NCCL_IB_QPS_PER_CONNECTION": "2"})
            below = self._host(root / "below", {"NCCL_IB_QPS_PER_CONNECTION": "1"})
            self.assertEqual(self._qps([at_minimum], node_count=128, fabric_tiers=2)["status"], "pass")
            self.assertEqual(self._qps([below], node_count=128, fabric_tiers=2)["status"], "warning")

    def test_qps_from_nccl_conf_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl.conf", "NCCL_IB_QPS_PER_CONNECTION=4\n")
            report = self._host(root, {})
            self.assertEqual(report["nccl"]["qps_per_connection"], 4)
            self.assertEqual(report["nccl"]["qps_source"], "nccl.conf")

    def test_host_without_rdma_devices_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {}, rdma=False)

            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "not_applicable")

    def test_no_topology_and_no_node_count_is_unknown_not_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=0, fabric_tiers=0)
            self.assertEqual(result["status"], "unknown")
            self.assertIsNone(result["multi_tier"])

    def test_unreadable_sysfs_is_unknown_not_absent_rdma(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = collect(root, env={})
            self.assertIs(report["nccl"]["rdma"]["sysfs_read"], False)
            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "unknown")

    def test_an_unreadable_infiniband_class_is_unknown_not_absent_rdma(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)

            write(root / "sys/class/infiniband", "")
            self.assertTrue(platform_config.sysfs_class_readable(root))

            report = collect(root, env={})
            self.assertIs(report["nccl"]["rdma"]["sysfs_read"], False)
            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["rdma_sysfs_unread_hosts"], 1)

    def test_one_host_that_read_an_empty_class_does_not_answer_for_an_unread_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readable = self._host(root / "readable", {}, rdma=False)
            unread = collect(root / "unread", env={}, hostname="node-1")
            self.assertIs(readable["nccl"]["rdma"]["sysfs_read"], True)
            self.assertIs(unread["nccl"]["rdma"]["sysfs_read"], False)
            result = self._qps([readable, unread], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["rdma_sysfs_unread_hosts"], 1)

    def test_no_host_checked_is_unknown_not_absent_rdma(self) -> None:
        result = self._qps([], node_count=128, fabric_tiers=2)
        self.assertEqual(result["status"], "unknown")

    def test_small_allocation_does_not_pass_a_fabric_of_unknown_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=2, node_count_scope="allocation", fabric_tiers=0)
            self.assertEqual(result["status"], "unknown")

    def test_a_small_allocation_on_a_read_topology_is_still_graded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=2, node_count_scope="allocation", fabric_tiers=3)
            self.assertEqual(result["status"], "warning")
            self.assertEqual(result["fabric_shape_basis"], "topology (3 tiers)")

class SlurmFabricScaleTests(unittest.TestCase):

    SINFO = (
        "node001      gpu:h100:8(S:0-1)\n"
        "node002      gpu:h100:8(S:0-1)\n"
        "node001      gpu:h100:8(S:0-1)\n"
        "login01      (null)\n"
        "storage01    (null)\n"
        "\n"
    )

    def _count(self, stdout: str, *, returncode: int = 0) -> tuple[int, list[str]]:
        proc = subprocess.CompletedProcess(args=["sinfo"], returncode=returncode, stdout=stdout, stderr="")
        with mock.patch.object(platform_config, "run_command", return_value=proc) as runner:
            result = platform_config.slurm_cluster_node_count()
        self.assertIn("%G", " ".join(runner.call_args.args[0]))
        return result

    def test_cpu_nodes_do_not_inflate_the_fabric(self) -> None:
        names, total = platform_config.parse_sinfo_gpu_nodes(self.SINFO)
        self.assertEqual(names, ["node001", "node002"])
        self.assertEqual(total, 4)
        self.assertEqual(self._count(self.SINFO), (2, []))

    def test_gres_entries_are_matched_by_resource_name(self) -> None:
        for gres, expected in (
            ("gpu:8", True),
            ("gpu:h100:8(S:0-1)", True),
            ("shard:h100:16,gpu:h100:8", True),
            ("(null)", False),
            ("", False),
            ("shard:h100:16", False),

            ("gpushard:8", False),
            ("shard:gpu-h100:16", False),
        ):
            with self.subTest(gres=gres):
                self.assertIs(platform_config.gres_names_gpu(gres), expected)

    def test_a_cluster_with_no_gres_reports_no_count(self) -> None:
        count, errors = self._count("login01      (null)\nnode001      (null)\n")
        self.assertEqual(count, 0)
        self.assertEqual(len(errors), 1)

        self.assertIn("gres", errors[0])
        self.assertIn("2 node", errors[0])
        self.assertIn("not known", errors[0])

    def test_a_failed_sinfo_reports_no_count(self) -> None:
        count, errors = self._count("", returncode=1)
        self.assertEqual(count, 0)
        self.assertIn("not known", errors[0])

    def test_a_cpu_only_fabric_grades_unknown_rather_than_passing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "sys/class/infiniband/mlx5_0/ports/1/link_layer", "InfiniBand\n")
            report = collect(root)
            result = platform_config.summarize_nccl_ib_qps(
                reports=[report],
                node_count_scope="allocation",
                node_count=2,
                fabric_tiers=0,
                clos_node_threshold=platform_config.DEFAULT_CLOS_NODE_THRESHOLD,
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")

            self.assertEqual(result["rdma_sysfs_unread_hosts"], 0)
            self.assertEqual(result["rdma_devices"], ["mlx5_0"])
            self.assertIn("allocation", result["message"])

class LocalFallbackVantageTests(unittest.TestCase):

    def _local_report(self, root: Path) -> dict:
        write_bare_metal(root)
        report = collect(root)
        report["check_scope"] = "local"
        return report

    def test_a_local_stand_in_does_not_clear_the_topology_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self._local_report(Path(tmp))
            result = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")
            self.assertIn("no GPU host was checked", result["message"])

    def test_a_local_stand_in_does_not_clear_the_queue_pair_advisory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self._local_report(Path(tmp))
            result = platform_config.summarize_nccl_ib_qps(
                reports=[report],
                node_count_scope="cluster",
                node_count=512,
                fabric_tiers=3,
                clos_node_threshold=platform_config.DEFAULT_CLOS_NODE_THRESHOLD,
                errors=[],
            )
            self.assertEqual(result["status"], "unknown")
            self.assertIn("no GPU host was checked", result["message"])

    def test_a_read_of_the_fabric_still_grades_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            report = collect(root)
            self.assertNotIn("check_scope", report)
            topo = platform_config.summarize_nccl_topo_file(
                reports=[report],
                container={"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True},
                errors=[],
            )
            self.assertEqual(topo["status"], "not_applicable")
            qps = platform_config.summarize_nccl_ib_qps(
                reports=[report],
                node_count_scope="cluster",
                node_count=512,
                fabric_tiers=3,
                clos_node_threshold=platform_config.DEFAULT_CLOS_NODE_THRESHOLD,
                errors=[],
            )
            self.assertEqual(qps["status"], "not_applicable")

    def test_one_fabric_host_beside_a_stand_in_is_not_a_local_vantage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = self._local_report(root / "local")
            write_bare_metal(root / "remote")
            remote = collect(root / "remote")
            self.assertFalse(platform_config.vantage_is_local_only([local, remote]))
            self.assertTrue(platform_config.vantage_is_local_only([local]))
            self.assertFalse(platform_config.vantage_is_local_only([]))

    def test_missing_slurm_workers_never_substitute_local_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)

            base = collect(root)

            def fake_collect_host(**kwargs):  # noqa: ARG001
                return dict(base)

            with mock.patch.object(platform_config, "collect_host", fake_collect_host):
                with mock.patch.dict(os.environ, {}, clear=True):
                    reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual(reports, [])

                with mock.patch.dict(os.environ, {"SLURM_JOB_ID": "1", "SLURM_NNODES": "2"}, clear=True):
                    with mock.patch.object(platform_config, "run_command", side_effect=OSError("no srun")):
                        reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual(reports, [])

                    empty = subprocess.CompletedProcess(args=["srun"], returncode=0, stdout="", stderr="")
                    with mock.patch.object(platform_config, "run_command", return_value=empty):
                        reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual(reports, [])

    def test_kubernetes_with_no_gpu_node_grades_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)

            base = collect(root)

            def fake_collect_host(**kwargs):  # noqa: ARG001
                return dict(base)

            with mock.patch.object(platform_config, "collect_host", fake_collect_host):
                with mock.patch.object(platform_config, "k8s_gpu_node_list", return_value=([], ["no nodes"])):
                    with mock.patch.dict(os.environ, {}, clear=True):
                        payload = platform_config.run_default_check("k8s")
            for key in ("vm_iommu", "arm_smmu_virtualization", "nccl_ib_qps"):
                with self.subTest(key=key):
                    self.assertEqual(payload[key]["status"], "unknown")
            self.assertNotIn("nccl_topo_file", payload)

    def test_a_stand_in_does_not_clear_the_platform_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "proc/cmdline", "ro iommu=pt\n")
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")
            report = collect(root)
            report["check_scope"] = "local"

            self.assertEqual(
                [report["summaries"][key]["status"] for key in ("vm_iommu", "arm_smmu_virtualization")],
                ["pass", "not_applicable"],
            )
            payload = platform_config.build_payload(
                reports=[report],
                errors=[],
                container={"available": False, "reason_code": "no_allocation"},
                node_count=0,
            )
            for key in ("vm_iommu", "arm_smmu_virtualization"):
                with self.subTest(key=key):
                    self.assertEqual(payload[key]["status"], "unknown")
                    self.assertIn("stand-in", payload[key]["message"])

    def test_a_stand_in_that_reads_badly_keeps_its_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")
            report = collect(root)
            report["check_scope"] = "local"
            payload = platform_config.build_payload(
                reports=[report],
                errors=[],
                container={"available": False, "reason_code": "no_allocation"},
                node_count=0,
            )
            self.assertEqual(payload["vm_iommu"]["status"], "warning")

class FabricTierCountTests(unittest.TestCase):

    def test_scontrol_levels_give_an_exact_tier_count(self) -> None:
        dump = (
            "SwitchName=leaf1 Level=0 Nodes=node[001-016]\n"
            "SwitchName=leaf2 Level=0 Nodes=node[017-032]\n"
            "SwitchName=spine1 Level=1 Switches=leaf[1-2]\n"
        )
        self.assertEqual(platform_config.count_fabric_tiers(dump), 2)

    def test_three_levels_report_three_tiers(self) -> None:
        dump = (
            "SwitchName=leaf1 Level=0 Nodes=node[001-016]\n"
            "SwitchName=spine1 Level=1 Switches=leaf[1-8]\n"
            "SwitchName=core1 Level=2 Switches=spine[1-4]\n"
        )
        self.assertEqual(platform_config.count_fabric_tiers(dump), 3)

    def test_a_topology_conf_with_child_switches_is_at_least_two_tiers(self) -> None:
        conf = "SwitchName=leaf1 Nodes=node[001-016]\nSwitchName=spine1 Switches=leaf[1-8]\n"
        self.assertEqual(platform_config.count_fabric_tiers(conf), 2)

    def test_topology_comments_do_not_invent_fabric_tiers(self) -> None:
        conf = """# Example: SwitchName=spine Switches=leaf[0-15]
SwitchName=leaf0 Nodes=node[001-016] # Level=7
"""
        self.assertEqual(platform_config.count_fabric_tiers(conf), 1)

    def test_a_lone_switch_with_nodes_is_one_tier(self) -> None:
        self.assertEqual(platform_config.count_fabric_tiers("SwitchName=leaf1 Nodes=node[001-016]\n"), 1)

    def test_repeated_blocks_are_read_as_multi_tier(self) -> None:
        conf = "BlockName=b1 Nodes=node[001-018]\nBlockName=b2 Nodes=node[019-036]\n"
        self.assertEqual(platform_config.count_fabric_tiers(conf), 2)

    def test_a_single_block_is_one_tier(self) -> None:
        self.assertEqual(platform_config.count_fabric_tiers("BlockName=b1 Nodes=node[001-018]\n"), 1)

    def test_topology_yaml_children_prove_a_second_tier(self) -> None:
        yaml_text = "switches:\n  - switch: spine1\n    children: leaf[1-8]\n  - switch: leaf1\n    nodes: node[001-016]\n"
        self.assertEqual(platform_config.count_fabric_tiers(yaml_text), 2)

    def test_no_topology_data_reports_zero_not_one(self) -> None:
        for text in ("", "   \n", "there is no topology plugin configured\n"):
            with self.subTest(text=text):
                self.assertEqual(platform_config.count_fabric_tiers(text), 0)

class SlurmFabricTiersTests(unittest.TestCase):
    def _tiers(self, proc, files: dict[str, str]) -> tuple[int, list[str]]:
        def fake_read(path):
            return files.get(str(path), "")

        with mock.patch.object(platform_config, "run_command", return_value=proc):
            with mock.patch.object(platform_config, "read_text", side_effect=fake_read):
                return platform_config.slurm_fabric_tiers()

    def test_scontrol_is_preferred(self) -> None:
        proc = subprocess.CompletedProcess(
            args=["scontrol"],
            returncode=0,
            stdout="SwitchName=leaf1 Level=0 Nodes=n[1-16]\nSwitchName=spine1 Level=1 Switches=leaf1\n",
            stderr="",
        )
        self.assertEqual(self._tiers(proc, {}), (2, []))

    def test_a_failed_scontrol_falls_back_to_the_topology_file(self) -> None:
        proc = subprocess.CompletedProcess(args=["scontrol"], returncode=1, stdout="", stderr="no topology")
        files = {"/etc/slurm/topology.conf": "SwitchName=leaf1 Nodes=n[1-16]\nSwitchName=spine1 Switches=leaf1\n"}
        self.assertEqual(self._tiers(proc, files), (2, []))

    def test_no_topology_anywhere_reports_zero_with_a_reason(self) -> None:
        proc = subprocess.CompletedProcess(args=["scontrol"], returncode=1, stdout="", stderr="")
        tiers, errors = self._tiers(proc, {})
        self.assertEqual(tiers, 0)
        self.assertIn("not known", errors[0])

    def test_an_absent_scontrol_is_not_an_error(self) -> None:
        with mock.patch.object(platform_config, "run_command", side_effect=FileNotFoundError("srun")):
            with mock.patch.object(platform_config, "read_text", return_value=""):
                tiers, errors = platform_config.slurm_fabric_tiers()
        self.assertEqual(tiers, 0)
        self.assertEqual(len(errors), 1)

class FabricShapeTests(unittest.TestCase):
    def _shape(self, *, fabric_tiers: int, node_count: int, clos_node_threshold: int = 64):
        return platform_config.classify_fabric_shape(
            fabric_tiers=fabric_tiers,
            node_count=node_count,
            clos_node_threshold=clos_node_threshold,
        )

    def test_the_threshold_is_exclusive_at_its_own_value(self) -> None:
        self.assertIs(self._shape(fabric_tiers=0, node_count=64)[0], False)
        self.assertIs(self._shape(fabric_tiers=0, node_count=65)[0], True)

class NoPyxisClassificationTests(unittest.TestCase):

    def _classify(self, stderr: str) -> str:
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr=stderr)

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertIs(result["available"], False)
        return result["reason_code"]

    def test_a_rejected_container_image_flag_is_the_absent_plugin(self) -> None:
        for stderr in (
            "srun: unrecognized option '--container-image'\n",
            "srun: unrecognized option '--container-image=nvcr.io#nvidia/pytorch:26.04-py3'\n",
            "srun: invalid option -- 'container-image'\n",
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(self._classify(stderr), "no_pyxis")

    def test_a_pyxis_failure_that_echoes_the_flag_is_not_an_absent_plugin(self) -> None:
        for stderr in (
            "slurmstepd: error: pyxis: container start failed with --container-image=docker://alpine:3\n",
            "slurmstepd: error: pyxis: couldn't start container\nsrun: error: task 0 exited with code 1\n",
            "enroot: failed to import image\n",
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(self._classify(stderr), "check_incomplete")

    def test_a_plugin_that_failed_to_load_is_not_an_absent_plugin(self) -> None:
        stderr = (
            "srun: error: spank: pyxis.so: Plugin failed to load\n"
            "srun: unrecognized option '--container-image=docker://alpine:3'\n"
        )
        self.assertEqual(self._classify(stderr), "check_incomplete")

    def test_a_different_rejected_option_is_not_an_absent_plugin(self) -> None:
        self.assertEqual(self._classify("srun: unrecognized option '--overlap'\n"), "check_incomplete")

    def test_an_error_that_merely_quotes_the_command_is_not_an_absent_plugin(self) -> None:
        stderr = (
            "srun: error: Unable to create step for job 42: Requested node configuration is not available\n"
            "srun: launching with --container-image=docker://alpine:3\n"
        )
        self.assertEqual(self._classify(stderr), "check_incomplete")

    def test_an_empty_stderr_is_not_an_absent_plugin(self) -> None:
        self.assertEqual(self._classify(""), "check_incomplete")

    def test_the_rejection_and_the_flag_must_be_on_one_line(self) -> None:
        stderr = "srun: unrecognized option '--overlap'\nsrun: using --container-image=docker://alpine:3\n"
        self.assertIs(platform_config.stderr_says_no_pyxis(stderr), False)

class CheckImageTests(unittest.TestCase):

    def test_the_campaign_image_is_the_default(self) -> None:
        env = {"CLUSTERMAX_CONTAINER_IMAGE": "nvcr.io#nvidia/pytorch:25.01-py3"}
        self.assertEqual(platform_config.check_container_image(env), "nvcr.io#nvidia/pytorch:25.01-py3")

    def test_an_explicit_check_image_wins(self) -> None:
        env = {
            "CLUSTERMAX_CONTAINER_IMAGE": "nvcr.io#nvidia/pytorch:25.01-py3",
            "CLUSTERMAX_PYXIS_CHECK_IMAGE": "docker://alpine:3",
        }
        self.assertEqual(platform_config.check_container_image(env), "docker://alpine:3")

    def test_an_empty_value_does_not_win(self) -> None:
        env = {"CLUSTERMAX_PYXIS_CHECK_IMAGE": "  ", "CLUSTERMAX_CONTAINER_IMAGE": "docker://alpine:3"}
        self.assertEqual(platform_config.check_container_image(env), "docker://alpine:3")

    def test_no_environment_falls_back_to_the_repo_pin(self) -> None:
        self.assertEqual(platform_config.check_container_image({}), platform_config.PINNED_CHECK_IMAGE)

    def test_the_launcher_runs_the_resolved_image_and_adds_no_mount(self) -> None:
        calls: list[list[str]] = []

        def record(command, timeout=None):
            calls.append(command)
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="{}", stderr="")

        platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "1", "CLUSTERMAX_CONTAINER_IMAGE": "docker://alpine:3"},
            candidates=["/etc/nccl/topo.xml"],
            runner=record,
        )
        argv = calls[0]
        self.assertIn("--container-image=docker://alpine:3", argv)
        self.assertFalse([arg for arg in argv if arg.startswith(("--container-mounts", "--mount"))])

class HarnessSkipPathTests(unittest.TestCase):

    def _payload(self, harness: str, root: Path) -> dict:
        with mock.patch.object(platform_config, "collect_host", return_value=collect(root)):
            with mock.patch.dict(os.environ, {}, clear=True):
                return platform_config.run_default_check(harness)

    def test_standalone_omits_scheduler_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "sys/class/infiniband/mlx5_0/node_type", "1: CA\n")
            payload = self._payload("standalone", root)
            self.assertNotIn("nccl_ib_qps", payload)
            self.assertNotIn("nccl_topo_file", payload)

    def test_standalone_collection_does_not_read_scale_out_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")
            write_pci_device(root, "0000:08:00.0", vendor="0x15b3", pci_class="0x020700", group="13")

            with mock.patch.object(
                platform_config,
                "collect_nccl",
                side_effect=AssertionError(
                    "standalone must not collect NCCL or RDMA configuration"
                ),
            ):
                report = platform_config.collect_host(
                    root=root,
                    harness="standalone",
                    machine="x86_64",
                    env={},
                    hostname="node-0",
                    runner=_never_run,
                    include_scale_out=False,
                )

            self.assertEqual(report["nccl"], {})
            self.assertEqual(
                [device["kind"] for device in report["iommu"]["devices"]],
                ["gpu"],
            )

class ClosThresholdEnvTests(unittest.TestCase):

    def _threshold(self, value: str | None) -> int:
        env = {} if value is None else {"CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD": value}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            with mock.patch.object(
                platform_config, "k8s_gpu_node_list", return_value=([], [])
            ), mock.patch.object(
                platform_config, "collect_host", return_value=collect(root)
            ), mock.patch.dict(os.environ, env, clear=True):
                payload = platform_config.run_default_check("k8s")
        return payload["nccl_ib_qps"]["clos_node_threshold"]

    def test_the_default_is_sixty_four(self) -> None:
        self.assertEqual(self._threshold(None), platform_config.DEFAULT_CLOS_NODE_THRESHOLD)
        self.assertEqual(self._threshold(None), 64)

    def test_an_operator_value_is_honored(self) -> None:
        self.assertEqual(self._threshold("16"), 16)

    def test_a_junk_or_zero_value_falls_back_to_the_default(self) -> None:
        for value in ("0", "-8", "not-a-number", ""):
            with self.subTest(value=value):
                self.assertEqual(self._threshold(value), 64)

class ContainerCheckSkipTests(unittest.TestCase):

    def _run(self, root: Path) -> tuple[dict, list]:
        calls: list[dict] = []

        def record(**kwargs):
            calls.append(kwargs)
            return {"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True}

        with mock.patch.object(platform_config, "run_container_check", side_effect=record):
            with mock.patch.object(platform_config, "collect_host", return_value=collect(root)):
                payload = platform_config.run_default_check("standalone")
        return payload, calls

    def test_a_standalone_host_topology_file_does_not_start_the_slurm_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/nccl/topo.xml", "<system version=\"1\"/>\n")
            payload, calls = self._run(root)
            self.assertEqual(calls, [])
            self.assertNotIn("nccl_topo_file", payload)

class AggregationTests(unittest.TestCase):
    def _summary_report(self, host: str, status: str) -> dict:
        return {"host": host, "summaries": {"vm_iommu": platform_config.summary(status, f"{status} on {host}")}}

    def test_a_warning_host_outranks_passing_hosts(self) -> None:
        reports = [
            self._summary_report("node-0", "pass"),
            self._summary_report("node-1", "warning"),
        ]
        result = platform_config.aggregate_check("vm_iommu", reports, [])
        self.assertEqual(result["status"], "warning")
        self.assertIn("node-1", result["message"])
        self.assertEqual(result["hosts_checked"], 2)

    def test_a_not_applicable_host_does_not_hide_a_passing_host(self) -> None:
        reports = [
            self._summary_report("node-0", "not_applicable"),
            self._summary_report("node-1", "pass"),
        ]
        self.assertEqual(platform_config.aggregate_check("vm_iommu", reports, [])["status"], "pass")

    def test_an_unread_host_is_not_hidden_by_a_not_applicable_sibling(self) -> None:
        reports = [
            self._summary_report("node-0", "not_applicable"),
            self._summary_report("node-1", "unknown"),
        ]
        result = platform_config.aggregate_check("vm_iommu", reports, [])
        self.assertEqual(result["status"], "unknown")
        self.assertIn("node-1", result["message"])

    def test_no_reports_aggregate_to_unknown(self) -> None:
        result = platform_config.aggregate_check("vm_iommu", [], ["srun host check failed"])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["warnings"], ["srun host check failed"])

    def test_the_aggregate_keeps_the_reading_each_host_verdict_came_from(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "root=/dev/vda1 ro intel_iommu=on\n")
            write(root / "sys/class/iommu/dmar0/type", "DMAR\n")
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")

            payload = platform_config.build_payload(
                reports=[collect(root, hostname="node-7")],
                errors=[],
                container={"available": False, "reason": "standalone harness"},
                node_count=1,
            )
            iommu = payload["vm_iommu"]
            self.assertEqual(iommu["status"], "warning")
            evidence = iommu["hosts"]["node-7"]["evidence"]
            self.assertEqual(evidence["iommu"]["mode"], "translated")
            self.assertEqual(evidence["iommu"]["cmdline_params"], {"intel_iommu": "on"})
            self.assertEqual(
                [(device["bdf"], device["kind"], device["iommu_group"]) for device in evidence["iommu"]["devices"]],
                [("0000:07:00.0", "gpu", "12")],
            )
            self.assertTrue(evidence["virtualization"]["detected"])

CHECK_ROOT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
)

sys.path.insert(0, str(CHECK_ROOT))

ENTRYPOINTS = {
    "system/vm-iommu-check.py": "vm_iommu",
    "system/arm-smmu-virtualization-check.py": "arm_smmu_virtualization",
    "fabric/nccl-topology-file-check.py": "nccl_topo_file",
    "fabric/nccl-ib-qps-check.py": "nccl_ib_qps",
}

class PlatformCheckEntrypointTests(unittest.TestCase):
    def test_shared_module_loads_fanout_without_an_entrypoint_import(self) -> None:
        script = (
            "import importlib.util\n"
            f"path = {str(CHECK_ROOT / 'platform_config.py')!r}\n"
            "spec = importlib.util.spec_from_file_location('platform_config_isolated', path)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "print(module.load_fanout().__file__)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                cwd=tmp,
            )

        self.assertEqual(
            Path(run.stdout.strip()).resolve(),
            (CHECK_ROOT / "_fanout.py").resolve(),
        )

    def test_each_entrypoint_emits_only_its_check(self) -> None:
        payload = {
            key: {"status": "pass", "message": f"{key} passed"}
            for key in ENTRYPOINTS.values()
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "platform-config.json"
            cache.write_text(
                json.dumps({"harness": "slurm", "payload": payload})
            )
            env = {
                **os.environ,
                "CLUSTERMAX_AUDIT_HARNESS": "slurm",
                platform_config.CACHE_PATH_ENV: str(cache),
            }
            for relative, key in ENTRYPOINTS.items():
                with self.subTest(check=relative):
                    run = subprocess.run(
                        [sys.executable, str(CHECK_ROOT / relative)],
                        check=True,
                        capture_output=True,
                        text=True,
                        env=env,
                    )
                    self.assertEqual(json.loads(run.stdout), {key: payload[key]})

    def test_named_checks_reuse_collection_from_the_audit_cache(self) -> None:
        payload = {
            key: {"status": "pass", "message": f"{key} passed"}
            for key in platform_config.ALL_CHECK_KEYS
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "platform-config.json"
            with mock.patch.dict(
                os.environ,
                {
                    platform_config.CACHE_PATH_ENV: str(cache),
                    platform_config.REQUESTED_CHECKS_ENV: ",".join(payload),
                },
                clear=False,
            ), mock.patch.object(
                platform_config,
                "run_default_check",
                return_value=payload,
            ) as collect:
                first = platform_config.run_named_check("vm_iommu", "slurm")
                second = platform_config.run_named_check("nccl_ib_qps", "slurm")

        self.assertEqual(first, {"vm_iommu": payload["vm_iommu"]})
        self.assertEqual(second, {"nccl_ib_qps": payload["nccl_ib_qps"]})
        collect.assert_called_once_with("slurm", set(payload))

    def test_hardware_check_omits_scale_out_collection(self) -> None:
        report = {
            "host": "node-0",
            "summaries": {
                "vm_iommu": {
                    "status": "pass",
                    "message": "IOMMU uses passthrough",
                },
                "arm_smmu_virtualization": {
                    "status": "not_applicable",
                    "message": "the host is not an Arm guest",
                },
            },
            "nccl": {},
        }
        payload = {
            "vm_iommu": report["summaries"]["vm_iommu"],
            "arm_smmu_virtualization": report["summaries"][
                "arm_smmu_virtualization"
            ],
            "nccl_topo_file": {"status": "not_applicable", "message": "none"},
            "nccl_ib_qps": {"status": "not_applicable", "message": "none"},
        }
        with mock.patch.object(
            platform_config,
            "run_slurm_check",
            return_value=([report], []),
        ) as collect, mock.patch.object(
            platform_config,
            "slurm_cluster_node_count",
            side_effect=AssertionError("hardware check must not count fabric nodes"),
        ), mock.patch.object(
            platform_config,
            "slurm_fabric_tiers",
            side_effect=AssertionError("hardware check must not inspect fabric tiers"),
        ), mock.patch.object(
            platform_config,
            "run_container_check",
            side_effect=AssertionError("hardware check must not start a container"),
        ), mock.patch.object(
            platform_config,
            "build_payload",
            return_value=payload,
        ):
            result = platform_config.run_default_check("slurm", {"vm_iommu"})

        self.assertEqual(result, {"vm_iommu": payload["vm_iommu"]})
        collect.assert_called_once_with(
            "slurm",
            include_scale_out=False,
            include_rdma_iommu=True,
        )
