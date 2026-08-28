#!/usr/bin/env python3
"""Unit tests for the shared platform configuration implementation.

Each test builds a fake host root in a temporary directory and runs the real
``collect_host`` / summary code against it, so the assertions cover the check's
own parsing and not a restatement of its source.
"""

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
    """Create the top-level trees a full-host vantage always carries.

    The topology check separates "this tree holds no file" from "this vantage
    cannot see this tree", so a fake root that omits ``/var`` reads as a
    partial chroot rather than as a host.
    """
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
    # root is never "/" in these tests, so detect_virtualization never shells
    # out; the runner is passed only to make that explicit.
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
        """An EC2 .metal host advertises Amazon EC2 in DMI and is not a guest.

        Trusting DMI over the cpuinfo hypervisor bit would raise the guest-only
        IOMMU and SMMU warnings on bare metal.
        """
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
            # The IOMMU check still reports translated devices on bare metal,
            # but it must not call the host a guest.
            self.assertEqual(summaries["vm_iommu"]["status"], "warning")
            self.assertIs(summaries["vm_iommu"]["evidence"]["virtualization"]["detected"], False)
            # The SMMU check is guest-only and must fold to not-applicable.
            self.assertEqual(summaries["arm_smmu_virtualization"]["status"], "not_applicable")

    def test_hypervisor_sysfs_does_not_override_a_bare_metal_reading(self) -> None:
        """Xen Dom0 exposes /sys/hypervisor/type and is not a guest.

        The host that runs the hypervisor sees the same file its guests do,
        so promoting it would raise the guest-only SMMU warning on the host.
        """
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
        """Dom0 carries the CPUID hypervisor bit and exposes /sys/hypervisor/type.

        It is the host, which is why systemd-detect-virt special-cases it and
        reports "none". A weaker signal that overrode that answer would raise
        the guest-only SMMU warning on the machine running the hypervisor, and
        would report detected true beside a type of "none".
        """

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
        """aarch64 has no cpuinfo flag list, so DMI is the only signal there."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "sys/class/dmi/id/sys_vendor", "QEMU\n")
            write(root / "sys/class/dmi/id/product_name", "KVM Virtual Machine\n")
            write(root / "proc/cpuinfo", "processor\t: 0\nFeatures\t: fp asimd\n")
            result = platform_config.detect_virtualization(root, runner=_never_run)
            self.assertIs(result["detected"], True)
            self.assertEqual(result["type"], "qemu")

    def test_a_cloud_vendor_string_alone_never_asserts_a_guest(self) -> None:
        """aarch64 has no cpuinfo hypervisor bit, so DMI is the only signal.

        An EC2 .metal host and an EC2 guest write the same sys_vendor. Reading
        that as a guest raises the guest-only SMMU warning on bare metal, so it
        stays unresolved instead.
        """
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
        """The k8s check reads /host, where the pod's own detector answers for
        the pod. hostPID exposes the host's init, so the detector runs there."""
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
        """A vantage that cannot read the PCI bus must not report "no GPU".

        Reporting absence would silently self-disable the check on exactly the
        hosts it exists for.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vm_guest(root)
            write(root / "proc/cmdline", "ro intel_iommu=on\n")
            (root / "sys/class/iommu/dmar0").mkdir(parents=True)
            # No /sys/bus/pci/devices at all.

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
        """A Grace guest whose SMMUv3 has no CMDQV is the graded warning.

        The DMI product name is what identifies the platform as Grace here.
        Without it the same tree grades unknown, which is the sibling test
        below.
        """
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
        """A plain Arm guest is not graded against a Grace-only capability.

        CMDQV / VCMDQ is a Grace extension to SMMUv3, so an Ampere or Graviton
        guest with an ordinary SMMUv3 cannot expose it, and warning there would
        report a shortfall the silicon cannot fix. Nothing in this tree rules
        Grace out either, so the honest verdict is unknown rather than the
        not_applicable that would assert an absence this vantage never read.
        """
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
        """A Grace guest carrying no Grace DMI is identified by devicetree.

        A guest that boots from devicetree may carry no DMI at all, so relying
        on DMI alone would drop the warning on exactly the platform the check
        was written for.
        """
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
        """The DMI a Grace host passes through names the product, not the SoC.

        Grace ships as GH200, GB200, and GB300, and those servers boot ACPI
        rather than devicetree, so on the virtualized GB200 the blog post
        measured the product name is often the only identity signal there is.
        Matching only the SoC name would mute check 2 on its primary target.
        """
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
        """A chroot that omits /var reads the default path as empty.

        nvidia-topologyd publishes the topology file under /var/run, so a
        vantage with no view of that tree cannot establish that no host has
        one, and clearing the only hard-fail check on that reading would hide
        a real missing mount.
        """
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
        """The k8s vantage is whatever the pod mounts, so mount every candidate tree."""
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
        """Providers do not agree on the name inside /etc/nccl.

        Matching only the fixed candidate list reads a host that really has a
        topology file as having none, which clears the only hard-fail check.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "etc/nccl/site-fabric.xml", '<system version="1"/>\n')
            write_bare_metal(root)
            report = collect(root)
            self.assertEqual(report["nccl"]["topo_files_readable"], ["/etc/nccl/site-fabric.xml"])

    def test_the_host_read_records_size_digest_and_xml_shape(self) -> None:
        """The digest is what lets the container arm catch a shadowed copy."""
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
        """A stale NCCL_TOPO_FILE leaves no file to mount.

        Grading the missing mount would hard-fail a cluster for a leftover
        variable, and the container arm has no subject to inspect either.
        """
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
        """The path opens, so a readability check alone reports a pass.

        A container image that ships its own /etc/nccl/topo.xml resolves a
        topology that is not this host's, which is the silent fallback in a
        second costume.
        """
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
        """Two nodes may publish different topology files at the same path.

        A topology file describes the node it was generated for, so an
        allocation whose nodes each publish their own is healthy. The container
        runs on one node with no pin, so comparing it against a single
        last-writer-wins host would hard-fail that cluster as shadowed. The
        container here carries the first node's file byte for byte, which is
        the node a last-writer-wins merge discards.
        """
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
        """Matching no node at all is shadowing, even across differing nodes.

        Per-node files widen what counts as the host's own file; they do not
        clear a container carrying content nobody published.
        """
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
        """The container may have run on the node this vantage could not read.

        Shadowing says the content belongs to no node in the allocation. One
        node whose file this vantage never read cannot support that claim, so
        the honest reading is a pass rather than an asserted mismatch.
        """
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
        """NCCL falls back just as silently on a truncated file as a missing one."""
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
        """The host exported NCCL_TOPO_FILE and the container did not receive it.

        The file still resolves through the conf, so a resolution-only check
        passes it, while every other NCCL setting the job made is gone too.
        """
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

    def test_a_failure_carries_the_provider_side_remediation(self) -> None:
        """The graded fix is the automatic mount, not a per-job bind mount."""
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
            self.assertIn(platform_config.TOPO_REMEDIATION, result["failures"])

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
        """A conf-plus-enroot setup resolves the file with no variable set.

        The host declares the path in /etc/nccl.conf and never exports
        NCCL_TOPO_FILE, so there is no variable for the launcher to propagate
        and the conf read inside the container is the whole answer.
        """
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
            # Nothing in the container resolves a file, so no source produced one.
            self.assertEqual(result["container_topo_file_source"], "")
            self.assertEqual(result["container_topo_file"], "")

    def test_container_resolves_the_nccl_built_in_default_path(self) -> None:
        """NCCL loads its default path when nothing declares a file.

        A host running nvidia-topologyd publishes the file there with no
        environment variable and no conf entry, and a mounts.d entry that
        carries it into the container is a correct setup. Failing it would send
        a provider a finding about a cluster that is configured properly.
        """
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
        """Every host check failing is not the same as no host having a topology file.

        This is the only check that can hard-fail, so an empty read must leave
        it open instead of clearing it.
        """
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
            # The reason the vantage is missing must reach the operator.
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
        """The enroot scan runs before all four checks, so it must degrade.

        pathlib's recursive glob swallows PermissionError, so the errors that
        reach this scan are the rest of OSError. An unguarded raise here would
        abort the collector and lose all four verdicts, not just this field.
        """
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
            # Every other reading the four checks consume survived the raise.
            self.assertEqual(report["nccl"]["topo_file_declared"], "/etc/nccl/topo.xml")
            self.assertTrue(report["nccl"]["declared_topo_file_readable"])
            self.assertEqual(sorted(report["summaries"]), ["arm_smmu_virtualization", "vm_iommu"])

    def test_an_enroot_entry_that_cannot_be_stat_ed_costs_one_field(self) -> None:
        """The walk lists names without stat-ing them, so the stat raises later.

        getdents returns a stale entry's name with a usable d_type, so the
        rglob walk completes and the first stat is the per-candidate one. That
        raise must degrade this field only, exactly as the walk's own raise
        does.
        """
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
        """A directory entry we could not stat is unread, not absent.

        Path.is_file() re-raises every OSError whose errno is outside a small
        allowlist, so an ESTALE or EACCES on one entry of /etc/nccl would abort
        the host read and cost all four verdicts. Dropping the entry instead
        would push a host that really holds a topology file toward
        not_applicable, which is the absence this check must never assert from a
        failed read, so the candidate is carried through as unreachable.
        """
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

            # The host read survived, and every other check still has its reading.
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
        """The same reading applies to the tree a candidate lives under.

        If the vantage cannot stat /var, it cannot claim the default topology
        path holds nothing, so the candidate stays unreachable and the check
        grades unknown instead of not-applicable.
        """
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
        """NCCL reads /etc/nccl.conf too, so a conf-only container resolves it.

        Requiring NCCL_TOPO_FILE in the environment would fail a working
        conf-plus-enroot setup on the one check that can hard-fail.
        """
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
        """The container reads the conf in shell, the host in Python."""
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
        """The comparison only catches a shadowed file if both sides measure alike."""
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

    def test_the_launcher_adds_no_mount_of_its_own(self) -> None:
        """A bind mount here would manufacture the pass the check looks for."""
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="check=done\n", stderr="")

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertIs(result["container_mounts_added"], False)
        for argument in result["launcher_argv"]:
            self.assertNotIn("--mount", argument)
            self.assertNotIn("--container-mounts", argument)

    def test_a_launch_that_never_ran_is_no_vantage_not_a_missing_mount(self) -> None:
        """A busy allocation did not read the mount, so it found no absence."""
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

    def test_a_cluster_without_pyxis_is_no_vantage(self) -> None:
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="srun: unrecognized option '--container-image'\n"
            )

        result = platform_config.run_container_check(
            harness="slurm",
            env={"SLURM_JOB_ID": "42"},
            candidates=["/etc/nccl/topo.xml"],
            runner=runner,
        )
        self.assertIs(result["available"], False)
        self.assertEqual(result["reason_code"], "no_pyxis")

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
        """A harness with no launcher has nothing for the flag to disable.

        ``check_disabled`` is in the attestation-required set and
        ``no_launcher_on_harness`` is not, so reading the flag before the
        harness would let a skip knob raise a vendor-facing note on a harness
        this check does not cover.
        """
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
            # The check is advisory: the finding is recorded as a warning and
            # the failure list stays empty whatever the fabric looks like.
            self.assertEqual(result["failures"], [])
            self.assertEqual(result["warnings"], [result["message"]])

    def test_a_single_tier_fabric_is_not_applicable_however_wide_it_is(self) -> None:
        """Tier count beats node count: one tier has no spine to spread across.

        A 128-node single-tier fabric would clear the node threshold, so this
        traces that an exact reading of the shape overrides the fallback.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=128, fabric_tiers=1)
            self.assertEqual(result["status"], "not_applicable")
            self.assertIs(result["multi_tier"], False)
            self.assertEqual(result["fabric_shape_basis"], "topology (single tier)")

    def test_a_cluster_below_the_node_threshold_is_not_applicable(self) -> None:
        """No topology data and a small cluster: no spine tier to grade against."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=8, fabric_tiers=0)
            self.assertEqual(result["status"], "not_applicable")
            self.assertEqual(result["fabric_shape_basis"], "node count (8 <= 64)")

    def test_a_cluster_above_the_node_threshold_is_read_as_multi_tier(self) -> None:
        """A fabric wider than one leaf switch has to have a spine."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=128, fabric_tiers=0)
            self.assertEqual(result["status"], "warning")
            self.assertEqual(result["fabric_shape_basis"], "node count (128 > 64)")
            self.assertEqual(result["clos_node_threshold"], 64)

    def test_the_node_threshold_moves_the_verdict(self) -> None:
        """CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD is the knob operators reach for.

        The same 40-node cluster grades either way depending on it, so a site
        whose leaf switches are wider or narrower than the default can say so.
        """
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
        """Two is the minimum the advisory asks for, so it must not warn."""
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
            # A multi-tier fabric, so the verdict can only come from the absent
            # adapter and not from the shape gate.
            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "not_applicable")

    def test_no_topology_and_no_node_count_is_unknown_not_warning(self) -> None:
        """Neither reading available leaves the fabric shape unknown."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=0, fabric_tiers=0)
            self.assertEqual(result["status"], "unknown")
            self.assertIsNone(result["multi_tier"])

    def test_unreadable_sysfs_is_unknown_not_absent_rdma(self) -> None:
        """No /sys at all is not the same as a host with no RDMA adapter."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = collect(root, env={})
            self.assertIs(report["nccl"]["rdma"]["sysfs_read"], False)
            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "unknown")

    def test_an_unreadable_infiniband_class_is_unknown_not_absent_rdma(self) -> None:
        """A class directory that is present and unreadable is not an absence.

        Only a class directory that is missing says the host has no adapter.
        Every other read error leaves the question open, however readable
        /sys/class itself is.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            # Present, and not listable. iterdir raises NotADirectoryError,
            # which is an OSError and is not a missing class directory.
            write(root / "sys/class/infiniband", "")
            self.assertTrue(platform_config.sysfs_class_readable(root))

            report = collect(root, env={})
            self.assertIs(report["nccl"]["rdma"]["sysfs_read"], False)
            result = self._qps([report], node_count=128, fabric_tiers=2)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["rdma_sysfs_unread_hosts"], 1)

    def test_one_host_that_read_an_empty_class_does_not_answer_for_an_unread_host(self) -> None:
        """"No host has an RDMA device" is a claim about every host.

        A sibling that saw a clean empty InfiniBand class says nothing about
        the host nobody could read, so the pair is unknown, not not-applicable.
        """
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
        """A check outage read nothing, so it found no absence either."""
        result = self._qps([], node_count=128, fabric_tiers=2)
        self.assertEqual(result["status"], "unknown")

    def test_small_allocation_does_not_pass_a_fabric_of_unknown_size(self) -> None:
        """The documented audit allocation is two nodes.

        Grading that as "below the advisory scale" would clear a 512-node
        fabric, which is the scale the Exemplar post measured.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=2, node_count_scope="allocation", fabric_tiers=0)
            self.assertEqual(result["status"], "unknown")

    def test_a_small_allocation_on_a_read_topology_is_still_graded(self) -> None:
        """An exact tier count answers for the fabric, whatever the job size."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._host(root, {})
            result = self._qps([report], node_count=2, node_count_scope="allocation", fabric_tiers=3)
            self.assertEqual(result["status"], "warning")
            self.assertEqual(result["fabric_shape_basis"], "topology (3 tiers)")


class SlurmFabricScaleTests(unittest.TestCase):
    """The advisory scale must be the GPU fabric, not every node Slurm knows.

    The Kubernetes path counts only nodes advertising ``nvidia.com/gpu``.
    Counting login, storage, and other CPU nodes on Slurm would size an RDMA
    fabric from hardware that is not on it, and could draw a queue-pair warning
    on a mixed cluster whose GPU fabric is well below the advisory scale.
    """

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

    def test_a_node_in_two_partitions_is_counted_once(self) -> None:
        names, _ = platform_config.parse_sinfo_gpu_nodes(self.SINFO)
        self.assertEqual(names.count("node001"), 1)

    def test_gres_entries_are_matched_by_resource_name(self) -> None:
        for gres, expected in (
            ("gpu:8", True),
            ("gpu:h100:8(S:0-1)", True),
            ("shard:h100:16,gpu:h100:8", True),
            ("(null)", False),
            ("", False),
            ("shard:h100:16", False),
            # A resource whose own name is not "gpu" is not a GPU, however much
            # of the word it carries. Matching the field as a substring would
            # count these nodes into the fabric.
            ("gpushard:8", False),
            ("shard:gpu-h100:16", False),
        ):
            with self.subTest(gres=gres):
                self.assertIs(platform_config.gres_names_gpu(gres), expected)

    def test_a_cluster_with_no_gres_reports_no_count(self) -> None:
        """A site that never configures gres reads like a cluster with no GPUs.

        Returning the CPU node count would size the fabric from hardware that is
        not on it, and returning a count of zero as a reading would let the
        caller grade the advisory a pass for being below scale. Neither is a
        thing this vantage read, so the count is withheld and the caller falls
        back to the allocation, where the advisory grades unknown.
        """
        count, errors = self._count("login01      (null)\nnode001      (null)\n")
        self.assertEqual(count, 0)
        self.assertEqual(len(errors), 1)
        # The message must name what was read, so a reader can tell a cluster
        # whose nodes answered without GPU gres from one sinfo listed at all.
        self.assertIn("gres", errors[0])
        self.assertIn("2 node", errors[0])
        self.assertIn("not known", errors[0])

    def test_a_failed_sinfo_reports_no_count(self) -> None:
        count, errors = self._count("", returncode=1)
        self.assertEqual(count, 0)
        self.assertIn("not known", errors[0])

    def test_a_cpu_only_fabric_grades_unknown_rather_than_passing(self) -> None:
        """The whole point of withholding the count, traced to the verdict.

        A wide cluster with a handful of GPU nodes must not draw the queue-pair
        warning, and a fabric nobody sized must not be cleared either.

        The fixture has to hold an RDMA device. A host tree with no readable
        ``/sys/class/infiniband`` grades unknown two branches earlier, on the
        unread-sysfs rule, so the verdict would come out right for a reason that
        has nothing to do with the withheld count.
        """
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
            # Pin which branch answered, so the test cannot pass on the
            # unread-sysfs rule if the fixture loses its adapter.
            self.assertEqual(result["rdma_sysfs_unread_hosts"], 0)
            self.assertEqual(result["rdma_devices"], ["mlx5_0"])
            self.assertIn("allocation", result["message"])


class LocalFallbackVantageTests(unittest.TestCase):
    """A login node standing in for the fabric must not answer for the fabric.

    When the Slurm fan-out cannot run, or Kubernetes lists no GPU node, the check
    reads wherever it happens to be. That host holds no topology file and no RDMA
    adapter, which reads exactly like a clean look at a cluster that has neither.
    Grading ``not_applicable`` there clears the only hard-fail check and the
    queue-pair advisory from a machine that is not on the compute fabric.
    """

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
        """The gate must key on the stand-in flag, not on the empty reading.

        A cluster the check really did fan out to, that really has no topology
        file and no RDMA device, is out of scope for both checks and must keep
        saying so rather than degrading to unknown.
        """
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
        """The claim only fails when nothing on the fabric was read.

        A fan-out that returned compute-node output has a real vantage, whatever
        else is in the list, so the checks must grade on what those hosts hold.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = self._local_report(root / "local")
            write_bare_metal(root / "remote")
            remote = collect(root / "remote")
            self.assertFalse(platform_config.vantage_is_local_only([local, remote]))
            self.assertTrue(platform_config.vantage_is_local_only([local]))
            self.assertFalse(platform_config.vantage_is_local_only([]))

    def test_every_stand_in_read_is_stamped(self) -> None:
        """The gate is only as good as the stamping, so pin every fallback.

        Each of these branches replaces a fan-out that did not happen with a read
        of the machine the audit was launched from.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)

            base = collect(root)

            def fake_collect_host(**kwargs):  # noqa: ARG001
                return dict(base)

            with mock.patch.object(platform_config, "collect_host", fake_collect_host):
                with mock.patch.dict(os.environ, {}, clear=True):
                    reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual([report.get("check_scope") for report in reports], ["local"])

                with mock.patch.dict(os.environ, {"SLURM_JOB_ID": "1", "SLURM_NNODES": "2"}, clear=True):
                    with mock.patch.object(platform_config, "run_command", side_effect=OSError("no srun")):
                        reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual([report.get("check_scope") for report in reports], ["local"])

                    empty = subprocess.CompletedProcess(args=["srun"], returncode=0, stdout="", stderr="")
                    with mock.patch.object(platform_config, "run_command", return_value=empty):
                        reports, _ = platform_config.run_slurm_check("slurm")
                    self.assertEqual([report.get("check_scope") for report in reports], ["local"])

    def test_kubernetes_with_no_gpu_node_grades_unknown(self) -> None:
        """The k8s fallback reads the control host, so it is a stand-in too."""
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
        """A bare-metal login node must not answer for a virtualized fabric.

        This is the Exemplar post's primary case for checks 1 and 2: a
        virtualized GB200 fabric fronted by a bare-metal x86 login node. Read
        from the login node alone, both rows grade ``not_applicable`` for
        compute nodes nobody looked at.

        The fixture has to expose a readable PCI bus with a passthrough GPU.
        A host tree with no ``/sys/bus/pci`` grades unknown an earlier branch
        on, so the verdict would come out right for a reason that has nothing
        to do with the vantage.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "proc/cmdline", "ro iommu=pt\n")
            write_pci_device(root, "0000:07:00.0", vendor="0x10de", pci_class="0x030200", group="12")
            report = collect(root)
            report["check_scope"] = "local"
            # Without the gate these are the clearing statuses the login node
            # would publish for the whole cluster.
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
        """Withdrawing a warning would lose a fault on a host that really has it.

        The login node is the one machine the check did read, so a translating
        IOMMU there is a finding about a real host, not a claim about the
        fabric.
        """
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
    """Reading the tier count is what makes the queue-pair advisory apply.

    Under-reading a Clos as a single leaf tier would grade the advisory
    ``not_applicable`` on the largest fabrics, which is exactly where a single
    queue pair costs the most.
    """

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
        """No Level= lines, so the parent/child relation is the only evidence."""
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
        """topology/block emits no Level= and no Switches=.

        This is the common GB200 / GB300 shape. Reading it as a single tier
        would quietly exempt the largest Clos fabrics from the advisory.
        """
        conf = "BlockName=b1 Nodes=node[001-018]\nBlockName=b2 Nodes=node[019-036]\n"
        self.assertEqual(platform_config.count_fabric_tiers(conf), 2)

    def test_a_single_block_is_one_tier(self) -> None:
        self.assertEqual(platform_config.count_fabric_tiers("BlockName=b1 Nodes=node[001-018]\n"), 1)

    def test_topology_yaml_children_prove_a_second_tier(self) -> None:
        yaml_text = "switches:\n  - switch: spine1\n    children: leaf[1-8]\n  - switch: leaf1\n    nodes: node[001-016]\n"
        self.assertEqual(platform_config.count_fabric_tiers(yaml_text), 2)

    def test_no_topology_data_reports_zero_not_one(self) -> None:
        """Zero means "not read". One would be a claim the fabric is flat."""
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
        """A cluster with no topology plugin is not a single-tier fabric."""
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

    def test_an_exact_tier_count_beats_the_node_count(self) -> None:
        self.assertEqual(self._shape(fabric_tiers=1, node_count=512), (False, "topology (single tier)"))
        self.assertEqual(self._shape(fabric_tiers=2, node_count=2), (True, "topology (2 tiers)"))

    def test_the_node_count_stands_in_when_no_topology_was_read(self) -> None:
        self.assertEqual(self._shape(fabric_tiers=0, node_count=128), (True, "node count (128 > 64)"))
        self.assertEqual(self._shape(fabric_tiers=0, node_count=8), (False, "node count (8 <= 64)"))

    def test_the_threshold_is_exclusive_at_its_own_value(self) -> None:
        self.assertIs(self._shape(fabric_tiers=0, node_count=64)[0], False)
        self.assertIs(self._shape(fabric_tiers=0, node_count=65)[0], True)

    def test_neither_reading_is_unknown_not_flat(self) -> None:
        self.assertEqual(self._shape(fabric_tiers=0, node_count=0), (None, "no topology or node-count data"))


class NoPyxisClassificationTests(unittest.TestCase):
    """Only an option the launcher did not recognize proves pyxis is absent.

    ``no_pyxis`` is the one container-check failure code excluded from the
    attestation-required finding, on the grounds that nothing is owed on a
    cluster that has no launcher to ask. Every other failure leaves a real
    question open, so a reading that lands on ``no_pyxis`` by mistake silences
    exactly the note the operator has to take to the provider while access is
    live.
    """

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
        """Pyxis names itself when it fails, and it quotes the job's own flags.

        Matching the flag alone read a container that failed to start as a
        cluster with no pyxis at all, which is the inverted reading: the plugin
        is installed, the mount is unverified, and the operator is owed an
        answer.
        """
        for stderr in (
            "slurmstepd: error: pyxis: container start failed with --container-image=docker://alpine:3\n",
            "slurmstepd: error: pyxis: couldn't start container\nsrun: error: task 0 exited with code 1\n",
            "enroot: failed to import image\n",
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(self._classify(stderr), "check_incomplete")

    def test_a_plugin_that_failed_to_load_is_not_an_absent_plugin(self) -> None:
        """A cluster that ships pyxis.so and cannot load it still owes an answer.

        This is the one case where both signals appear at once: the SPANK plugin
        names itself in the load error, and srun then rejects the option it would
        have registered. The site has pyxis, so "this harness has no launcher to
        ask" is the wrong reading, and the operator has to raise the broken
        plugin with the provider while access is live.
        """
        stderr = (
            "srun: error: spank: pyxis.so: Plugin failed to load\n"
            "srun: unrecognized option '--container-image=docker://alpine:3'\n"
        )
        self.assertEqual(self._classify(stderr), "check_incomplete")

    def test_a_different_rejected_option_is_not_an_absent_plugin(self) -> None:
        """An older Slurm without ``--overlap`` says nothing about pyxis.

        The step never ran, so the mount is unverified, and matching the bare
        phrase turned that into a silent skip.
        """
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
        """Two unrelated lines are not one message about the container flag."""
        stderr = "srun: unrecognized option '--overlap'\nsrun: using --container-image=docker://alpine:3\n"
        self.assertIs(platform_config.stderr_says_no_pyxis(stderr), False)


class CheckImageTests(unittest.TestCase):
    """The mount check must exercise the image the campaign really runs.

    Launching some other image would grade a mount hook that the real
    benchmark launcher never uses.
    """

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
    """A harness the check cannot cover reports a skip, never a failure.

    Only slurm/pyxis gives the audit a launcher to interrogate, and only Slurm
    publishes a fabric topology, so the k8s and standalone paths must degrade
    without inventing a provider fault.
    """

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

    def test_a_harness_without_a_launcher_reports_why_and_does_not_fail(self) -> None:
        for harness in ("standalone", "k8s"):
            with self.subTest(harness=harness):
                container = platform_config.run_container_check(
                    harness=harness,
                    env={},
                    candidates=["/etc/nccl/topo.xml"],
                    runner=lambda *a, **k: None,
                )
                self.assertIs(container["available"], False)
                self.assertEqual(container["reason_code"], "no_launcher_on_harness")

    def test_standalone_does_not_build_the_slurm_topology_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            write(root / "etc/nccl/topo.xml", '<system version="1"/>\n')
            payload = self._payload("standalone", root)
            self.assertNotIn("nccl_topo_file", payload)


class ClosThresholdEnvTests(unittest.TestCase):
    """``CLUSTERMAX_AUDIT_CLOS_NODE_THRESHOLD`` is the operator override."""

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
        """Zero would read every fabric as a Clos and warn everywhere."""
        for value in ("0", "-8", "not-a-number", ""):
            with self.subTest(value=value):
                self.assertEqual(self._threshold(value), 64)


class ContainerCheckSkipTests(unittest.TestCase):
    """The Pyxis step must not run when its answer cannot change a verdict.

    A cold pull of the check image can run to the full timeout, and the topology
    check is already not-applicable when no host publishes a topology file.
    """

    def _run(self, root: Path) -> tuple[dict, list]:
        calls: list[dict] = []

        def record(**kwargs):
            calls.append(kwargs)
            return {"available": True, "topo_file_env": "", "topo_files_readable": [], "completed": True}

        with mock.patch.object(platform_config, "run_container_check", side_effect=record):
            with mock.patch.object(platform_config, "collect_host", return_value=collect(root)):
                payload = platform_config.run_default_check("standalone")
        return payload, calls

    def test_no_host_topology_file_skips_the_container_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            payload, calls = self._run(root)
            self.assertEqual(calls, [])
            self.assertNotIn("nccl_topo_file", payload)

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
        """not_applicable claims no host has a subject for the check.

        A host nobody could read cannot support that claim, so the pair folds
        to unknown rather than to an asserted absence.
        """
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

    def test_payload_carries_all_four_check_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bare_metal(root)
            payload = platform_config.build_payload(
                reports=[collect(root)],
                errors=[],
                container={"available": False, "reason": "standalone harness"},
                node_count=1,
            )
            self.assertEqual(
                sorted(payload),
                ["arm_smmu_virtualization", "nccl_ib_qps", "nccl_topo_file", "vm_iommu"],
            )
            for key, value in payload.items():
                with self.subTest(key=key):
                    self.assertIn(value["status"], {"pass", "warning", "fail", "not_applicable", "unknown"})
                    self.assertTrue(value["message"])

    def test_the_aggregate_keeps_the_reading_each_host_verdict_came_from(self) -> None:
        """A finding sent to a provider has to carry the values the check saw."""
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


if __name__ == "__main__":
    unittest.main()
