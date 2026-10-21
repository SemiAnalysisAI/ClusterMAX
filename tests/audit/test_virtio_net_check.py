
"""The BlueField VIRTIO-Net check reports five states and never a false pass."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
CHECK = AUDIT_SCRIPTS / "checks" / "fabric" / "virtio-net-check.py"

BLUEFIELD3_LSPCI = (
    "0000:46:00.0 Ethernet controller [0200]: Mellanox Technologies MT43244 "
    "BlueField-3 integrated ConnectX-7 network controller [15b3:a2dc] (rev 01)\n"
    "0000:46:00.1 Ethernet controller [0200]: Mellanox Technologies MT43244 "
    "BlueField-3 integrated ConnectX-7 network controller [15b3:a2dc] (rev 01)\n"
    "0000:00:04.0 SCSI storage controller [0100]: Red Hat, Inc. Virtio block "
    "device [1af4:1001]\n"
)
NO_BLUEFIELD_LSPCI = (
    "0000:17:00.0 Infiniband controller [0207]: Mellanox Technologies MT2910 "
    "Family [ConnectX-7] [15b3:1021]\n"
    "0000:00:04.0 SCSI storage controller [0100]: Red Hat, Inc. Virtio block "
    "device [1af4:1001]\n"
)
DPU_MODE_MLXCONFIG = """
Device #1:
----------
Configurations:                              Current
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         ENABLED(0)
         INTERNAL_CPU_RSHIM                  ENABLED(0)
"""
NIC_MODE_MLXCONFIG = """
Configurations:                              Current
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         DISABLED(1)
         INTERNAL_CPU_RSHIM                  ENABLED(0)
"""
ZERO_TRUST_MLXCONFIG = """
Configurations:                              Current
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         ENABLED(0)
         INTERNAL_CPU_RSHIM                  DISABLED(1)
"""
VIRTNET_VERSION_JSON = (
    '[\n  { "Original Controller": "v24.10.17" },\n'
    '  { "Destination Controller": "v24.10.19" }\n]\n'
)

def load_check_module():
    # Return a fresh module so cache mutations do not leak between tests.
    spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class CheckHarness(unittest.TestCase):

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory(prefix="virtio-net-check-")
        self.addCleanup(holder.cleanup)
        self.tmp = Path(holder.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.root = self.tmp / "root"
        (self.root / "dev").mkdir(parents=True)
        (self.root / "sys" / "class" / "net").mkdir(parents=True)
        self.calls = self.tmp / "calls"
        self.calls.mkdir()

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(
            "#!/bin/bash\n"
            f'printf "%s\\n" "$*" >> "{self.calls}/{name}.calls"\n' + body + "\n"
        )
        path.chmod(0o755)

    def stub_output(self, name: str, stdout: str, *, returncode: int = 0) -> None:

        data = self.tmp / f"{name}.stdout"
        data.write_text(stdout)
        self.stub(name, f'/bin/cat "{data}"\nexit {returncode}')

    def stub_missing(self, name: str) -> None:
        target = self.bin / name
        if target.exists():
            target.unlink()

    def stub_root_only(self, name: str, stdout: str) -> None:
        data = self.tmp / f"{name}.stdout"
        data.write_text(stdout)
        self.stub(
            name,
            'if [ -n "$STUB_SUDO" ]; then\n'
            f'  /bin/cat "{data}"\n'
            "  exit 0\n"
            "fi\n"
            'echo "-E- Failed to open the device" >&2\n'
            "exit 1",
        )

    def stub_sudo(self) -> None:
        self.stub(
            "sudo",
            'while [ "$1" = "-n" ]; do shift; done\nexport STUB_SUDO=1\nexec "$@"',
        )

    def stub_sudo_denied(self) -> None:
        self.stub("sudo", 'echo "sudo: a password is required" >&2\nexit 1')

    def calls_for(self, name: str) -> list[str]:
        path = self.calls / f"{name}.calls"
        return path.read_text().splitlines() if path.exists() else []

    def run_check(self, *args: str, **env_overrides: str) -> dict:
        env = {
            **os.environ,

            "PATH": str(self.bin),
            "CLUSTERMAX_AUDIT_ROOT": str(self.root),
            "CLUSTERMAX_HARNESS": "standalone",
            "CLUSTERMAX_AUDIT_HARNESS": "standalone",

            "CLUSTERMAX_DPU_SSH_DISABLE": "1",
            **env_overrides,
        }
        result = subprocess.run(
            [sys.executable, str(CHECK), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, f"check failed: {result.stderr}")
        return json.loads(result.stdout)

    def host_record(self, **env_overrides: str) -> dict:
        return self.run_check("--collect-host", **env_overrides)

class VersionCollectionTests(CheckHarness):
    def test_virtnet_version_json_yields_the_original_controller(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        payload = self.tmp / "virtnet-version.json"
        payload.write_text(VIRTNET_VERSION_JSON)
        self.stub("virtnet", f"""
case "$1" in
  version) /bin/cat "{payload}" ;;
  *) exit 1 ;;
esac
""")

        record = self.host_record()

        self.assertEqual(record["version"], "24.10.17")
        self.assertEqual(record["versionSource"], "virtnet-version")
        self.assertEqual(record["state"], "version")

    def test_virtnet_dash_v_is_never_the_controller_version(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        self.stub("virtnet", """
case "$1" in
  version) exit 1 ;;
  -v) echo "Nvidia virtio-net-controller command line interface v24.10.50" ;;
  *) exit 1 ;;
esac
""")

        record = self.host_record()

        self.assertIsNone(record["version"])
        self.assertIsNone(record["versionSource"])
        self.assertEqual(record["state"], "unknown")

        self.assertEqual(record["cliVersion"], "24.10.50")
        self.assertIn("24.10.50", record["reason"])
        self.assertIn("not graded", record["reason"])

    def test_a_cli_version_reaches_the_evaluator_as_unknown(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        self.stub("virtnet", """
case "$1" in
  version) exit 1 ;;
  -v) echo "Nvidia virtio-net-controller command line interface v24.10.50" ;;
  *) exit 1 ;;
esac
""")

        summary = self.run_check("--summary")

        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertNotEqual(summary["virtioNet"], "24.10.50")
        self.assertEqual(summary["state"], "unknown")

    def test_a_staged_destination_controller_does_not_shadow_the_running_one(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        payload = self.tmp / "virtnet-version.json"
        payload.write_text(VIRTNET_VERSION_JSON)
        self.stub("virtnet", f"""
case "$1" in
  version) /bin/cat "{payload}" ;;
  *) exit 1 ;;
esac
""")

        summary = self.run_check("--summary")

        self.assertEqual(summary["virtioNet"], "24.10.17")
        self.assertNotEqual(summary["virtioNet"], "24.10.19")

class ReleaseLineTests(CheckHarness):

    def bluefield_dpu(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)

    def test_line_is_null_when_nothing_names_a_train(self) -> None:

        self.bluefield_dpu()
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v25.10.4"}]' ;;
  list) echo '[]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'exit 1')

        record = self.host_record()

        self.assertEqual(record["version"], "25.10.4")
        self.assertIsNone(record["line"])

    def test_line_is_read_from_the_bluefield_bundle_identity(self) -> None:
        self.bluefield_dpu()
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v24.10.17"}]' ;;
  list) echo '[]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'echo "DOCA_2.9.3_BSP_4.9.3_LTS24_Ubuntu_22.04-1.24-10.prod"')

        record = self.host_record()

        self.assertEqual(record["line"], "LTS24")
        self.assertIn("/etc/mlnx-release", " ".join(self.calls_for("cat")))

    def test_line_from_a_virtnet_label_short_circuits_the_bundle_read(self) -> None:
        self.bluefield_dpu()
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v25.10.6", "Channel": "GA"}]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'echo "should not be needed"')

        record = self.host_record()

        self.assertEqual(record["line"], "GA")
        self.assertEqual(self.calls_for("cat"), [])

    def test_a_lowercase_ga_fragment_is_not_a_release_line(self) -> None:

        self.bluefield_dpu()
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v25.10.4"}]' ;;
  list) echo '[]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'echo "DOCA_2.9.3_BSP_4.9.3_Ubuntu_22.04-ga-1.x86_64.prod"')

        record = self.host_record()

        self.assertEqual(record["version"], "25.10.4")
        self.assertIsNone(record["line"])

    def test_two_different_labels_in_the_evidence_decline_a_line(self) -> None:
        self.bluefield_dpu()
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v25.10.4"}]' ;;
  list) echo '[{"name": "vf0"}]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'echo "DOCA_2.9.3_LTS24_upgraded_from_LTS23_Ubuntu_22.04"')

        record = self.host_record()

        self.assertIsNone(record["line"])

class ScopeStateTests(CheckHarness):
    def test_bluefield3_without_virtnet_is_an_informed_unknown(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)

        record = self.host_record()

        self.assertEqual(record["state"], "unknown")
        self.assertTrue(record["bluefield3Present"])
        self.assertEqual(record["mode"], "dpu")
        self.assertIsNone(record["version"])
        self.assertIn("DPU ARM side", record["reason"])
        self.assertIn("attest", record["reason"])

    def test_nic_mode_is_latent_not_not_applicable(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", NIC_MODE_MLXCONFIG)

        record = self.host_record()

        self.assertEqual(record["state"], "not_running")
        self.assertNotEqual(record["state"], "not_applicable")
        self.assertEqual(record["mode"], "nic")
        self.assertTrue(record["bluefield3Present"])
        self.assertIn("firmware stays installed", record["reason"])

    def test_no_bluefield_with_a_completed_scan_is_not_applicable(self) -> None:

        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        record = self.host_record()

        self.assertEqual(record["state"], "not_applicable")
        self.assertFalse(record["bluefield3Present"])
        self.assertEqual(record["bluefieldDevices"], [])

        self.assertEqual(record["virtioPciDevices"], 1)

    def test_missing_lspci_is_incomplete_not_not_applicable(self) -> None:
        self.stub_missing("lspci")

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])

    def test_mlxconfig_without_root_is_incomplete_not_not_applicable(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub("mlxconfig", 'echo "-E- You must be root to run this tool" >&2\nexit 1')
        self.stub("mst", 'echo "-E- Root permissions required" >&2\nexit 1')
        self.stub_sudo_denied()

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertTrue(record["bluefield3Present"])
        self.assertEqual(record["mode"], "unknown")
        self.assertIn("root", record["reason"])

        self.assertIn("mlxconfig", record["modeError"])

    def test_a_failed_lspci_with_partial_output_is_incomplete(self) -> None:

        self.stub_output("lspci", NO_BLUEFIELD_LSPCI, returncode=1)

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])

    def test_an_empty_lspci_listing_is_incomplete(self) -> None:

        self.stub_output("lspci", "")

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])
        self.assertIn("no PCI device", record["scanError"])

    def test_a_corroborated_empty_bus_is_not_applicable(self) -> None:

        self.stub_output("lspci", "")
        (self.root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)

        record = self.host_record()

        self.assertTrue(record["scanComplete"])
        self.assertIsNone(record["scanError"])
        self.assertFalse(record["bluefield3Present"])
        self.assertEqual(record["state"], "not_applicable")

    def test_a_populated_sysfs_bus_does_not_corroborate_an_empty_listing(self) -> None:

        self.stub_output("lspci", "")
        device = self.root / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
        device.mkdir(parents=True)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_does_not_corroborate(self) -> None:

        self.stub_output("lspci", "")
        bus = self.root / "sys" / "bus" / "pci" / "devices"
        bus.mkdir(parents=True)
        bus.chmod(0o000)
        self.addCleanup(bus.chmod, 0o755)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    def test_a_failed_lspci_is_incomplete_even_beside_an_empty_sysfs_bus(self) -> None:

        self.stub_output("lspci", "", returncode=1)
        (self.root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    def test_a_bluefield_in_a_partial_listing_still_counts_as_present(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI, returncode=1)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)

        record = self.host_record()

        self.assertTrue(record["scanComplete"])
        self.assertTrue(record["bluefield3Present"])
        self.assertEqual(record["state"], "unknown")

    def test_missing_mlxconfig_is_incomplete(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_missing("mlxconfig")

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertIn("mlxconfig", record["reason"])

class EscalationPathTests(unittest.TestCase):

    def setUp(self) -> None:
        self.check = load_check_module()

    def prefix(self, *, euid: int, sudo: str | None) -> tuple[list[str], str]:
        return self.check.privileged_prefix(which=lambda _name: sudo, euid=lambda: euid)

    def test_a_root_caller_needs_no_prefix(self) -> None:

        prefix, label = self.prefix(euid=0, sudo="/usr/bin/sudo")

        self.assertEqual(prefix, [])
        self.assertEqual(label, self.check.ESCALATION_ROOT)

    def test_a_tenant_with_sudo_gets_one_non_interactive_attempt(self) -> None:
        prefix, label = self.prefix(euid=1000, sudo="/usr/bin/sudo")

        self.assertEqual(prefix, ["/usr/bin/sudo", "-n"])
        self.assertEqual(label, self.check.ESCALATION_SUDO)

    def test_a_tenant_without_sudo_has_nothing_to_try(self) -> None:

        prefix, label = self.prefix(euid=1000, sudo=None)

        self.assertEqual(prefix, [])
        self.assertEqual(label, self.check.ESCALATION_UNAVAILABLE)

@unittest.skipIf(os.geteuid() == 0, "a root caller holds the rights and never escalates")
class PrivilegedModeReadTests(CheckHarness):

    def test_a_tenant_mode_read_escalates_and_settles_the_scope(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", NIC_MODE_MLXCONFIG)
        self.stub_sudo()

        record = self.host_record()

        self.assertEqual(record["mode"], "nic")
        self.assertEqual(record["state"], "not_running")
        self.assertIsNone(record["modeError"])

        self.assertEqual(record["modeSource"], "sudo mlxconfig")
        self.assertEqual(record["modeEscalation"], "sudo -n")

        self.assertEqual(len(self.calls_for("mlxconfig")), 2)
        sudo_argv = self.calls_for("sudo")[0]
        self.assertTrue(sudo_argv.startswith("-n "))
        self.assertIn("mlxconfig", sudo_argv)

    def test_a_working_unprivileged_read_never_calls_sudo(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        self.stub_sudo()

        record = self.host_record()

        self.assertEqual(record["mode"], "dpu")
        self.assertEqual(record["modeSource"], "mlxconfig")
        self.assertEqual(self.calls_for("sudo"), [])

    def test_the_escalated_read_reaches_the_isolation_evidence(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", ZERO_TRUST_MLXCONFIG)
        self.stub_sudo()

        summary = self.run_check("--summary")
        evidence = json.loads(summary["dpuIsolationJson"])

        self.assertEqual(evidence["rshimHostAccess"]["internalCpuRshim"], "1")
        self.assertTrue(evidence["rshimHostAccess"]["rshimRestricted"])
        self.assertIsNone(evidence["modeError"])

    def test_an_enabled_rshim_is_proven_rather_than_left_unknown(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", NIC_MODE_MLXCONFIG)
        self.stub_sudo()

        rshim = json.loads(self.run_check("--summary")["dpuIsolationJson"])["rshimHostAccess"]

        self.assertEqual(rshim["internalCpuRshim"], "0")
        self.assertIs(rshim["rshimRestricted"], False)

    def test_a_denied_sudo_keeps_the_host_unresolved(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", NIC_MODE_MLXCONFIG)
        self.stub("mst", "exit 1")
        self.stub_sudo_denied()

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertEqual(record["mode"], "unknown")
        self.assertEqual(record["modeEscalation"], "sudo -n")
        self.assertTrue(self.calls_for("sudo"))
        self.assertIn("sudo -n retry did not answer", record["reason"])

    def test_failed_mode_read_never_loads_host_kernel_modules(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub("mlxconfig", 'echo "-E- Failed to open the device" >&2\nexit 1')
        self.stub("mst", "exit 0")
        self.stub_sudo()

        record = self.host_record()
        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(self.calls_for("mst"))
        self.assertFalse(any(call.startswith("-n mst") for call in self.calls_for("sudo")))

class RshimEvidenceTests(CheckHarness):

    def test_rshim_reachability_is_recorded_as_evidence(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        (self.root / "dev" / "rshim0").touch()
        (self.root / "sys" / "class" / "net" / "tmfifo_net0").mkdir()

        record = self.host_record()
        rshim = record["rshimHostAccess"]

        self.assertTrue(rshim["rshimDeviceNode"])
        self.assertTrue(rshim["tmfifoNet0"])
        self.assertEqual(rshim["internalCpuRshim"], "0")
        self.assertFalse(rshim["rshimRestricted"])

        self.assertNotIn("grade", record)
        self.assertNotIn("status", record)

    def test_zero_trust_restriction_is_recorded(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", ZERO_TRUST_MLXCONFIG)

        rshim = self.host_record()["rshimHostAccess"]

        self.assertEqual(rshim["internalCpuRshim"], "1")
        self.assertTrue(rshim["rshimRestricted"])
        self.assertFalse(rshim["rshimDeviceNode"])

    def test_rshim_ssh_is_batch_mode_and_never_prompts(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        (self.root / "sys" / "class" / "net" / "tmfifo_net0").mkdir()
        self.stub("ssh", """
for arg in "$@"; do
  if [ "$arg" = version ]; then
    echo '[{"Original Controller": "v23.10.20"}]'
    exit 0
  fi
done
exit 1
""")

        record = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")

        self.assertEqual(record["version"], "23.10.20")
        self.assertEqual(record["versionSource"], "rshim-ssh/virtnet-version")
        self.assertTrue(record["rshimHostAccess"]["dpuReachedFromHost"])
        argv = self.calls_for("ssh")[0]
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("192.168.100.2", argv)

    def test_unreachable_dpu_falls_through_to_unknown(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        (self.root / "dev" / "rshim0").touch()
        self.stub("ssh", 'echo "Permission denied (publickey)." >&2\nexit 255')

        record = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")

        self.assertEqual(record["state"], "unknown")
        self.assertFalse(record["rshimHostAccess"]["dpuReachedFromHost"])
        self.assertIn("did not answer", record["reason"])

class SummaryAndCollectorTests(CheckHarness):

    def test_summary_reports_not_installed_for_a_clean_not_applicable(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "not_applicable")

        self.assertEqual(summary["virtioNet"], "not-installed")
        self.assertIsNone(summary["virtioNetLine"])

    def test_summary_reports_unknown_for_an_unresolved_dpu(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "unknown")
        self.assertEqual(summary["virtioNet"], "unknown")

    def test_summary_reports_unknown_when_the_scan_could_not_run(self) -> None:
        self.stub_missing("lspci")

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertNotEqual(summary["virtioNet"], "not-installed")

    def test_summary_passes_a_read_version_through(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        self.stub("virtnet", """
case "$1" in
  version) echo '[{"Original Controller": "v24.10.17"}]' ;;
  list) echo '[]' ;;
  *) exit 1 ;;
esac
""")
        self.stub("cat", 'echo "DOCA_2.9.3_BSP_4.9.3_LTS24_Ubuntu_22.04"')

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "version")
        self.assertEqual(summary["virtioNet"], "24.10.17")
        self.assertEqual(summary["virtioNetLine"], "LTS24")

    def test_nic_mode_never_reaches_the_evaluator_as_not_installed(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", NIC_MODE_MLXCONFIG)

        summary = self.run_check("--summary")

        self.assertNotEqual(summary["virtioNet"], "not-installed")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertEqual(summary["virtioNetMode"], "nic")
        self.assertEqual(summary["state"], "not_running")

    def test_absent_bluefield_is_the_only_source_of_not_installed(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary")

        self.assertEqual(summary["virtioNet"], "not-installed")
        self.assertEqual(summary["virtioNetMode"], "absent")

    def test_summary_carries_the_dpu_isolation_evidence(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        (self.root / "dev" / "rshim0").touch()

        summary = self.run_check("--summary")
        evidence = json.loads(summary["dpuIsolationJson"])

        self.assertTrue(evidence["scanComplete"])
        self.assertTrue(evidence["bluefield3Present"])
        self.assertTrue(evidence["rshimHostAccess"]["rshimDeviceNode"])
        self.assertFalse(evidence["rshimHostAccess"]["rshimRestricted"])
        self.assertEqual(evidence["rshimHostAccess"]["internalCpuRshim"], "0")

    def test_payload_carries_hosts_and_summary(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", NIC_MODE_MLXCONFIG)

        payload = self.run_check()

        self.assertIn("virtio_net_bluefield", payload)
        block = payload["virtio_net_bluefield"]
        self.assertEqual(block["summary"]["state"], "not_running")
        self.assertEqual(block["summary"]["mode"], "nic")
        self.assertEqual(len(block["hosts"]), 1)
        host = next(iter(block["hosts"].values()))
        self.assertEqual(host["state"], "not_running")

class FanOutCoverageTests(CheckHarness):

    def slurm_env(self) -> dict[str, str]:
        return {
            "CLUSTERMAX_HARNESS": "slurm",
            "CLUSTERMAX_AUDIT_HARNESS": "slurm",
            "SLURM_JOB_ID": "",
        }

    def test_a_login_node_without_an_allocation_is_not_a_clean_cluster(self) -> None:

        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary", **self.slurm_env())

        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertNotEqual(summary["virtioNet"], "not-installed")
        self.assertNotEqual(summary["virtioNetMode"], "absent")
        self.assertIn("did not reach every host", summary["virtioNetReason"])

    def test_a_partial_fan_out_withdraws_the_isolation_clean_bill(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary", **self.slurm_env())
        evidence = json.loads(summary["dpuIsolationJson"])

        self.assertFalse(evidence["scanComplete"])
        self.assertIn("did not reach every host", evidence["scanError"])

    def test_a_failed_srun_does_not_clear_the_cluster_from_the_local_host(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)
        self.stub("srun", 'echo "srun: error: Unable to allocate resources" >&2\nexit 1')

        summary = self.run_check(
            "--summary", **{**self.slurm_env(), "SLURM_JOB_ID": "4242", "SLURM_NNODES": "4"}
        )

        self.assertIn("--collect-host", " ".join(self.calls_for("srun")))
        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["virtioNet"], "unknown")

class WorstObservedTests(CheckHarness):

    def host_json(self, host: str, **fields: object) -> str:
        record = {
            "host": host,
            "state": "unknown",
            "version": None,
            "versionSource": None,
            "line": None,
            "mode": "dpu",
            "scanComplete": True,
            "bluefield3Present": True,
            "reason": f"{host}: unresolved",
            "rshimHostAccess": {},
        }
        record.update(fields)
        return json.dumps(record)

    def fan_out(self, *records: str) -> dict:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        payload = self.tmp / "srun.stdout"
        payload.write_text("\n".join(records) + "\n")
        self.stub("srun", f'/bin/cat "{payload}"')
        return self.run_check(
            "--summary",
            CLUSTERMAX_HARNESS="slurm",
            CLUSTERMAX_AUDIT_HARNESS="slurm",
            SLURM_JOB_ID="4242",
            SLURM_NNODES="2",
        )

    def test_a_below_minimum_host_survives_an_unresolved_peer(self) -> None:

        summary = self.fan_out(
            self.host_json(
                "node-a",
                state="version",
                version="24.10.17",
                versionSource="virtnet-version",
                line="LTS24",
            ),
            self.host_json("node-b"),
        )

        self.assertEqual(summary["state"], "unknown")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.17")
        self.assertEqual(summary["virtioNetWorstObservedLine"], "LTS24")
        self.assertEqual(summary["virtioNetWorstObservedMode"], "dpu")
        self.assertEqual(summary["virtioNetWorstObservedHost"], "node-a")

    def test_the_lowest_version_across_hosts_is_the_one_reported(self) -> None:
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="24.10.60", line="LTS24"),
            self.host_json("node-b", state="version", version="24.10.17", line="LTS24"),
        )

        self.assertEqual(summary["state"], "version")
        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.17")
        observed = json.loads(summary["virtioNetObservedJson"])
        self.assertEqual([entry["version"] for entry in observed], ["24.10.17", "24.10.60"])

    def test_mixed_modes_report_each_reading_instead_of_an_invented_host(self) -> None:

        summary = self.fan_out(
            self.host_json("node-a", state="not_running", version="24.10.17", mode="nic"),
            self.host_json("node-b", state="version", version="24.10.50", mode="dpu"),
        )

        self.assertEqual(summary["virtioNetWorstObserved"], "")
        observed = json.loads(summary["virtioNetObservedJson"])
        self.assertEqual(
            {entry["version"]: entry["mode"] for entry in observed},
            {"24.10.17": "nic", "24.10.50": "dpu"},
            "each reading must keep the mode of the host that produced it",
        )

    def test_one_shared_mode_and_line_still_reports_a_single_worst_reading(self) -> None:
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="24.10.17",
                           mode="dpu", line="LTS24"),
            self.host_json("node-b", state="version", version="24.10.40",
                           mode="dpu", line="LTS24"),
        )

        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.17")
        self.assertEqual(summary["virtioNetWorstObservedMode"], "dpu")
        self.assertEqual(summary["virtioNetWorstObservedHost"], "node-a")

    def test_readings_with_no_release_line_are_each_graded(self) -> None:
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="23.10.30", mode="dpu"),
            self.host_json("node-b", state="version", version="24.10.17", mode="dpu"),
        )

        self.assertEqual(summary["virtioNetWorstObserved"], "")
        observed = json.loads(summary["virtioNetObservedJson"])
        self.assertEqual(
            sorted(entry["version"] for entry in observed), ["23.10.30", "24.10.17"]
        )

    def test_mixed_schemes_report_each_reading_instead_of_an_invented_order(self) -> None:

        summary = self.fan_out(
            self.host_json("node-a", state="version", version="1.8.0"),
            self.host_json("node-b", state="version", version="24.10.17"),
        )

        self.assertEqual(summary["virtioNetWorstObserved"], "")
        observed = json.loads(summary["virtioNetObservedJson"])
        self.assertEqual(
            sorted(entry["version"] for entry in observed), ["1.8.0", "24.10.17"]
        )
        self.assertEqual(
            sorted(entry["scheme"] for entry in observed), ["calendar", "legacy"]
        )

    def test_disagreeing_release_lines_report_each_reading(self) -> None:
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="25.10.4", line="GA"),
            self.host_json("node-b", state="version", version="25.10.5", line="LTS25"),
        )

        self.assertEqual(summary["virtioNetWorstObserved"], "")
        self.assertEqual(len(json.loads(summary["virtioNetObservedJson"])), 2)

    def test_a_partial_fan_out_is_detected_from_the_host_count(self) -> None:

        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)
        payload = self.tmp / "srun.stdout"
        payload.write_text(
            self.host_json(
                "node-a", state="not_applicable", bluefield3Present=False, mode="unknown"
            )
            + "\n"
        )
        self.stub("srun", f'/bin/cat "{payload}"')

        summary = self.run_check(
            "--summary",
            CLUSTERMAX_HARNESS="slurm",
            CLUSTERMAX_AUDIT_HARNESS="slurm",
            SLURM_JOB_ID="4242",
            SLURM_NNODES="4",
        )

        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertIn("1 of 4 host records", summary["virtioNetReason"])

    def test_a_coverage_gap_does_not_erase_a_proven_finding(self) -> None:

        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        payload = self.tmp / "srun.stdout"
        payload.write_text(
            self.host_json("node-a", state="version", version="24.10.17", line="LTS24")
            + "\n"
        )
        self.stub("srun", f'/bin/cat "{payload}"')

        summary = self.run_check(
            "--summary",
            CLUSTERMAX_HARNESS="slurm",
            CLUSTERMAX_AUDIT_HARNESS="slurm",
            SLURM_JOB_ID="4242",
            SLURM_NNODES="4",
        )

        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["virtioNet"], "unknown")
        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.17")
        self.assertEqual(summary["virtioNetWorstObservedLine"], "LTS24")

    def nic_unread(self, host: str = "node-b") -> str:
        return self.host_json(
            host,
            state="not_running",
            mode="nic",
            reason=(
                "BlueField-3 is in NIC mode (INTERNAL_CPU_OFFLOAD_ENGINE=1), so the "
                "virtio-net controller is not running and there is no exposure now. "
                "The firmware stays installed, so a change back to DPU mode would "
                "activate it unchanged."
            ),
        )

    def test_a_nic_mode_host_is_not_spoken_for_by_a_patched_peer(self) -> None:

        summary = self.fan_out(
            self.host_json("node-a", state="version", version="24.10.50", line="LTS24"),
            self.nic_unread(),
        )

        self.assertEqual(summary["state"], "not_running")

        self.assertNotEqual(summary["state"], "version")
        self.assertEqual(summary["virtioNet"], "unknown")

        self.assertIn("NIC mode", summary["virtioNetReason"])
        self.assertIn("firmware stays installed", summary["virtioNetReason"])

        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.50")
        self.assertEqual(summary["virtioNetWorstObservedLine"], "LTS24")

    def test_a_nic_mode_peer_does_not_weaken_a_proven_fail(self) -> None:

        summary = self.fan_out(
            self.host_json("node-c", state="version", version="24.10.17", line="LTS24"),
            self.nic_unread(),
        )

        self.assertEqual(summary["state"], "not_running")
        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.17")
        self.assertEqual(summary["virtioNetWorstObservedLine"], "LTS24")
        self.assertEqual(summary["virtioNetWorstObservedHost"], "node-c")

    def test_a_purely_version_fleet_is_unchanged(self) -> None:
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="24.10.50", line="LTS24"),
            self.host_json("node-b", state="version", version="24.10.60", line="LTS24"),
        )

        self.assertEqual(summary["state"], "version")
        self.assertEqual(summary["virtioNet"], "24.10.50")

    def test_no_version_anywhere_leaves_the_field_empty(self) -> None:
        summary = self.fan_out(self.host_json("node-a"), self.host_json("node-b"))

        self.assertEqual(summary["virtioNetWorstObserved"], "")
        self.assertEqual(json.loads(summary["virtioNetObservedJson"]), [])

class CheckCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.check = load_check_module()

    def test_reuses_the_full_payload_within_one_audit_run(self) -> None:
        payload = {
            "virtio_net_bluefield": {
                "hosts": {"gpu-a": {"state": "incomplete"}},
                "summary": {"state": "incomplete"},
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "virtio-net.json"
            env = {self.check.CHECK_CACHE_ENV: str(cache)}
            with mock.patch.object(
                self.check, "build_check_payload", return_value=payload
            ) as build:
                first = self.check.load_or_build_payload(harness="k8s", env=env)
                second = self.check.load_or_build_payload(harness="k8s", env=env)

        self.assertEqual(first, payload)
        self.assertEqual(second, payload)
        build.assert_called_once_with(harness="k8s", env=env)

    def test_invalid_cache_is_recollected(self) -> None:
        payload = {
            "virtio_net_bluefield": {"hosts": {}, "summary": {"state": "incomplete"}}
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "virtio-net.json"
            cache.write_text("not json")
            env = {self.check.CHECK_CACHE_ENV: str(cache)}
            with mock.patch.object(
                self.check, "build_check_payload", return_value=payload
            ) as build:
                result = self.check.load_or_build_payload(harness="k8s", env=env)

            self.assertEqual(json.loads(cache.read_text()), payload)

        self.assertEqual(result, payload)
        build.assert_called_once_with(harness="k8s", env=env)

class KubernetesNamespaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.check = load_check_module()

    def test_common_nvidia_namespace_is_discovered(self) -> None:

        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            found = command[-1] == "nvidia"
            return subprocess.CompletedProcess(command, 0 if found else 1, "", "")

        namespace = self.check.k8s_namespace(env={}, runner=runner)

        self.assertEqual(namespace, "nvidia")
        self.assertIn(["kubectl", "get", "namespace", "nvidia"], calls)

    def test_branded_gpu_operator_namespace_is_discovered(self) -> None:
        namespaces = {
            "items": [
                {"metadata": {"name": "default"}},
                {"metadata": {"name": "example-nvidia-gpu-operator"}},
            ]
        }

        def runner(command, **kwargs):
            if command[1:3] == ["get", "namespace"]:
                return subprocess.CompletedProcess(command, 1, "", "")
            return subprocess.CompletedProcess(
                command, 0, json.dumps(namespaces), ""
            )

        namespace = self.check.k8s_namespace(env={}, runner=runner)

        self.assertEqual(namespace, "example-nvidia-gpu-operator")

    def test_privileged_device_plugin_collects_from_host_root(self) -> None:
        pods = {
            "items": [
                {
                    "metadata": {"name": "nvidia-device-plugin-daemonset-abcde"},
                    "status": {"phase": "Running"},
                    "spec": {
                        "volumes": [
                            {"name": "host-root", "hostPath": {"path": "/"}}
                        ],
                        "containers": [
                            {
                                "name": "nvidia-device-plugin",
                                "securityContext": {"privileged": True},
                                "volumeMounts": [
                                    {"name": "host-root", "mountPath": "/host"}
                                ],
                            }
                        ],
                    },
                }
            ]
        }
        commands = []
        collector = "\n".join(
            ["@@LSPCI_BEGIN@@", NO_BLUEFIELD_LSPCI, "@@LSPCI_END@@"]
        )

        def runner(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["get", "pods"]:
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(pods), ""
                )
            return subprocess.CompletedProcess(command, 0, collector, "")

        record, error = self.check.run_k8s_node_check(
            "example-nvidia-gpu-operator", "gpu-1", runner=runner
        )

        self.assertIsNone(error)
        self.assertEqual(record["state"], "not_applicable")
        exec_command = commands[-1]
        self.assertIn("nvidia-device-plugin", exec_command)
        self.assertEqual(exec_command[-5:-2], ["chroot", "/host", "sh"])

class ReleaseLineDetectionTests(unittest.TestCase):

    def setUp(self) -> None:
        self.check = load_check_module()

    def test_evidence_naming_two_lines_names_none(self) -> None:
        self.assertIsNone(self.check.detect_line(["bundle LTS24 25.10.4", "channel GA"]))
        self.assertIsNone(self.check.detect_line(["LTS24 GA 25.10.4"]))

    def test_a_single_named_line_is_still_read(self) -> None:
        self.assertEqual(self.check.detect_line(["bundle LTS24 25.10.4"]), "LTS24")
        self.assertEqual(self.check.detect_line(["bundle GA 25.10.4"]), "GA")

    def test_two_lts_trains_are_still_ambiguous(self) -> None:
        self.assertIsNone(self.check.detect_line(["LTS23 and LTS24"]))

class ReleaseLineFallbackTests(unittest.TestCase):

    def setUp(self) -> None:
        self.check = load_check_module()

    def runner_for(self, outputs: dict[str, str]):
        def run(command, **kwargs):
            key = "list" if command[-1] == "list" else "release"
            return types.SimpleNamespace(
                returncode=0, stdout=outputs.get(key, ""), stderr=""
            )
        return run

    def test_a_later_single_label_cannot_resolve_an_earlier_contradiction(self) -> None:

        line, evidence = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4 LTS24", "channel GA"],
            runner=self.runner_for({"list": "GA"}),
            timeout=5,
        )
        self.assertIsNone(line)

        self.assertIn("Original Controller: 25.10.4 LTS24", evidence)

    def test_a_fallback_still_supplies_a_line_the_primary_evidence_lacks(self) -> None:
        line, _ = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4"],
            runner=self.runner_for({"list": "channel LTS24"}),
            timeout=5,
        )
        self.assertEqual(line, "LTS24")

    def test_a_contradiction_raised_by_a_fallback_survives_the_next_one(self) -> None:
        line, evidence = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4"],
            runner=self.runner_for({"list": "LTS24 and GA channels", "release": "LTS24"}),
            timeout=5,
        )
        self.assertIsNone(line)
        self.assertEqual(len(evidence), 3)

class IsolationSelectionTests(unittest.TestCase):

    WORKLOAD = CHECK.parent.parent.parent

    def setUp(self) -> None:
        self.check = load_check_module()

    def record(self, host: str, *, scan: bool, present: bool | None, rshim: dict,
               state: str = "unknown", scan_error: str | None = None) -> dict:
        return {
            "host": host, "state": state, "version": None, "versionSource": None,
            "line": None, "mode": "dpu", "scanComplete": scan,
            "bluefield3Present": present, "scanError": scan_error, "modeError": None,
            "rshimHostAccess": rshim, "reason": f"{host}: {state}",
        }

    def proven(self, host: str = "node-a") -> dict:
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": True, "tmfifoNet0": False,
            "rshimRestricted": False, "internalCpuRshim": "0"})

    def hardened(self, host: str = "node-h") -> dict:
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": False, "tmfifoNet0": False,
            "rshimRestricted": True, "internalCpuRshim": "1"})

    def unreadable(self, host: str = "node-u") -> dict:
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": False, "tmfifoNet0": False,
            "rshimRestricted": None, "internalCpuRshim": "unknown"})

    def incomplete(self, host: str = "node-b") -> dict:
        return self.record(host, scan=False, present=None, rshim={},
                           state="incomplete", scan_error="mlxconfig is not installed")

    def grade(self, records: list[dict]) -> tuple[dict, dict]:
        summary = self.check.summarize(records)
        flat = self.check.collector_summary({"virtio_net_bluefield": {"summary": summary}})
        proc = subprocess.run(
            [
                sys.executable, str(self.WORKLOAD / "security_version_audit.py"),
                "--virtio-net", flat["virtioNet"],
                "--virtio-net-mode", flat["virtioNetMode"],
                "--virtio-net-state", flat["state"],
                "--dpu-isolation-json", flat["dpuIsolationJson"],
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, f"evaluator failed: {proc.stderr}")
        return json.loads(flat["dpuIsolationJson"]), json.loads(proc.stdout)["dpuHostIsolation"]

    def test_a_proven_reachable_host_survives_an_incomplete_peer(self) -> None:

        evidence, verdict = self.grade([self.proven(), self.incomplete()])

        self.assertEqual(verdict["status"], "fail")
        self.assertNotEqual(verdict["status"], "unknown")
        self.assertEqual(evidence["host"], "node-a")

        self.assertEqual(evidence["unassessedHosts"], ["node-b"])

    def unscanned_but_reachable(self, host: str = "node-n") -> dict:
        return self.record(host, scan=False, present=None, state="incomplete",
                           scan_error="lspci not found", rshim={
                               "rshimDeviceNode": True, "tmfifoNet0": False,
                               "rshimRestricted": None, "internalCpuRshim": "unknown"})

    def test_selection_follows_the_consumer_onto_a_scanless_proof(self) -> None:
        evidence, verdict = self.grade(
            [self.unscanned_but_reachable(), self.hardened()]
        )
        self.assertEqual(verdict["status"], "fail")
        self.assertEqual(evidence["host"], "node-n")

        self.assertNotIn("node-n", evidence["unassessedHosts"])

    def test_a_scanless_mlxconfig_reading_is_not_treated_as_proof(self) -> None:
        scanless_mlxconfig = self.record(
            "node-m", scan=False, present=None, state="incomplete",
            scan_error="lspci not found",
            rshim={"rshimDeviceNode": False, "tmfifoNet0": False,
                   "rshimRestricted": False, "internalCpuRshim": "0"},
        )
        evidence, verdict = self.grade([scanless_mlxconfig, self.hardened()])
        self.assertNotEqual(verdict["status"], "fail")
        self.assertIn("node-m", evidence["unassessedHosts"])

    def test_a_hardened_host_does_not_speak_for_an_incomplete_peer(self) -> None:

        _, verdict = self.grade([self.hardened(), self.incomplete()])

        self.assertEqual(verdict["status"], "unknown")
        self.assertNotEqual(verdict["status"], "pass")

    def test_a_hardened_host_does_not_speak_for_an_unreadable_posture(self) -> None:

        _, verdict = self.grade([self.hardened(), self.unreadable()])

        self.assertEqual(verdict["status"], "unknown")
        self.assertNotEqual(verdict["status"], "pass")

    def test_every_host_hardened_and_read_passes(self) -> None:
        _, verdict = self.grade([self.hardened("node-h"), self.hardened("node-i")])

        self.assertEqual(verdict["status"], "pass")

    def test_every_host_incomplete_is_unknown(self) -> None:
        _, verdict = self.grade([self.incomplete("node-b"), self.incomplete("node-c")])

        self.assertEqual(verdict["status"], "unknown")

SEVERITY_MATRIX = Path(__file__).parent / "fixtures" / "virtio-net-severity-matrix.json"

# Keep explicit fleet inputs; the expected output is not recomputed by test logic.

_RSHIM = {
    "proven": {"rshimDeviceNode": True, "tmfifoNet0": False, "rshimRestricted": False,
               "internalCpuRshim": "0", "dpuReachedFromHost": None},
    "tmfifo": {"rshimDeviceNode": False, "tmfifoNet0": True, "rshimRestricted": None,
               "internalCpuRshim": "unknown", "dpuReachedFromHost": None},
    "hardened": {"rshimDeviceNode": False, "tmfifoNet0": False, "rshimRestricted": True,
                 "internalCpuRshim": "1", "dpuReachedFromHost": None},
    "unreadable": {"rshimDeviceNode": False, "tmfifoNet0": False, "rshimRestricted": None,
                   "internalCpuRshim": "unknown", "dpuReachedFromHost": None},
    "empty": {},
}

_CONTROLLER = {
    "v_pass": dict(state="version", version="24.10.50", line="LTS24", mode="dpu"),
    "v_fail": dict(state="version", version="24.10.17", line="LTS24", mode="dpu"),
    "v_pass_nic": dict(state="version", version="24.10.50", line="LTS24", mode="nic"),
    "v_fail_nic": dict(state="version", version="24.10.17", line="LTS24", mode="nic"),
    "v_ga": dict(state="version", version="25.10.4", line="GA", mode="dpu"),
    "v_lts25": dict(state="version", version="25.10.5", line="LTS25", mode="dpu"),
    "v_unlabelled": dict(state="version", version="25.10.4", line=None, mode="dpu"),
    "v_legacy": dict(state="version", version="1.8.0", line=None, mode="dpu"),
    "nic_unread": dict(state="not_running", version=None, line=None, mode="nic"),
    "unk_dpu": dict(state="unknown", version=None, line=None, mode="dpu"),
    "incomplete": dict(state="incomplete", version=None, line=None, mode="unknown",
                       scan=False, present=None, scan_error="mlxconfig is not installed"),
    "not_applic": dict(state="not_applicable", version=None, line=None, mode="unknown",
                       present=False),
}

_MATRIX_GAP = ["node-z: virtio-net check exec failed"]

_MATRIX_PAIRS = [
    ("v_pass+nic_unread", ("v_pass", "empty"), ("nic_unread", "empty")),
    ("v_fail+nic_unread", ("v_fail", "empty"), ("nic_unread", "empty")),
    ("v_pass+v_fail", ("v_pass", "empty"), ("v_fail", "empty")),
    ("v_pass+unk_dpu", ("v_pass", "empty"), ("unk_dpu", "empty")),
    ("v_pass+incomplete", ("v_pass", "empty"), ("incomplete", "empty")),
    ("v_pass+not_applic", ("v_pass", "empty"), ("not_applic", "empty")),
    ("nic_unread+not_applic", ("nic_unread", "empty"), ("not_applic", "empty")),
    ("nic_unread+unk_dpu", ("nic_unread", "empty"), ("unk_dpu", "empty")),
    ("incomplete+not_applic", ("incomplete", "empty"), ("not_applic", "empty")),
    ("not_applic+not_applic", ("not_applic", "empty"), ("not_applic", "empty")),
    ("v_ga+v_lts25", ("v_ga", "empty"), ("v_lts25", "empty")),
    ("v_legacy+v_fail", ("v_legacy", "empty"), ("v_fail", "empty")),
    ("v_fail_nic+unk_dpu", ("v_fail_nic", "empty"), ("unk_dpu", "empty")),
    ("v_pass_nic+v_pass", ("v_pass_nic", "empty"), ("v_pass", "empty")),
    ("v_unlabelled+v_pass", ("v_unlabelled", "empty"), ("v_pass", "empty")),
    ("iso proven+incomplete", ("unk_dpu", "proven"), ("incomplete", "empty")),
    ("iso proven+hardened", ("unk_dpu", "proven"), ("unk_dpu", "hardened")),
    ("iso proven+unreadable", ("unk_dpu", "proven"), ("unk_dpu", "unreadable")),
    ("iso proven+not_applic", ("unk_dpu", "proven"), ("not_applic", "empty")),
    ("iso tmfifo+hardened", ("unk_dpu", "tmfifo"), ("unk_dpu", "hardened")),
    ("iso hardened+incomplete", ("unk_dpu", "hardened"), ("incomplete", "empty")),
    ("iso hardened+unreadable", ("unk_dpu", "hardened"), ("unk_dpu", "unreadable")),
    ("iso hardened+hardened", ("unk_dpu", "hardened"), ("unk_dpu", "hardened")),
    ("iso hardened+not_applic", ("unk_dpu", "hardened"), ("not_applic", "empty")),
    ("iso unreadable+incomplete", ("unk_dpu", "unreadable"), ("incomplete", "empty")),
    ("iso incomplete+incomplete", ("incomplete", "empty"), ("incomplete", "empty")),
    ("iso not_applic+incomplete", ("not_applic", "empty"), ("incomplete", "empty")),
    ("v_fail+proven / nic_unread+hardened", ("v_fail", "proven"), ("nic_unread", "hardened")),
    ("v_pass+hardened / incomplete+empty", ("v_pass", "hardened"), ("incomplete", "empty")),
]

_MATRIX_TRIPLES = [
    ("pass+nic+incomplete", ("v_pass", "hardened"), ("nic_unread", "unreadable"), ("incomplete", "empty")),
    ("fail+pass+incomplete", ("v_fail", "proven"), ("v_pass", "hardened"), ("incomplete", "empty")),
    ("fail+nic+unk", ("v_fail", "hardened"), ("nic_unread", "proven"), ("unk_dpu", "unreadable")),
    ("pass+pass+not_applic", ("v_pass", "hardened"), ("v_pass", "hardened"), ("not_applic", "empty")),
    ("all_incomplete", ("incomplete", "empty"), ("incomplete", "empty"), ("incomplete", "empty")),
    ("all_not_applic", ("not_applic", "empty"), ("not_applic", "empty"), ("not_applic", "empty")),
    ("ga+lts25+incomplete", ("v_ga", "hardened"), ("v_lts25", "hardened"), ("incomplete", "empty")),
    ("legacy+fail+nic", ("v_legacy", "empty"), ("v_fail", "empty"), ("nic_unread", "empty")),
    ("proven+hardened+unreadable", ("unk_dpu", "proven"), ("unk_dpu", "hardened"), ("unk_dpu", "unreadable")),
    ("fail_nic+unk_dpu+incomplete", ("v_fail_nic", "hardened"), ("unk_dpu", "hardened"), ("incomplete", "empty")),
]

def _matrix_host(name: str, archetype: str, rshim: str = "empty") -> dict:
    spec = dict(_CONTROLLER[archetype])
    scan = spec.pop("scan", True)
    present = spec.pop("present", True)
    scan_error = spec.pop("scan_error", None)
    return {
        "host": name, "state": spec["state"], "version": spec["version"],
        "versionSource": "virtnet-version" if spec["version"] else None,
        "cliVersion": None, "line": spec["line"], "mode": spec["mode"],
        "scanComplete": scan, "bluefield3Present": present, "scanError": scan_error,
        "modeError": None, "rshimHostAccess": dict(_RSHIM[rshim]),
        "reason": f"{name}: {spec['state']}/{rshim}",
    }

def severity_matrix_cases() -> list[tuple[str, list[dict], list[str]]]:
    out: list[tuple[str, list[dict], list[str]]] = []
    for archetype in _CONTROLLER:
        for posture in _RSHIM:
            for errors, tag in [([], "clean"), (_MATRIX_GAP, "gap")]:
                out.append((f"1host/{archetype}/{posture}/{tag}",
                            [_matrix_host("node-a", archetype, posture)], errors))
    for label, a, b in _MATRIX_PAIRS:
        for errors, tag in [([], "clean"), (_MATRIX_GAP, "gap")]:
            out.append((f"2host/{label}/{tag}",
                        [_matrix_host("node-a", *a), _matrix_host("node-b", *b)], errors))
    for label, a, b, c in _MATRIX_TRIPLES:
        for errors, tag in [([], "clean"), (_MATRIX_GAP, "gap")]:
            out.append((f"3host/{label}/{tag}",
                        [_matrix_host("node-a", *a), _matrix_host("node-b", *b),
                         _matrix_host("node-c", *c)], errors))
    out.append(("0host/empty/clean", [], []))
    out.append(("0host/empty/gap", [], _MATRIX_GAP))
    return out

class SeverityMatrixTests(unittest.TestCase):

    def setUp(self) -> None:
        self.check = load_check_module()

    def test_every_fleet_shape_resolves_as_recorded(self) -> None:
        expected = json.loads(SEVERITY_MATRIX.read_text())
        observed = severity_signatures(self.check)

        self.assertEqual(sorted(observed), sorted(expected), "matrix case list drifted")
        for name in sorted(expected):
            with self.subTest(case=name):
                self.assertEqual(observed[name], expected[name])

def severity_signatures(check) -> dict[str, str]:
    signatures: dict[str, str] = {}
    for name, records, errors in severity_matrix_cases():
        summary = check.apply_coverage_gap(check.summarize(records), errors)
        flat = check.collector_summary({"virtio_net_bluefield": {"summary": summary}})
        iso = json.loads(flat["dpuIsolationJson"])
        rshim = iso.get("rshimHostAccess") or {}
        observed = json.loads(flat["virtioNetObservedJson"])
        signatures[name] = " | ".join(str(value) for value in [
            flat["state"], flat["virtioNet"], flat["virtioNetMode"], flat["virtioNetLine"],
            flat["virtioNetWorstObserved"], flat["virtioNetWorstObservedLine"],
            flat["virtioNetWorstObservedMode"], flat["virtioNetWorstObservedHost"],
            ",".join(sorted(entry["version"] for entry in observed)) or "-",
            iso.get("host"), iso.get("scanComplete"), iso.get("bluefield3Present"),
            rshim.get("rshimDeviceNode"), rshim.get("tmfifoNet0"), rshim.get("rshimRestricted"),
            ",".join(iso.get("unassessedHosts") or []) or "-",
        ])
    return signatures

class CoverageGapUnitTests(unittest.TestCase):

    def setUp(self) -> None:
        self.check = load_check_module()

    def clean(self, state: str, **extra: object) -> dict:
        summary = {
            "state": state,
            "version": None,
            "mode": "absent" if state == "not_applicable" else "dpu",
            "reason": "prior reason",
            "isolationEvidence": {
                "scanComplete": True,
                "bluefield3Present": False,
                "rshimHostAccess": {},
            },
        }
        summary.update(extra)
        return summary

    def test_an_unreachable_node_blocks_a_cluster_pass(self) -> None:
        summary = self.check.apply_coverage_gap(
            self.clean("version", version="25.10.9", mode="dpu"),
            ["node-3: no running nvidia-driver pod for the virtio-net check"],
        )

        self.assertEqual(summary["state"], "incomplete")
        self.assertEqual(summary["version"], "25.10.9")
        self.assertIn("node-3", summary["reason"])

    def test_an_unknown_node_keeps_its_stronger_finding(self) -> None:
        summary = self.check.apply_coverage_gap(
            self.clean("unknown"), ["node-3: virtio-net check exec failed"]
        )

        self.assertEqual(summary["state"], "unknown")

    def test_a_proven_reachable_dpu_keeps_its_isolation_finding(self) -> None:
        summary = self.clean("unknown")
        summary["isolationEvidence"]["bluefield3Present"] = True
        summary["isolationEvidence"]["rshimHostAccess"] = {"rshimDeviceNode": True}

        summary = self.check.apply_coverage_gap(summary, ["node-3: exec failed"])

        self.assertTrue(summary["isolationEvidence"]["scanComplete"])

    def test_a_gap_withdraws_a_nic_mode_claim_not_only_an_absent_one(self) -> None:

        summary = self.check.apply_coverage_gap(
            self.clean("not_running", mode="nic"), ["node-3: exec failed"]
        )

        self.assertIsNone(summary["mode"])
        self.assertNotEqual(summary["mode"], "nic")

    def test_a_gap_keeps_the_severe_dpu_mode_claim(self) -> None:

        summary = self.check.apply_coverage_gap(
            self.clean("unknown", mode="dpu"), ["node-3: exec failed"]
        )

        self.assertEqual(summary["mode"], "dpu")

    def test_no_errors_changes_nothing(self) -> None:
        summary = self.check.apply_coverage_gap(self.clean("not_applicable"), [])

        self.assertEqual(summary["state"], "not_applicable")
        self.assertEqual(summary["mode"], "absent")

def _write_severity_matrix() -> None:
    module = load_check_module()
    SEVERITY_MATRIX.parent.mkdir(parents=True, exist_ok=True)
    signatures = severity_signatures(module)
    SEVERITY_MATRIX.write_text(json.dumps(signatures, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(signatures)} cases to {SEVERITY_MATRIX}")

if __name__ == "__main__":
    if "--write-matrix" in sys.argv:
        _write_severity_matrix()
    else:
        unittest.main()
