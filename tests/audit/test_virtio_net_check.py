#!/usr/bin/env python3
"""The BlueField VIRTIO-Net check reports five states and never a false pass.

NVIDIA bulletin a_id 5815 (CVE-2026-65094) is a tenant-escape class defect in
the virtio-net controller on a BlueField-3 DPU. The controller version is
readable only from the DPU ARM side, so the check's job is as much to settle
scope as to read a version, and every state it reports has to be earned:

* ``version``        - the RUNNING controller version was actually read. The
  staged "Destination Controller" and the ``virtnet -v`` CLI version are both
  different things and neither one may fill it, because the evaluator grades
  this value and never reads the source label beside it.
* ``not_running``    - a BlueField-3 in NIC mode. No controller runs, so nothing
  is exposed today, but the firmware stays installed and the mode is one
  mlxconfig setting away, so this is a latent finding and not ``not_applicable``.
* ``not_applicable`` - a completed scan found no BlueField-3.
* ``unknown``        - BlueField-3 in confirmed DPU mode with no reachable
  ``virtnet``. The provider must attest.
* ``incomplete``     - the evidence gap. The scan or the mode read could not
  run, the listing was empty or exited non-zero, or the per-node fan-out did
  not reach every host. This is the state most likely to regress into a false
  ``not_applicable``: ``mlxconfig`` normally needs root and a tenant audit runs
  without it, and a Slurm audit before ``salloc`` sees only the login node. Each
  of those is asserted explicitly.

Every test runs the real check as a subprocess with stub executables on PATH,
following the AGENTS.md testing doctrine (pattern 1). The stubs record their
argv the same way the audit-local ``bashtest.py`` stubs do.
"""

from __future__ import annotations

import hashlib
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
Configurations:                              Next Boot
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         ENABLED(0)
         INTERNAL_CPU_RSHIM                  ENABLED(0)
"""
NIC_MODE_MLXCONFIG = """
Configurations:                              Next Boot
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         DISABLED(1)
         INTERNAL_CPU_RSHIM                  ENABLED(0)
"""
ZERO_TRUST_MLXCONFIG = """
Configurations:                              Next Boot
         INTERNAL_CPU_MODEL                  EMBEDDED_CPU(1)
         INTERNAL_CPU_OFFLOAD_ENGINE         ENABLED(0)
         INTERNAL_CPU_RSHIM                  DISABLED(1)
"""
VIRTNET_VERSION_JSON = (
    '[\n  { "Original Controller": "v24.10.17" },\n'
    '  { "Destination Controller": "v24.10.19" }\n]\n'
)


class CheckHarness(unittest.TestCase):
    """Run the real check with stub executables on PATH."""

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
        """Install a stub that records its argv, then runs the given body."""
        path = self.bin / name
        path.write_text(
            "#!/bin/bash\n"
            f'printf "%s\\n" "$*" >> "{self.calls}/{name}.calls"\n' + body + "\n"
        )
        path.chmod(0o755)

    def stub_output(self, name: str, stdout: str, *, returncode: int = 0) -> None:
        # The payload is read with an absolute /bin/cat, because `cat` itself is
        # one of the commands the check runs and is stubbed in some tests.
        data = self.tmp / f"{name}.stdout"
        data.write_text(stdout)
        self.stub(name, f'/bin/cat "{data}"\nexit {returncode}')

    def stub_missing(self, name: str) -> None:
        """Nothing is installed for this name, so exec fails with ENOENT."""
        target = self.bin / name
        if target.exists():
            target.unlink()

    def stub_root_only(self, name: str, stdout: str) -> None:
        """A tool that answers only under the sudo stub below.

        This is the real behavior of `mlxconfig` on a tenant account: it opens
        the device itself, so an unprivileged call fails with the message below
        while the answer sits on the card.
        """
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
        """Passwordless sudo: drop the -n flag, mark the child, exec it."""
        self.stub(
            "sudo",
            'while [ "$1" = "-n" ]; do shift; done\nexport STUB_SUDO=1\nexec "$@"',
        )

    def stub_sudo_denied(self) -> None:
        """sudo without passwordless rights. `-n` makes it fail, never prompt."""
        self.stub("sudo", 'echo "sudo: a password is required" >&2\nexit 1')

    def calls_for(self, name: str) -> list[str]:
        path = self.calls / f"{name}.calls"
        return path.read_text().splitlines() if path.exists() else []

    def run_check(self, *args: str, **env_overrides: str) -> dict:
        env = {
            **os.environ,
            # Only the stub dir, so anything not stubbed is genuinely missing
            # and the check sees ENOENT exactly as it would on a real host.
            "PATH": str(self.bin),
            "CLUSTERMAX_AUDIT_ROOT": str(self.root),
            "CLUSTERMAX_HARNESS": "standalone",
            "CLUSTERMAX_AUDIT_HARNESS": "standalone",
            # The RShim SSH attempt is opt-out by default in these tests; the
            # cases that exercise it turn it back on.
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

        # The staged "Destination Controller" is deliberately not reported: the
        # running controller is what is exposed.
        self.assertEqual(record["version"], "24.10.17")
        self.assertEqual(record["versionSource"], "virtnet-version")
        self.assertEqual(record["state"], "version")

    def test_virtnet_dash_v_is_never_the_controller_version(self) -> None:
        # `virtnet -v` prints the CLI's own version. A staged DOCA upgrade puts
        # the CLI on the new release while the old controller is still running,
        # which is the same split `virtnet version` reports as Original versus
        # Destination Controller. 24.10.50 is the published LTS24 minimum, so
        # letting it fill `version` would pass a controller nobody read.
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
        # Kept as its own labelled fact, so the reading is not lost.
        self.assertEqual(record["cliVersion"], "24.10.50")
        self.assertIn("24.10.50", record["reason"])
        self.assertIn("not graded", record["reason"])

    def test_a_cli_version_reaches_the_evaluator_as_unknown(self) -> None:
        # The evaluator grades the `virtioNet` value and never reads
        # `virtioNetSource`, so a source label alone cannot stop a CLI version
        # from being graded as controller firmware. The value itself must not
        # be the CLI's.
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

    def test_leading_v_is_stripped_from_the_version(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        self.stub("virtnet", """
[ "$1" = version ] && echo '[{"Original Controller": "v25.10.6"}]' || exit 1
""")

        record = self.host_record()

        self.assertEqual(record["version"], "25.10.6")
        self.assertNotIn("v", record["version"])


class ReleaseLineTests(CheckHarness):
    """The release train is reported only when evidence names it."""

    def bluefield_dpu(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)

    def test_line_is_null_when_nothing_names_a_train(self) -> None:
        # 25.10.x is exactly the ambiguous band: GA 25.10.6 and LTS25 25.10.2
        # share the prefix, so inferring a line from the number would produce a
        # confident wrong verdict. The check must decline.
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
        # "ga" bounded by punctuation appears inside ordinary build strings. A
        # case-insensitive match would read one as the GA train and grade the
        # firmware against the GA minimum (25.10.6) instead of LTS25 (25.10.2),
        # which is a confident wrong verdict from a substring.
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
        # In NIC mode no virtio-net controller runs, so there is no exposure
        # today. The card and its firmware are still present and NIC versus DPU
        # mode is an mlxconfig setting, so this must stay a visible latent
        # finding and must never collapse into "not installed".
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", NIC_MODE_MLXCONFIG)

        record = self.host_record()

        self.assertEqual(record["state"], "not_running")
        self.assertNotEqual(record["state"], "not_applicable")
        self.assertEqual(record["mode"], "nic")
        self.assertTrue(record["bluefield3Present"])
        self.assertIn("firmware stays installed", record["reason"])

    def test_no_bluefield_with_a_completed_scan_is_not_applicable(self) -> None:
        # Most clusters have no DPU. A permanent unknown on all of them would
        # train reviewers to ignore the field.
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        record = self.host_record()

        self.assertEqual(record["state"], "not_applicable")
        self.assertFalse(record["bluefield3Present"])
        self.assertEqual(record["bluefieldDevices"], [])
        # A 1af4 device alone proves nothing, so its presence must not move the
        # verdict; it is recorded as supporting evidence only.
        self.assertEqual(record["virtioPciDevices"], 1)

    def test_missing_lspci_is_incomplete_not_not_applicable(self) -> None:
        self.stub_missing("lspci")

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])

    def test_mlxconfig_without_root_is_incomplete_not_not_applicable(self) -> None:
        # mlxconfig normally needs root, so this is the tenant case and the one
        # most likely to regress into a false not_applicable. Here sudo itself
        # is unusable, which is the only remaining way to reach this state.
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub("mlxconfig", 'echo "-E- You must be root to run this tool" >&2\nexit 1')
        self.stub("mst", 'echo "-E- Root permissions required" >&2\nexit 1')
        self.stub_sudo_denied()

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertTrue(record["bluefield3Present"])
        self.assertEqual(record["mode"], "unknown")
        self.assertIn("root", record["reason"])
        # The reported error names the tool the operator has to run rather than
        # the sudo wrapper. True on every privilege path, so this holds for a
        # root runner too.
        self.assertIn("mlxconfig", record["modeError"])

    def test_a_failed_lspci_with_partial_output_is_incomplete(self) -> None:
        # lspci can print some of the bus and still exit non-zero. The device it
        # did not reach may be the BlueField, so a partial listing that names no
        # DPU is an unread bus, never "no DPU is present".
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI, returncode=1)

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])

    def test_an_empty_lspci_listing_is_incomplete(self) -> None:
        # A host always has PCI devices. An empty listing with a clean exit is
        # a container with no bus access, not a machine with no BlueField.
        self.stub_output("lspci", "")

        record = self.host_record()

        self.assertEqual(record["state"], "incomplete")
        self.assertFalse(record["scanComplete"])
        self.assertIsNone(record["bluefield3Present"])
        self.assertIn("no PCI device", record["scanError"])

    def test_a_corroborated_empty_bus_is_not_applicable(self) -> None:
        # The exception to the rule above: some virtual machines genuinely
        # expose no PCI device at all. lspci exits cleanly with nothing to
        # print and /sys/bus/pci/devices is readable and empty, so two
        # independent readers agree the bus holds zero devices. That is a read
        # bus with no BlueField on it, not a tool failure. Without this, such
        # a host graded a permanent unknown nobody could attest away.
        self.stub_output("lspci", "")
        (self.root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)

        record = self.host_record()

        self.assertTrue(record["scanComplete"])
        self.assertIsNone(record["scanError"])
        self.assertFalse(record["bluefield3Present"])
        self.assertEqual(record["state"], "not_applicable")

    def test_a_populated_sysfs_bus_does_not_corroborate_an_empty_listing(self) -> None:
        # sysfs holding a device while lspci printed nothing means lspci
        # failed to read the bus, and the device it missed may be the
        # BlueField, so the scan stays incomplete.
        self.stub_output("lspci", "")
        device = self.root / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
        device.mkdir(parents=True)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_does_not_corroborate(self) -> None:
        # A directory the check cannot list is missing data, not an empty
        # bus, so the permissions problem must never upgrade an unread bus
        # into a claim of absence.
        self.stub_output("lspci", "")
        bus = self.root / "sys" / "bus" / "pci" / "devices"
        bus.mkdir(parents=True)
        bus.chmod(0o000)
        self.addCleanup(bus.chmod, 0o755)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    def test_a_failed_lspci_is_incomplete_even_beside_an_empty_sysfs_bus(self) -> None:
        # The corroboration only upgrades a clean, empty listing. A failed
        # lspci is a failed read whatever sysfs says.
        self.stub_output("lspci", "", returncode=1)
        (self.root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)

        record = self.host_record()

        self.assertFalse(record["scanComplete"])
        self.assertEqual(record["state"], "incomplete")

    def test_a_bluefield_in_a_partial_listing_still_counts_as_present(self) -> None:
        # The asymmetry that makes the rule above safe: positive evidence is
        # trustworthy even from a failed run, so a non-zero exit must not
        # discard a DPU that was actually seen.
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
    """Which privilege path a host is on, decided without running anything.

    These run whatever identity the suite runs under, which is what makes the
    root and no-sudo paths testable at all: the subprocess cases below need a
    non-root runner, because a real euid cannot be injected into a subprocess.
    """

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def prefix(self, *, euid: int, sudo: str | None) -> tuple[list[str], str]:
        return self.check.privileged_prefix(which=lambda _name: sudo, euid=lambda: euid)

    def test_a_root_caller_needs_no_prefix(self) -> None:
        # Even where sudo exists, a root caller already holds the rights.
        prefix, label = self.prefix(euid=0, sudo="/usr/bin/sudo")

        self.assertEqual(prefix, [])
        self.assertEqual(label, self.check.ESCALATION_ROOT)

    def test_a_tenant_with_sudo_gets_one_non_interactive_attempt(self) -> None:
        prefix, label = self.prefix(euid=1000, sudo="/usr/bin/sudo")

        self.assertEqual(prefix, ["/usr/bin/sudo", "-n"])
        self.assertEqual(label, self.check.ESCALATION_SUDO)

    def test_a_tenant_without_sudo_has_nothing_to_try(self) -> None:
        # The k8s driver-pod image and most containers.
        prefix, label = self.prefix(euid=1000, sudo=None)

        self.assertEqual(prefix, [])
        self.assertEqual(label, self.check.ESCALATION_UNAVAILABLE)


class EscalationReasonTests(unittest.TestCase):
    """A failed mode read states the privilege path that actually ran.

    The reason string is graded evidence that operators paste into provider
    feedback, so it may not claim a `sudo -n` retry on a host that never ran
    one. decide() is pure, so every path is checked here directly.
    """

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def reason(self, escalation: str | None) -> str:
        state, reason = self.check.decide(
            {
                "scanComplete": True,
                "bluefield3Present": True,
                "mode": "unknown",
                "modeError": "mlxconfig failed: -E- Failed to open the device",
                "modeEscalation": escalation,
            }
        )
        self.assertEqual(state, "incomplete")
        return reason

    def test_a_sudo_host_reports_the_retry_that_ran(self) -> None:
        self.assertIn("sudo -n retry did not answer", self.reason(self.check.ESCALATION_SUDO))

    def test_a_host_without_sudo_never_claims_a_retry(self) -> None:
        reason = self.reason(self.check.ESCALATION_UNAVAILABLE)

        self.assertIn("no sudo is installed", reason)
        self.assertNotIn("retry did not answer", reason)

    def test_a_root_caller_never_claims_a_retry(self) -> None:
        reason = self.reason(self.check.ESCALATION_ROOT)

        self.assertIn("root rights", reason)
        self.assertNotIn("retry did not answer", reason)

    def test_a_record_from_an_older_collector_still_reads_sensibly(self) -> None:
        # An artifact collected before modeEscalation existed carries no value.
        reason = self.reason(None)

        self.assertIn("root", reason)
        self.assertNotIn("retry did not answer", reason)


@unittest.skipIf(os.geteuid() == 0, "a root caller holds the rights and never escalates")
class PrivilegedModeReadTests(CheckHarness):
    """`mlxconfig` needs root, so the mode read escalates with `sudo -n`.

    Observed on prime-b300-slurm (2026-07-31): the operator account held
    passwordless sudo, `mlxconfig` answered under `sudo` and failed with `-E-
    Failed to open the device` without it, and the check reported `incomplete`.
    Both criteria that depend on the read graded `unknown`: the controller
    criterion lost the platform mode, and DPU host isolation lost
    `INTERNAL_CPU_RSHIM`, its only non-filesystem evidence. On that host the
    escalated read proves NIC mode and an enabled RShim, so the audit reports a
    latent controller and a reachable DPU control plane instead of two unknowns.
    """

    def test_a_tenant_mode_read_escalates_and_settles_the_scope(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", NIC_MODE_MLXCONFIG)
        self.stub_sudo()

        record = self.host_record()

        self.assertEqual(record["mode"], "nic")
        self.assertEqual(record["state"], "not_running")
        self.assertIsNone(record["modeError"])
        # The artifact says which read answered, so an operator can tell an
        # unprivileged reading from an escalated one.
        self.assertEqual(record["modeSource"], "sudo mlxconfig")
        self.assertEqual(record["modeEscalation"], "sudo -n")
        # Unprivileged first, then the same query under sudo -n.
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
        # The isolation criterion reads this record shape verbatim, so the
        # escalation has to land in dpuIsolationJson and not only in the mode.
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", ZERO_TRUST_MLXCONFIG)
        self.stub_sudo()

        summary = self.run_check("--summary")
        evidence = json.loads(summary["dpuIsolationJson"])

        self.assertEqual(evidence["rshimHostAccess"]["internalCpuRshim"], "1")
        self.assertTrue(evidence["rshimHostAccess"]["rshimRestricted"])
        self.assertIsNone(evidence["modeError"])

    def test_an_enabled_rshim_is_proven_rather_than_left_unknown(self) -> None:
        # The prime-b300-slurm reading: INTERNAL_CPU_RSHIM=ENABLED(0). The
        # evaluator grades this as a reachable DPU control plane, so leaving it
        # unreadable turned a proven finding into "posture unknown".
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_root_only("mlxconfig", NIC_MODE_MLXCONFIG)
        self.stub_sudo()

        rshim = json.loads(self.run_check("--summary")["dpuIsolationJson"])["rshimHostAccess"]

        self.assertEqual(rshim["internalCpuRshim"], "0")
        self.assertIs(rshim["rshimRestricted"], False)

    def test_a_denied_sudo_keeps_the_host_unresolved(self) -> None:
        # No passwordless rights. sudo -n fails at once without a prompt, the
        # host stays unresolved rather than clean, and the reason names the
        # retry that did run.
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

    def test_mst_start_carries_the_same_privilege_as_the_query(self) -> None:
        # `mst start` loads kernel modules, so an unprivileged attempt is a
        # wasted call. It only helps when it runs with the same rights.
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub("mlxconfig", 'echo "-E- Failed to open the device" >&2\nexit 1')
        self.stub("mst", "exit 0")
        self.stub_sudo()

        self.host_record()

        self.assertTrue(any(call.startswith("-n mst") for call in self.calls_for("sudo")))


class RshimEvidenceTests(CheckHarness):
    """DPU-boundary evidence is recorded, never graded inside the check."""

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
        # No pass/fail verdict is invented here; the record carries evidence.
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
    """The rollup the collectors hand to security_version_audit.py."""

    def test_summary_reports_not_installed_for_a_clean_not_applicable(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "not_applicable")
        # "not-installed" is the only value the evaluator reads as
        # not_applicable; every other state must arrive as "unknown".
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
        # The regression this test exists for: "not-installed" is the one value
        # the evaluator grades as not_applicable, which would hide a present
        # BlueField whose firmware is only idle. NIC mode must arrive as an
        # unknown version carrying mode "nic", so the evaluator can report the
        # latent exposure instead of dismissing it.
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

        # dpu_host_isolation_verdict() reads this record shape verbatim.
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
    """A DPU is per node, so a partial fan-out cannot clear the cluster."""

    def slurm_env(self) -> dict[str, str]:
        return {
            "CLUSTERMAX_HARNESS": "slurm",
            "CLUSTERMAX_AUDIT_HARNESS": "slurm",
            "SLURM_JOB_ID": "",
        }

    def test_a_login_node_without_an_allocation_is_not_a_clean_cluster(self) -> None:
        # `cmax audit` before `salloc` is the documented flow, and the login
        # node has no DPU. Reporting that as "not-installed" grades the whole
        # cluster not_applicable from a host that is not even a worker.
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

        # dpu_host_isolation_verdict() reports not_applicable on a completed
        # scan with no BlueField, so the coverage gap has to reach scanComplete.
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

    def test_a_complete_local_scan_on_standalone_stays_not_applicable(self) -> None:
        # The guard must not fire where the local host genuinely is the fleet,
        # or every DPU-free standalone box turns into a permanent warning.
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)

        summary = self.run_check("--summary")

        self.assertEqual(summary["state"], "not_applicable")
        self.assertEqual(summary["virtioNet"], "not-installed")


class WorstObservedTests(CheckHarness):
    """A proven-vulnerable host survives an unresolved peer.

    The rollup state answers "can this cluster be cleared" and an unreadable
    node correctly blocks it. It must not also erase a version another node
    reported. Coverage gaps weaken a pass or a not-applicable, never a fail.
    """

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
        """Run the real slurm arm with an srun stub emitting per-host JSON."""
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
        # THE regression. 24.10.17 is below the published LTS24 minimum of
        # 24.10.50, so node-a is proven vulnerable. node-b could not be read.
        # The cluster rollup must stay unknown, and the proven finding must
        # still reach the evaluator instead of being softened into a warning.
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
        # This field used to carry the lowest version paired with the worst mode
        # across hosts, which invented a host that does not exist: node-a's
        # below-minimum version wearing node-b's DPU mode. The argument was that
        # the pairing can never under-report, which is only half the
        # requirement. A verdict may assert only what the audit proved, in both
        # directions, and here it manufactured a live critical failure out of an
        # idle below-minimum card and a patched running one.
        #
        # 24.10.50 is the published LTS24 minimum, so node-b is patched.
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
        """The narrowing is limited to readings that genuinely disagree.

        Two DPU-mode hosts on the same named release line describe one
        situation, so the lowest version still speaks for both and the evaluator
        grades one reading rather than two. The line has to be named: two
        readings with no line are comparable only by number, which is what the
        test below covers.
        """
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
        """An unknown line is not a shared line.

        The collector reports a line only when the output names one, so
        `line: None` on every host is the ordinary case. Comparing the field as
        a set read that as one comparable line, because `{None}` has one member,
        and the lines interleave: 23.10.30 clears the LTS23 minimum and 24.10.17
        is below the LTS24 minimum, so the lower NUMBER was the milder grade. The
        fleet reported 23.10.30 and graded pass with exposure none while a
        below-minimum controller ran on the other host.
        """
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
        # 1.8.0 is above the retired scheme's affected range and grades
        # unknown; 24.10.17 is below the LTS24 minimum and grades fail. The lower
        # NUMBER is the milder finding, so a bare minimum across the two schemes
        # would pick the weaker verdict and re-open the defect.
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
        # srun returns the hosts that answered and says nothing about the ones
        # that did not, so a 4-node allocation that yields one record would
        # otherwise read as a complete cluster answer built from a subset.
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
        # One host of four answered, and it is running below-minimum firmware.
        # The cluster claim correctly drops to incomplete. The host fact must
        # survive that, or the coverage gap swallows a proven vulnerability.
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
        # 24.10.50 is exactly the published LTS24 minimum, so node-a is patched
        # and grades pass on its own. node-b carries installed controller
        # firmware that nobody read, and on its own grades unknown with the
        # latent-exposure wording. Ranking `version` above `not_running` let
        # node-a speak for the fleet: the rollup read as complete coverage, the
        # single reading graded pass with exposure none, and node-b disappeared
        # from the graded record. Adding one patched host must not turn the
        # cluster green.
        summary = self.fan_out(
            self.host_json("node-a", state="version", version="24.10.50", line="LTS24"),
            self.nic_unread(),
        )

        self.assertEqual(summary["state"], "not_running")
        # "version" is the one state the consumer reads as complete coverage.
        self.assertNotEqual(summary["state"], "version")
        self.assertEqual(summary["virtioNet"], "unknown")
        # node-b's finding is what the cluster reason now carries.
        self.assertIn("NIC mode", summary["virtioNetReason"])
        self.assertIn("firmware stays installed", summary["virtioNetReason"])
        # node-a's proven reading still reaches the evaluator to be graded, so
        # the rollup change costs no evidence.
        self.assertEqual(summary["virtioNetWorstObserved"], "24.10.50")
        self.assertEqual(summary["virtioNetWorstObservedLine"], "LTS24")

    def test_a_nic_mode_peer_does_not_weaken_a_proven_fail(self) -> None:
        # The safety property behind the rung above. 24.10.17 is below the
        # LTS24 minimum, so node-c is proven vulnerable. Denying complete
        # coverage must not cost that finding: the consumer's partial-coverage
        # rule keeps a fail a fail, and it can only do so if the reading still
        # arrives.
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
        spec = importlib.util.spec_from_file_location("virtio_net_check_cache", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

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
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def test_common_nvidia_namespace_is_discovered(self) -> None:
        # Azure run 20260731-210243-907 reached this current-master check, but
        # it reported an incomplete fleet because the GPU Operator is in the
        # common `nvidia` namespace that this check did not search.
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
                {"metadata": {"name": "cw-nvidia-gpu-operator"}},
            ]
        }

        def runner(command, **kwargs):
            if command[1:3] == ["get", "namespace"]:
                return subprocess.CompletedProcess(command, 1, "", "")
            return subprocess.CompletedProcess(
                command, 0, json.dumps(namespaces), ""
            )

        namespace = self.check.k8s_namespace(env={}, runner=runner)

        self.assertEqual(namespace, "cw-nvidia-gpu-operator")

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
            "cw-nvidia-gpu-operator", "gpu-1", runner=runner
        )

        self.assertIsNone(error)
        self.assertEqual(record["state"], "not_applicable")
        exec_command = commands[-1]
        self.assertIn("nvidia-device-plugin", exec_command)
        self.assertEqual(exec_command[-5:-2], ["chroot", "/host", "sh"])


class ReleaseLineDetectionTests(unittest.TestCase):
    """The release line is read only when the evidence names exactly one."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def test_evidence_naming_two_lines_names_none(self) -> None:
        """Every pattern is consulted before a line is claimed.

        The scan returned as soon as the LTS pattern matched, so evidence naming
        both an LTS train and GA yielded the LTS label with full confidence and
        the GA pattern was never read. Inside the interleaved 25.10 window the
        two lines are fixed at different patches, so that grades the firmware
        against a minimum it may not belong to and can pass a vulnerable
        controller.
        """
        self.assertIsNone(self.check.detect_line(["bundle LTS24 25.10.4", "channel GA"]))
        self.assertIsNone(self.check.detect_line(["LTS24 GA 25.10.4"]))

    def test_a_single_named_line_is_still_read(self) -> None:
        """The fix must not make every line undetectable."""
        self.assertEqual(self.check.detect_line(["bundle LTS24 25.10.4"]), "LTS24")
        self.assertEqual(self.check.detect_line(["bundle GA 25.10.4"]), "GA")

    def test_two_lts_trains_are_still_ambiguous(self) -> None:
        self.assertIsNone(self.check.detect_line(["LTS23 and LTS24"]))


class ReleaseLineFallbackTests(unittest.TestCase):
    """`collect_line`, not `detect_line`: the caller is where the line is decided.

    The fallback reads used to scan only their own text, so a contradiction the
    primary evidence had already established was discarded and the next
    single-label source claimed the line with full confidence. That is the same
    false-pass mechanism `detect_line` guards against, reached one call up, and
    the tests that cover `detect_line` directly cannot see it.
    """

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def runner_for(self, outputs: dict[str, str]):
        """Answer each fallback command with the given stdout."""
        def run(command, **kwargs):
            key = "list" if command[-1] == "list" else "release"
            return types.SimpleNamespace(
                returncode=0, stdout=outputs.get(key, ""), stderr=""
            )
        return run

    def test_a_later_single_label_cannot_resolve_an_earlier_contradiction(self) -> None:
        # A staged DOCA upgrade: the primary evidence names both trains, which
        # detect_line correctly refuses to grade. `virtnet list` then prints a
        # bare channel label.
        line, evidence = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4 LTS24", "channel GA"],
            runner=self.runner_for({"list": "GA"}),
            timeout=5,
        )
        self.assertIsNone(line)
        # The contradictory primary evidence is still on file.
        self.assertIn("Original Controller: 25.10.4 LTS24", evidence)

    def test_a_fallback_still_supplies_a_line_the_primary_evidence_lacks(self) -> None:
        """The fix must not make the fallbacks useless."""
        line, _ = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4"],
            runner=self.runner_for({"list": "channel LTS24"}),
            timeout=5,
        )
        self.assertEqual(line, "LTS24")

    def test_a_contradiction_raised_by_a_fallback_survives_the_next_one(self) -> None:
        """The ambiguity can arrive mid-chain, and it still has to stick.

        The primary evidence names no train, so `virtnet list` runs and its
        output names both. That contradiction must not then be resolved by the
        bundle identity naming one: three opinions with two distinct labels is
        still ambiguity.

        The other direction, a fallback contradicting a primary that already
        named one train, is unreachable by construction: `collect_line` returns
        as soon as any step yields a single label, so no later read happens.
        """
        line, evidence = self.check.collect_line(
            ["virtnet"],
            ["Original Controller: 25.10.4"],
            runner=self.runner_for({"list": "LTS24 and GA channels", "release": "LTS24"}),
            timeout=5,
        )
        self.assertIsNone(line)
        self.assertEqual(len(evidence), 3)


class IsolationSelectionTests(unittest.TestCase):
    """Which host decides the DPU host-isolation verdict, graded for real.

    The verdict is computed from ONE host record, so the record this module
    selects is the whole verdict. Each case runs the real evaluator as a
    subprocess, because "node-a was selected" is not the claim that matters:
    "the cluster grades fail" is.

    The rule is asymmetric on purpose. Incomplete coverage may weaken a clean
    answer. It must never erase a proven failure.
    """

    WORKLOAD = CHECK.parent.parent.parent

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def record(self, host: str, *, scan: bool, present: bool | None, rshim: dict,
               state: str = "unknown", scan_error: str | None = None) -> dict:
        return {
            "host": host, "state": state, "version": None, "versionSource": None,
            "line": None, "mode": "dpu", "scanComplete": scan,
            "bluefield3Present": present, "scanError": scan_error, "modeError": None,
            "rshimHostAccess": rshim, "reason": f"{host}: {state}",
        }

    def proven(self, host: str = "node-a") -> dict:
        """Host side reached the DPU control plane. Grades fail on its own."""
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": True, "tmfifoNet0": False,
            "rshimRestricted": False, "internalCpuRshim": "0"})

    def hardened(self, host: str = "node-h") -> dict:
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": False, "tmfifoNet0": False,
            "rshimRestricted": True, "internalCpuRshim": "1"})

    def unreadable(self, host: str = "node-u") -> dict:
        """BlueField present, mlxconfig gave no INTERNAL_CPU_RSHIM."""
        return self.record(host, scan=True, present=True, rshim={
            "rshimDeviceNode": False, "tmfifoNet0": False,
            "rshimRestricted": None, "internalCpuRshim": "unknown"})

    def incomplete(self, host: str = "node-b") -> dict:
        return self.record(host, scan=False, present=None, rshim={},
                           state="incomplete", scan_error="mlxconfig is not installed")

    def grade(self, records: list[dict]) -> tuple[dict, dict]:
        """check rollup -> collector flattening -> the real evaluator."""
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
        # THE regression. node-a answered and showed /dev/rshim0, so the DPU
        # control plane is reachable from the tenant-visible host side. node-b
        # could not be read and says nothing about node-a. Selecting node-b
        # reported unknown and erased a proven tenant-isolation finding.
        evidence, verdict = self.grade([self.proven(), self.incomplete()])

        self.assertEqual(verdict["status"], "fail")
        self.assertNotEqual(verdict["status"], "unknown")
        self.assertEqual(evidence["host"], "node-a")
        # The fail stands, and the partial coverage is still recorded beside it.
        self.assertEqual(evidence["unassessedHosts"], ["node-b"])

    def unscanned_but_reachable(self, host: str = "node-n") -> dict:
        """No lspci, so no PCI scan, but the RShim path is right there.

        The normal shape of a minimal Kubernetes driver pod: `collect_rshim`
        stats /dev/rshim0 and tmfifo_net0 and never runs lspci.
        """
        return self.record(host, scan=False, present=None, state="incomplete",
                           scan_error="lspci not found", rshim={
                               "rshimDeviceNode": True, "tmfifoNet0": False,
                               "rshimRestricted": None, "internalCpuRshim": "unknown"})

    def test_selection_follows_the_consumer_onto_a_scanless_proof(self) -> None:
        """Selection must agree with the consumer about what produces a fail.

        The consumer grades a record fail on the two filesystem paths alone,
        before its scan gate. While selection still required a completed scan,
        this record sat on the same rung as a host that proved nothing, so a
        hardened peer could be selected in its place and the fan-out
        re-introduced the erasure one layer above the consumer.
        """
        evidence, verdict = self.grade(
            [self.unscanned_but_reachable(), self.hardened()]
        )
        self.assertEqual(verdict["status"], "fail")
        self.assertEqual(evidence["host"], "node-n")
        # The host that produced the proof is not also an unassessed host.
        self.assertNotIn("node-n", evidence["unassessedHosts"])

    def test_a_scanless_mlxconfig_reading_is_not_treated_as_proof(self) -> None:
        """INTERNAL_CPU_RSHIM needs the scan, so it must not win selection.

        It comes from mlxconfig reading the device the scan finds. The consumer
        keeps it behind the scan gate, so selection does too, otherwise the two
        disagree again in the opposite direction.
        """
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
        # The asymmetry, and it has to survive the change above. An unread host
        # can still be exposing its control plane, so a partial clean is not a
        # pass.
        _, verdict = self.grade([self.hardened(), self.incomplete()])

        self.assertEqual(verdict["status"], "unknown")
        self.assertNotEqual(verdict["status"], "pass")

    def test_a_hardened_host_does_not_speak_for_an_unreadable_posture(self) -> None:
        # Same asymmetry one rung down. The old ranking scored "present and
        # hardened" and "present, posture unreadable" identically, so a
        # hostname tie-break could report pass while a peer was never read.
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

# RShim postures a host can be in, one per rung of the isolation ladder.
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

# Controller states a host can be in, plus the release-line and versioning-scheme
# shapes that decide how a reading grades. 24.10.50 is the published LTS24 minimum
# and 24.10.17 is below it, so v_pass and v_fail straddle a real boundary.
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
    """Every fleet shape the severity ladders have to resolve.

    Single hosts cross every controller rung with every RShim posture, then
    two- and three-host fleets cover the mixed cases where one host's rung
    decides for another. Each shape runs twice, with and without a fan-out
    coverage gap, because the gap is the other half of the rule.
    """
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
    """No verdict may move. The severity ladders decide every case below.

    The controller ladder, the isolation ladder and the coverage clamp all live
    in this check, and the consumer's verdicts are a function of what the check
    emits. Pinning the check's output across every fleet shape is therefore
    necessary and sufficient to catch a verdict moving, and it stays inside this
    file's contract home rather than pinning another module's prose.

    This matrix was captured before the severity refactor collapsed four
    hand-written orderings into one shared ladder, and replayed after it, to
    prove the refactor changed no behaviour. Regenerate deliberately, never to
    make a failing run green:

        python3 tests/audit/test_virtio_net_check.py --write-matrix
    """

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def test_every_fleet_shape_resolves_as_recorded(self) -> None:
        expected = json.loads(SEVERITY_MATRIX.read_text())
        observed = severity_signatures(self.check)

        self.assertEqual(sorted(observed), sorted(expected), "matrix case list drifted")
        for name in sorted(expected):
            with self.subTest(case=name):
                self.assertEqual(observed[name], expected[name])


def severity_signatures(check) -> dict[str, str]:
    """One line per fleet: every check output a verdict is computed from.

    Field order: state, virtioNet, mode, line, worst version / line / mode /
    host, observed versions, then the isolation record's host, scanComplete,
    bluefield3Present, the three RShim signals, and unassessedHosts. The
    trailing digest covers the rollup reason, which selects a host's wording
    without changing a grade.
    """
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
            hashlib.sha256((flat["virtioNetReason"] or "").encode()).hexdigest()[:8],
        ])
    return signatures


class TimeoutBudgetTests(unittest.TestCase):
    """The srun budget has to cover the worst-case single host."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def test_the_srun_budget_covers_the_worst_case_host(self) -> None:
        # Commands gather() can run on one host, each hanging to its own
        # timeout: lspci; mlxconfig, the sudo -n retry, sudo -n mst start, the
        # sudo -n mlxconfig retry; local virtnet version and -v; then four RShim
        # SSH reads. srun runs the hosts in parallel, so the slowest host sets
        # the wall time.
        check = self.check
        worst = (
            check.TOOL_TIMEOUT_S
            + 4 * check.TOOL_TIMEOUT_S
            + 2 * check.TOOL_TIMEOUT_S
            + 4 * (check.SSH_TIMEOUT_S * 2)
        )
        startup_allowance = 60

        self.assertLess(worst + startup_allowance, check.SLURM_TIMEOUT_S)


class CoverageGapUnitTests(unittest.TestCase):
    """apply_coverage_gap() over rollups the k8s arm can produce."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

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

        # The version stays as evidence; only the graded state drops, because a
        # version read from seven of eight nodes does not clear the eighth.
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

        # A host that can reach its DPU is a finding whatever the unvisited
        # hosts look like, so it must not be softened into an evidence gap.
        self.assertTrue(summary["isolationEvidence"]["scanComplete"])

    def test_a_gap_withdraws_a_nic_mode_claim_not_only_an_absent_one(self) -> None:
        # THE regression. A cluster-wide "nic" is a claim about every node,
        # exactly as "absent" is: summarize() computes it as the worst mode
        # across the hosts that ANSWERED. The consumer grades it as a latent
        # exposure, which reads as installed but idle, while an unread host may
        # be in DPU mode and actively exposed. Withdrawing only "absent" left
        # that permissive claim standing.
        summary = self.check.apply_coverage_gap(
            self.clean("not_running", mode="nic"), ["node-3: exec failed"]
        )

        self.assertIsNone(summary["mode"])
        self.assertNotEqual(summary["mode"], "nic")

    def test_a_gap_keeps_the_severe_dpu_mode_claim(self) -> None:
        # The direction that makes the withdrawal safe. "dpu" is the exposed
        # mode, so claiming it fleet-wide from partial data over-states, and
        # over-stating is the safe error. Withdrawing it would drop the cluster
        # to a milder reading, which is the failure the whole rule exists for.
        summary = self.check.apply_coverage_gap(
            self.clean("unknown", mode="dpu"), ["node-3: exec failed"]
        )

        self.assertEqual(summary["mode"], "dpu")

    def test_no_errors_changes_nothing(self) -> None:
        summary = self.check.apply_coverage_gap(self.clean("not_applicable"), [])

        self.assertEqual(summary["state"], "not_applicable")
        self.assertEqual(summary["mode"], "absent")


class SummaryRollupTests(unittest.TestCase):
    """Worst case wins across nodes; one unresolved node blocks the cluster."""

    def setUp(self) -> None:
        # The check's filename has a hyphen, so it is loaded by path.
        spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module

    def record(self, host: str, state: str, version: str | None = None, line: str | None = None) -> dict:
        return {
            "host": host,
            "state": state,
            "version": version,
            "versionSource": "virtnet-version" if version else None,
            "line": line,
            "reason": f"{host}: {state}",
            "bluefield3Present": state != "not_applicable",
        }

    def test_oldest_version_is_reported(self) -> None:
        summary = self.check.summarize(
            [
                self.record("a", "version", "24.10.19", "LTS24"),
                self.record("b", "version", "24.10.17", "LTS24"),
            ]
        )

        self.assertEqual(summary["state"], "version")
        self.assertEqual(summary["version"], "24.10.17")
        self.assertEqual(summary["line"], "LTS24")

    def test_one_unresolved_node_blocks_a_cluster_version(self) -> None:
        summary = self.check.summarize(
            [
                self.record("a", "version", "24.10.19", "LTS24"),
                self.record("b", "unknown"),
            ]
        )

        self.assertEqual(summary["state"], "unknown")

    def test_incomplete_beats_not_applicable(self) -> None:
        summary = self.check.summarize(
            [self.record("a", "not_applicable"), self.record("b", "incomplete")]
        )

        self.assertEqual(summary["state"], "incomplete")

    def test_a_nic_mode_node_keeps_the_cluster_out_of_not_applicable(self) -> None:
        nic = self.record("a", "not_running")
        nic["mode"] = "nic"
        absent = self.record("b", "not_applicable")
        absent["mode"] = "unknown"
        absent["scanComplete"] = True

        summary = self.check.summarize([nic, absent])

        self.assertEqual(summary["state"], "not_running")
        self.assertEqual(summary["mode"], "nic")

    def test_a_dpu_node_outranks_a_nic_node_for_the_cluster_mode(self) -> None:
        nic = self.record("a", "not_running")
        nic["mode"] = "nic"
        dpu = self.record("b", "unknown")
        dpu["mode"] = "dpu"

        summary = self.check.summarize([nic, dpu])

        self.assertEqual(summary["mode"], "dpu")
        self.assertEqual(summary["state"], "unknown")

    def test_no_records_is_incomplete(self) -> None:
        self.assertEqual(self.check.summarize([])["state"], "incomplete")


def _write_severity_matrix() -> None:
    spec = importlib.util.spec_from_file_location("virtio_net_check", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SEVERITY_MATRIX.parent.mkdir(parents=True, exist_ok=True)
    signatures = severity_signatures(module)
    SEVERITY_MATRIX.write_text(json.dumps(signatures, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(signatures)} cases to {SEVERITY_MATRIX}")


if __name__ == "__main__":
    if "--write-matrix" in sys.argv:
        _write_severity_matrix()
    else:
        unittest.main()
