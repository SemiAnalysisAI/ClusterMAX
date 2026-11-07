"""The BlueField SNAP-4 container read and its per-train grade.

SNAP-4 runs on the DPU Arm cores, so the virtio-net check reads it on the same
DPU path. These tests pin the per-host states, the cluster rollup, and the
security verdict, including the per-train rule from NVIDIA bulletin 5744.

Sources: cmax/scripts/1-audit/checks/fabric/virtio-net-check.py (the read and
rollup) and cmax/scripts/1-audit/security_version_audit.py (the grade).
"""

from __future__ import annotations

import json
import os
import shutil
import unittest
from pathlib import Path

from tests.audit.test_security_version_audit import security
from tests.audit.test_virtio_net_check import (
    BLUEFIELD3_LSPCI,
    DPU_MODE_MLXCONFIG,
    NIC_MODE_MLXCONFIG,
    NO_BLUEFIELD_LSPCI,
    VIRTNET_VERSION_JSON,
    CheckHarness,
    load_check_module,
)

minimums = security.minimum_versions

SNAP_IMAGE_ID = "sha256:5d3f0b2c9a"
RUNNING_PS = json.dumps(
    {
        "containers": [
            {
                "id": "c1",
                "metadata": {"name": "doca-snap"},
                "image": {"image": SNAP_IMAGE_ID},
                "imageRef": SNAP_IMAGE_ID,
                "state": "CONTAINER_RUNNING",
            },
            {
                "id": "c2",
                "metadata": {"name": "doca-telemetry"},
                "image": {"image": "sha256:other"},
                "imageRef": "sha256:other",
            },
        ]
    },
    indent=2,
)
IMAGES = json.dumps(
    {
        "images": [
            {"id": SNAP_IMAGE_ID, "repoTags": ["nvcr.io/nvidia/doca/doca_snap:4.9.0-doca3.1.0"]},
            {"id": "sha256:other", "repoTags": ["nvcr.io/nvidia/doca/doca_telemetry:1.21.4-doca3.1.0"]},
        ]
    },
    indent=2,
)


def listing(*, manifests: str = "", ps: str | None = RUNNING_PS, images: str = IMAGES) -> str:
    """What SNAP4_DPU_SCRIPT prints on a DPU."""
    lines = ["@@SNAP4-MANIFESTS@@", manifests]
    if ps is None:
        lines += ["@@SNAP4-NO-CRICTL@@"]
    else:
        lines += ["@@SNAP4-PS@@", ps, "@@SNAP4-IMAGES@@", images, "@@SNAP4-END@@"]
    return "\n".join(lines) + "\n"


class Snap4ListingParseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.check = load_check_module()

    def test_running_container_version_comes_from_the_image_tag(self) -> None:
        parsed = self.check.parse_snap4_listing(listing())
        self.assertTrue(parsed["reached"])
        self.assertTrue(parsed["listed"])
        self.assertEqual(parsed["running"], ["4.9.0"])

    def test_container_named_by_its_image_needs_no_images_listing(self) -> None:
        ps = json.dumps(
            {"containers": [{"metadata": {"name": "x"}, "image": {"image": "nvcr.io/nvidia/doca/doca_snap:4.5.5-doca2.9.1"}}]}
        )
        parsed = self.check.parse_snap4_listing(listing(ps=ps, images="{}"))
        self.assertEqual(parsed["running"], ["4.5.5"])

    def test_manifest_version_is_read_when_nothing_runs(self) -> None:
        parsed = self.check.parse_snap4_listing(
            listing(
                manifests="    image: nvcr.io/nvidia/doca/doca_snap:4.9.1-doca3.2.0",
                ps=json.dumps({"containers": []}),
            )
        )
        self.assertEqual(parsed["running"], [])
        self.assertEqual(parsed["configured"], ["4.9.1"])

    def test_a_snap_container_without_a_tag_is_flagged(self) -> None:
        ps = json.dumps({"containers": [{"metadata": {"name": "snap"}, "image": {"image": "sha256:none"}}]})
        parsed = self.check.parse_snap4_listing(listing(ps=ps, images="{}"))
        self.assertEqual(parsed["running"], [])
        self.assertTrue(parsed["runningWithoutVersion"])

    def test_no_crictl_and_no_output_are_not_a_listing(self) -> None:
        self.assertFalse(self.check.parse_snap4_listing(listing(ps=None))["listed"])
        empty = self.check.parse_snap4_listing("")
        self.assertFalse(empty["reached"])
        self.assertFalse(empty["listed"])

    def test_failed_ps_is_not_a_listing(self) -> None:
        text = "@@SNAP4-MANIFESTS@@\n@@SNAP4-PS@@\n@@SNAP4-PS-FAILED@@\n"
        parsed = self.check.parse_snap4_listing(text)
        self.assertTrue(parsed["reached"])
        self.assertFalse(parsed["listed"])


class Snap4HostReadTests(CheckHarness):
    def bluefield(self, mode: str = DPU_MODE_MLXCONFIG) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", mode)
        (self.root / "dev" / "rshim0").touch()

    def ssh_prints(self, text: str, *, returncode: int = 0) -> None:
        data = self.tmp / "ssh-snap4.stdout"
        data.write_text(text)
        # virtnet over SSH fails; the SNAP-4 script (the argument carrying
        # crictl) prints the canned DPU listing.
        self.stub(
            "ssh",
            f"""
for arg in "$@"; do
  case "$arg" in
    *crictl*) /bin/cat "{data}"; exit {returncode} ;;
  esac
done
exit 1
""",
        )

    def snap_calls(self) -> str:
        """The SSH call that carried the SNAP-4 script, or "" if none did."""
        path = self.calls / "ssh.calls"
        text = path.read_text() if path.exists() else ""
        return text if "crictl" in text else ""

    def test_running_container_is_read_over_rshim(self) -> None:
        self.bluefield()
        self.ssh_prints(listing())

        record = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")

        snap = record["snap4"]
        self.assertEqual(snap["state"], "version")
        self.assertEqual(snap["versions"], ["4.9.0"])
        self.assertEqual(snap["source"], "rshim-ssh/crictl")
        self.assertTrue(record["rshimHostAccess"]["dpuReachedFromHost"])
        argv = self.snap_calls()
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("sudo -n crictl", argv)
        # The read lists only. It never pulls, runs, stops, or execs.
        for verb in ("crictl pull", "crictl run", "crictl stop", "crictl exec", "crictl rm"):
            self.assertNotIn(verb, argv)

    def test_collector_summary_carries_the_rollup(self) -> None:
        self.bluefield()
        self.ssh_prints(listing())

        summary = self.run_check("--summary", CLUSTERMAX_DPU_SSH_DISABLE="")

        snap = json.loads(summary["snap4Json"])
        self.assertEqual(snap["state"], "version")
        self.assertEqual(snap["observed"][0]["version"], "4.9.0")

    def test_reached_dpu_without_snap_is_not_installed(self) -> None:
        self.bluefield()
        self.ssh_prints(listing(ps=json.dumps({"containers": []})))

        snap = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")["snap4"]

        self.assertEqual(snap["state"], "not_installed")
        self.assertEqual(snap["versions"], [])

    def test_unreachable_dpu_is_unknown_and_asks_for_attestation(self) -> None:
        self.bluefield()
        self.stub("ssh", 'echo "Permission denied (publickey)." >&2\nexit 255')

        snap = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")["snap4"]

        self.assertEqual(snap["state"], "unknown")
        self.assertIn("attest", snap["reason"])

    def test_disabled_ssh_is_unknown_without_a_call(self) -> None:
        self.bluefield()
        self.ssh_prints(listing())

        snap = self.host_record()["snap4"]

        self.assertEqual(snap["state"], "unknown")
        self.assertEqual(self.snap_calls(), "")

    def test_nic_mode_is_not_running_and_never_dials_the_dpu(self) -> None:
        self.bluefield(NIC_MODE_MLXCONFIG)
        self.ssh_prints(listing())

        snap = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")["snap4"]

        self.assertEqual(snap["state"], "not_running")
        self.assertEqual(self.snap_calls(), "")

    def test_no_bluefield_is_not_applicable(self) -> None:
        self.stub_output("lspci", NO_BLUEFIELD_LSPCI)
        self.ssh_prints(listing())

        snap = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")["snap4"]

        self.assertEqual(snap["state"], "not_applicable")
        self.assertEqual(self.snap_calls(), "")

    def test_on_the_dpu_the_read_runs_locally(self) -> None:
        self.stub_output("lspci", BLUEFIELD3_LSPCI)
        self.stub_output("mlxconfig", DPU_MODE_MLXCONFIG)
        payload = self.tmp / "virtnet-version.json"
        payload.write_text(VIRTNET_VERSION_JSON)
        self.stub("virtnet", f'case "$1" in version) /bin/cat "{payload}" ;; *) exit 1 ;; esac')
        for tool in ("sh", "grep"):
            os.symlink(shutil.which(tool), self.bin / tool)
        (self.tmp / "ps.json").write_text(RUNNING_PS)
        (self.tmp / "images.json").write_text(IMAGES)
        self.stub(
            "crictl",
            f'case "$1" in ps) /bin/cat "{self.tmp}/ps.json" ;; images) /bin/cat "{self.tmp}/images.json" ;; esac',
        )
        self.ssh_prints(listing())

        snap = self.host_record(CLUSTERMAX_DPU_SSH_DISABLE="")["snap4"]

        self.assertEqual(snap["versions"], ["4.9.0"])
        self.assertEqual(snap["source"], "local/crictl")
        self.assertEqual(self.snap_calls(), "")


class Snap4SummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.check = load_check_module()

    def record(self, host: str, state: str, versions=(), source="rshim-ssh/crictl", reason="r") -> dict:
        return {
            "host": host,
            "state": "version",
            "snap4": {"state": state, "versions": list(versions), "source": source, "reason": reason},
        }

    def test_every_reading_survives_the_rollup(self) -> None:
        summary = self.check.summarize_snap4(
            [
                self.record("a", "version", ["4.9.1"]),
                self.record("b", "version", ["4.7.0"]),
                self.record("c", "unknown", reason="DPU not reached"),
            ]
        )
        self.assertEqual(summary["state"], "unknown")
        self.assertEqual([entry["version"] for entry in summary["observed"]], ["4.7.0", "4.9.1"])
        self.assertEqual(summary["hostsChecked"], 3)

    def test_nic_peer_outranks_a_read_host(self) -> None:
        summary = self.check.summarize_snap4(
            [self.record("a", "version", ["4.9.1"]), self.record("b", "not_running")]
        )
        self.assertEqual(summary["state"], "not_running")

    def test_a_coverage_gap_withdraws_a_clean_rollup(self) -> None:
        summary = {"snap4": {"state": "not_installed", "reason": "", "observed": []}}
        gapped = self.check.apply_coverage_gap(dict(summary), ["node-7: srun failed"])
        self.assertEqual(gapped["snap4"]["state"], "incomplete")


SNAP4_BLOCK = {
    "kind": "releaseLines",
    "lines": {"4.5": {"fixed": "4.5.5"}, "4.9": {"fixed": "4.9.1"}},
    "advisory": "https://nvidia.custhelp.com/app/answers/detail/a_id/5744",
    "cves": ["CVE-2025-33215", "CVE-2025-33216"],
    "source": {"aId": 5744, "feed": "nvidia-csaf"},
}


class Snap4VerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        table = json.loads(minimums.minimums_path().read_text())
        table["components"]["snap4Container"] = SNAP4_BLOCK
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        path = Path(holder.name) / "minimums.json"
        path.write_text(json.dumps(table))
        previous = os.environ.get(minimums.MINIMUMS_ENV)
        os.environ[minimums.MINIMUMS_ENV] = str(path)
        minimums._CACHE = None

        def restore() -> None:
            if previous is None:
                os.environ.pop(minimums.MINIMUMS_ENV, None)
            else:
                os.environ[minimums.MINIMUMS_ENV] = previous
            minimums._CACHE = None

        self.addCleanup(restore)

    def grade(self, version: str) -> tuple[str, str]:
        verdict, _ = security.snap4_verdict(version)
        return verdict.status, verdict.minimum

    def test_each_train_is_held_to_its_own_fix(self) -> None:
        self.assertEqual(self.grade("4.9.0"), ("fail", "4.9.1"))
        self.assertEqual(self.grade("4.9.1"), ("pass", "4.9.1"))
        self.assertEqual(self.grade("4.5.4"), ("fail", "4.5.5"))
        self.assertEqual(self.grade("4.5.5"), ("pass", "4.5.5"))

    def test_a_train_without_a_fix_moves_to_the_next_fix_above(self) -> None:
        self.assertEqual(self.grade("4.7.2"), ("fail", "4.9.1"))
        self.assertEqual(self.grade("4.3.0"), ("fail", "4.5.5"))

    def test_a_train_newer_than_every_fix_passes(self) -> None:
        self.assertEqual(self.grade("4.12.0"), ("pass", "4.9.1"))

    def result(self, state: str, *observed: tuple[str, str], reason: str = "") -> dict:
        return security.snap4_container_result(
            {
                "state": state,
                "reason": reason,
                "observed": [{"version": v, "host": h, "source": "rshim-ssh/crictl"} for v, h in observed],
            }
        )

    def test_the_worst_reading_decides(self) -> None:
        result = self.result("version", ("4.12.0", "a"), ("4.9.0", "b"), ("4.5.5", "c"))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["version"], "4.9.0")
        self.assertEqual(result["minimum"], "4.9.1")
        self.assertEqual(result["host"], "b")

    def test_a_fail_stands_beside_an_unread_peer(self) -> None:
        result = self.result("unknown", ("4.7.0", "a"), reason="DPU not reached")
        self.assertEqual(result["status"], "fail")
        self.assertIn("Not every DPU was read", result["detail"])

    def test_passing_readings_do_not_clear_unread_peers(self) -> None:
        result = self.result("unknown", ("4.9.1", "a"), reason="DPU not reached")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("not every DPU was read", result["detail"])

    def test_passing_readings_with_full_coverage_pass(self) -> None:
        result = self.result("not_running", ("4.9.1", "a"))
        self.assertEqual(result["status"], "pass")

    def test_nothing_to_read_is_not_applicable(self) -> None:
        for state in ("not_applicable", "not_installed", "not_running"):
            with self.subTest(state=state):
                self.assertEqual(self.result(state)["status"], "not_applicable")

    def test_unread_dpu_mode_is_unknown(self) -> None:
        result = self.result("unknown", reason="the DPU did not answer")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("did not answer", result["detail"])

    def test_no_rollup_is_unknown(self) -> None:
        self.assertEqual(security.snap4_container_result(None)["status"], "unknown")


class Snap4WithoutTableEntryTests(unittest.TestCase):
    """The shipped table predates snap4Container until the refresh publishes it."""

    def test_reading_without_a_minimum_is_unknown_and_absence_still_applies(self) -> None:
        table = json.loads(minimums.minimums_path().read_text())
        if "snap4Container" in table.get("components", {}):
            self.skipTest("the shipped table already lists snap4Container")
        read = security.snap4_container_result(
            {"state": "version", "observed": [{"version": "4.9.1", "host": "a", "source": "x"}]}
        )
        self.assertEqual(read["status"], "unknown")
        absent = security.snap4_container_result({"state": "not_applicable", "observed": []})
        self.assertEqual(absent["status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
