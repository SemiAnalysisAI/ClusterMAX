#!/usr/bin/env python3
"""Synthetic tests for the Tier A/B plane-evidence NIC topology check.

Covers the parsers (mlxconfig / mlxlink / lldp / ibnetdiscover / port attrs),
the tri-state evidence assembly, the bounded local collector, and the k8s
@@PLANE@@ block parser. For the public audit contract,
every derived value must be ok / not-determined-with-reason, never a crash.
All parser inputs below are hand-built test data, not collected tool output.
"""

from __future__ import annotations

import sys
import importlib.util
import subprocess
import unittest
from pathlib import Path

SCRIPT_DIR = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit"
)
from typing import Any


CHECK_PATH = SCRIPT_DIR / "checks" / "fabric" / "nic-topology-check.py"


spec = importlib.util.spec_from_file_location("plane_evidence_check_under_test", CHECK_PATH)
nic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nic)


def completed(command: list[str], *, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


MLXCONFIG_OK = """
Configurations:                              Next Boot
         LINK_TYPE_P1                        IB(1)
         SRIOV_EN                            True(1)
         NUM_OF_VFS                          0
         SPLIT_MODE                          SPLIT_2X(1)
         KEEP_ETH_LINK_UP_P1                 True(1)
"""

MLXLINK_OK = """
State                           : Active
Physical state                  : LinkUp
Speed                           : NDR
Width                           : 4x

Identifier                      : OSFP
Vendor Name                     : NVIDIA
Vendor Part Number              : TEST-PART-001
Vendor Serial Number            : TEST-SERIAL-001
"""

LLDP_OK = """Chassis ID TLV
\tMAC: 02:00:00:00:00:01
Port ID TLV
\tIfname: Ethernet1/1/1
Port Description TLV
\tsynthetic switch port
System Name TLV
\tsynthetic-switch-a
"""

IBNETDISCOVER_P = """CA     1  1 0x00000000000000a1 4x XDR - SW     2 1 0x00000000000000b1 ( 'synthetic-worker-a mlx5_ib0' - 'synthetic-switch-a' )
SW     2 1 0x00000000000000b1 4x XDR - CA     1  1 0x00000000000000a1 ( 'synthetic-switch-a' - 'synthetic-worker-a mlx5_ib0' )
SW     2 2 0x00000000000000b1 4x XDR - SW     3 1 0x00000000000000b2 ( 'synthetic-switch-a' - 'synthetic-switch-b' )
"""


class PortAttrsTests(unittest.TestCase):
    def test_parses_rate_width_speed(self) -> None:
        self.assertEqual(
            nic.parse_port_attrs("800 Gb/sec (4X XDR)"),
            {"rate_gbps": 800, "width": "4X", "speed": "XDR"},
        )

    def test_parses_rate_without_parenthetical(self) -> None:
        self.assertEqual(nic.parse_port_attrs("100 Gb/sec"), {"rate_gbps": 100})

    def test_unparseable_keeps_raw(self) -> None:
        self.assertEqual(nic.parse_port_attrs("garbage"), {"raw": "garbage"})
        self.assertEqual(nic.parse_port_attrs(""), {"raw": ""})


class ParserTests(unittest.TestCase):
    def test_hostname_prefix_does_not_match_another_worker(self) -> None:
        text = IBNETDISCOVER_P.replace("synthetic-worker-a", "synthetic-worker-a0")
        self.assertEqual(nic.parse_ibnetdiscover(text, "", "synthetic-worker-a")["matched"], [])

    def test_guid_match_takes_precedence_over_hostname_matches(self) -> None:
        other = IBNETDISCOVER_P.replace("0x00000000000000a1", "0x00000000000000c1")
        summary = nic.parse_ibnetdiscover(IBNETDISCOVER_P + other, "0000:0000:0000:00a1", "synthetic-worker-a")
        self.assertTrue(summary["matched"])
        self.assertTrue(all("0x00000000000000c1" not in line for line in summary["matched"]))
    def test_mlxconfig_keeps_plane_and_sriov_keys_only(self) -> None:
        fields = nic.parse_mlxconfig(MLXCONFIG_OK)
        self.assertEqual(fields["LINK_TYPE_P1"], "IB(1)")
        self.assertEqual(fields["SPLIT_MODE"], "SPLIT_2X(1)")
        self.assertEqual(fields["SRIOV_EN"], "True(1)")
        self.assertEqual(fields["NUM_OF_VFS"], "0")
        self.assertNotIn("KEEP_ETH_LINK_UP_P1", fields)

    def test_mlxlink_keeps_identity_keys(self) -> None:
        fields = nic.parse_mlxlink(MLXLINK_OK)
        self.assertEqual(fields["Speed"], "NDR")
        self.assertEqual(fields["Vendor Serial Number"], "TEST-SERIAL-001")
        self.assertEqual(fields["Identifier"], "OSFP")
        self.assertNotIn("Physical state", fields)

    def test_lldp_keeps_neighbor_tlvs(self) -> None:
        fields = nic.parse_lldp(LLDP_OK)
        self.assertEqual(fields["System Name TLV"], "synthetic-switch-a")
        self.assertEqual(fields["Port ID TLV"], "Ifname: Ethernet1/1/1")
        self.assertNotIn("Chassis ID TLV", fields)

    def test_ibnetdiscover_counts_switches_and_matches_guid(self) -> None:
        summary = nic.parse_ibnetdiscover(IBNETDISCOVER_P, "0000:0000:0000:00a1", "other-host")
        self.assertEqual(summary["switch_count"], 2)
        self.assertEqual(len(summary["matched"]), 2)

    def test_ibnetdiscover_falls_back_to_hostname(self) -> None:
        summary = nic.parse_ibnetdiscover(IBNETDISCOVER_P, "", "synthetic-worker-a")
        self.assertEqual(len(summary["matched"]), 2)


class RunEvidenceToolTests(unittest.TestCase):
    def test_missing_tool(self) -> None:
        def runner(command: Any, **_: Any):
            raise FileNotFoundError(command[0])

        self.assertEqual(nic.run_evidence_tool(["mlxconfig"], runner=runner), ("", "tool not installed"))

    def test_timeout(self) -> None:
        def runner(command: Any, **_: Any):
            raise subprocess.TimeoutExpired(cmd=command, timeout=10)

        self.assertEqual(nic.run_evidence_tool(["mlxlink"], runner=runner), ("", "timeout"))

    def test_permission_denial_is_classified(self) -> None:
        def runner(command: Any, **_: Any):
            return completed(command, returncode=1, stderr="-E- Failed to open device: /dev/mst/mt4131_pciconf0\n")

        _, reason = nic.run_evidence_tool(["mlxconfig"], runner=runner)
        assert reason is not None
        self.assertTrue(reason.startswith("insufficient privilege"))

    def test_generic_failure_keeps_exit_and_first_line(self) -> None:
        def runner(command: Any, **_: Any):
            return completed(command, returncode=2, stderr="ibwarn: discover failed\n")

        self.assertEqual(
            nic.run_evidence_tool(["ibnetdiscover"], runner=runner),
            ("", "exit 2: ibwarn: discover failed"),
        )

    def test_success_returns_stdout(self) -> None:
        def runner(command: Any, **_: Any):
            return completed(command, stdout=MLXCONFIG_OK)

        self.assertEqual(nic.run_evidence_tool(["mlxconfig"], runner=runner), (MLXCONFIG_OK, None))


class EvidenceAssemblyTests(unittest.TestCase):
    def test_split_key_yields_ok_presentation(self) -> None:
        record = nic.evidence_from_raw(
            "mlx5_ib0", "InfiniBand", "800 Gb/sec (4X XDR)",
            {"mlxconfig": (MLXCONFIG_OK, None), "mlxlink": (MLXLINK_OK, None), "ibnetdiscover": (IBNETDISCOVER_P, None)},
            node_guid="0000:0000:0000:00a1", host="synthetic-worker-a",
        )
        self.assertEqual(record["presentation"]["status"], "ok")
        self.assertEqual(record["presentation"]["fields"], {"SPLIT_MODE": "SPLIT_2X(1)"})
        self.assertEqual(record["port"], {"rate_gbps": 800, "width": "4X", "speed": "XDR"})
        self.assertEqual(record["neighbor"]["method"], "ibnetdiscover")
        self.assertEqual(record["neighbor"]["switch_count"], 2)

    def test_denied_mlxconfig_chains_reason_into_presentation(self) -> None:
        record = nic.evidence_from_raw(
            "mlx5_ib1", "InfiniBand", "800 Gb/sec (4X XDR)",
            {
                "mlxconfig": ("", "insufficient privilege (-E- Failed to open device)"),
                "mlxlink": ("", "tool not installed"),
                "ibnetdiscover": ("", "insufficient privilege (umad)"),
            },
        )
        self.assertEqual(record["presentation"]["status"], "not determined")
        self.assertIn("insufficient privilege", record["presentation"]["reason"])
        self.assertIn("Tier A", record["presentation"]["reason"])
        self.assertEqual(record["neighbor"]["status"], "not determined")

    def test_visible_mlxconfig_without_plane_key_stays_not_determined(self) -> None:
        record = nic.evidence_from_raw(
            "mlx5_ib2", "InfiniBand", "800 Gb/sec (4X XDR)",
            {"mlxconfig": ("LINK_TYPE_P1  IB(1)\n", None), "mlxlink": ("", "tool not installed"), "ibnetdiscover": ("", "timeout")},
        )
        self.assertEqual(record["presentation"]["status"], "not determined")
        self.assertIn("no split/plane key", record["presentation"]["reason"])

    def test_ethernet_uses_lldp_neighbor(self) -> None:
        record = nic.evidence_from_raw(
            "mlx5_rail0", "Ethernet", "400 Gb/sec (4X NDR)",
            {"mlxconfig": ("", "tool not installed"), "mlxlink": ("", "tool not installed"), "lldp": (LLDP_OK, None)},
        )
        self.assertEqual(record["neighbor"]["method"], "lldp")
        self.assertEqual(record["neighbor"]["fields"]["System Name TLV"], "synthetic-switch-a")

    def test_unattempted_tools_are_not_determined(self) -> None:
        record = nic.evidence_from_raw("mlx5_ib3", "InfiniBand", "", {})
        self.assertEqual(record["mlxconfig"], {"status": "not determined", "reason": "not attempted"})
        self.assertEqual(record["neighbor"]["reason"], "not attempted")
        self.assertEqual(record["presentation"]["status"], "not determined")


class CollectPlaneEvidenceTests(unittest.TestCase):
    NICS = [
        {"name": "mlx5_ib0", "role": "fabric", "layer": "InfiniBand"},
        {"name": "mlx5_ib1", "role": "fabric", "layer": "InfiniBand"},
        {"name": "mlx5_an0", "role": "frontend", "layer": "Ethernet"},
        {"name": "mlx5_st0", "role": "storage", "layer": "InfiniBand"},
    ]

    def test_only_fabric_hcas_checked_and_absent_tools_recorded(self) -> None:
        calls: list[list[str]] = []

        def runner(command: Any, **_: Any):
            calls.append(command)
            raise FileNotFoundError(command[0])

        out = nic.collect_plane_evidence(self.NICS, runner=runner, sysfs_root="/nonexistent")

        self.assertEqual([e["ibdev"] for e in out], ["mlx5_ib0", "mlx5_ib1"])
        for record in out:
            self.assertEqual(record["mlxconfig"], {"status": "not determined", "reason": "tool not installed"})
            self.assertEqual(record["presentation"]["status"], "not determined")
        checked = {c[0] for c in calls}
        self.assertEqual(checked, {"mlxconfig", "mlxlink", "ibnetdiscover"})

    def test_budget_exhaustion_marks_remaining_hcas(self) -> None:
        clock = iter([0.0, 1.0, 100.0])
        last = [0.0]

        def time_fn() -> float:
            for value in clock:
                last[0] = value
                return value
            return last[0]

        def runner(command: Any, **_: Any):
            raise FileNotFoundError(command[0])

        out = nic.collect_plane_evidence(
            self.NICS, runner=runner, sysfs_root="/nonexistent", budget_s=45.0, time_fn=time_fn
        )

        self.assertEqual(out[0]["mlxconfig"]["reason"], "tool not installed")
        self.assertEqual(out[1]["mlxconfig"]["reason"], "budget exhausted")
        self.assertEqual(out[1]["presentation"]["status"], "not determined")


class K8sPlaneBlockTests(unittest.TestCase):
    SAMPLE = "\n".join(
        [
            "@@PLANEGUID@@\tmlx5_ib0\t0000:0000:0000:00a1",
            "@@PLANE@@ mlx5_ib0 mlxconfig BEGIN",
            "         SPLIT_MODE                          SPLIT_2X(1)",
            "@@PLANE@@ mlx5_ib0 mlxconfig END 0",
            "@@PLANE@@ mlx5_ib0 mlxlink MISSING",
            "@@PLANE@@ mlx5_ib0 ibnetdiscover BEGIN",
            "ibwarn: umad_init failed",
            "@@PLANE@@ mlx5_ib0 ibnetdiscover END 1",
            "@@PLANE@@ mlx5_ib1 mlxconfig SKIPPED",
            "@@PLANE@@ mlx5_rail0 lldp NONETDEV",
            "@@PLANE@@ mlx5_ib2 mlxlink BEGIN",
            "@@PLANE@@ mlx5_ib2 mlxlink END 124",
        ]
    )

    def test_blocks_parse_to_evidence_raws(self) -> None:
        raws, guids = nic._parse_k8s_plane(self.SAMPLE)

        self.assertEqual(guids, {"mlx5_ib0": "0000:0000:0000:00a1"})
        raw, reason = raws["mlx5_ib0"]["mlxconfig"]
        self.assertIsNone(reason)
        self.assertIn("SPLIT_MODE", raw)
        self.assertEqual(raws["mlx5_ib0"]["mlxlink"], ("", "tool not installed"))
        # umad denial goes through the same _failure_reason classifier as local runs.
        self.assertTrue(raws["mlx5_ib0"]["ibnetdiscover"][1].startswith("insufficient privilege"))
        self.assertEqual(raws["mlx5_ib1"]["mlxconfig"], ("", "skipped (no timeout binary in pod)"))
        self.assertEqual(raws["mlx5_rail0"]["lldp"], ("", "no netdev exposed for this HCA"))
        # timeout(1) kill status 124 maps to the stable "timeout" reason.
        self.assertEqual(raws["mlx5_ib2"]["mlxlink"], ("", "timeout"))

    def test_rate_raws_from_hca_lines(self) -> None:
        text = "@@HCA@@\tmlx5_ib0\t800 Gb/sec (4X XDR)\tInfiniBand\t4: ACTIVE\n"
        self.assertEqual(nic._k8s_rate_raws(text), {"mlx5_ib0": "800 Gb/sec (4X XDR)"})


class PayloadTests(unittest.TestCase):
    def test_plane_evidence_by_host_keeps_only_hosts_with_evidence(self) -> None:
        records = [
            {"host": "worker-0", "nics": [], "plane_evidence": [{"ibdev": "mlx5_ib0"}]},
            {"host": "worker-1", "nics": []},
            {"host": "", "plane_evidence": [{"ibdev": "mlx5_ib0"}]},
        ]
        self.assertEqual(
            nic.plane_evidence_by_host(records),
            {"worker-0": [{"ibdev": "mlx5_ib0"}]},
        )

    def test_k8s_record_gains_plane_evidence_for_fabric_nics(self) -> None:
        collector = "\n".join(
            [
                "@@TOPO_BEGIN@@",
                "\tGPU0\tNIC0\tCPU Affinity",
                "GPU0\t X \tPIX\t0-55",
                "NIC0\tPIX\t X ",
                "",
                "NIC Legend:",
                "",
                "  NIC0: mlx5_ib0",
                "@@TOPO_END@@",
                "@@HCA@@\tmlx5_ib0\t800 Gb/sec (4X XDR)\tInfiniBand\t4: ACTIVE",
                "@@PLANEGUID@@\tmlx5_ib0\t0000:0000:0000:00a1",
                "@@PLANE@@ mlx5_ib0 mlxconfig MISSING",
                "@@PLANE@@ mlx5_ib0 mlxlink MISSING",
                "@@PLANE@@ mlx5_ib0 ibnetdiscover MISSING",
            ]
        ) + "\n"

        def runner(command: Any, **kwargs: Any):
            args = command[1:]
            if args[:2] == ["get", "pods"]:
                return completed(command, stdout='{"items": [{"metadata": {"name": "nvidia-driver-abc"}, "status": {"phase": "Running"}}]}')
            if args[0] == "exec":
                return completed(command, stdout=collector)
            raise AssertionError(f"unexpected kubectl call: {args}")

        record, error = nic.run_k8s_node_check("gpu-operator", "node-1", runner=runner)

        self.assertIsNone(error)
        assert record is not None
        evidence = record["plane_evidence"]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["ibdev"], "mlx5_ib0")
        self.assertEqual(evidence[0]["port"], {"rate_gbps": 800, "width": "4X", "speed": "XDR"})
        self.assertEqual(evidence[0]["mlxconfig"], {"status": "not determined", "reason": "tool not installed"})
        self.assertEqual(evidence[0]["presentation"]["status"], "not determined")


if __name__ == "__main__":
    unittest.main()
