"""Plane parsers, tool failures, and cross-host fabric evidence."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any

import pytest

SCRIPT_DIR = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit"
)
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
    def test_port_attributes(self) -> None:
        for raw, expected in [
            ("800 Gb/sec (4X XDR)", {"rate_gbps": 800, "width": "4X", "speed": "XDR"}),
            ("100 Gb/sec", {"rate_gbps": 100}),
            ("garbage", {"raw": "garbage"}),
            ("", {"raw": ""}),
        ]:
            with self.subTest(raw=raw):
                self.assertEqual(nic.parse_port_attrs(raw), expected)


class ParserTests(unittest.TestCase):
    def test_ibnetdiscover_matches_guid_or_exact_hostname(self) -> None:
        for guid, host, text, matched in [
            ("0000:0000:0000:00a1", "other-host", IBNETDISCOVER_P, 2),
            ("", "synthetic-worker-a", IBNETDISCOVER_P, 2),
            ("", "synthetic-worker-a",
             IBNETDISCOVER_P.replace("synthetic-worker-a", "synthetic-worker-a0"), 0),
        ]:
            with self.subTest(guid=guid, host=host, matched=matched):
                summary = nic.parse_ibnetdiscover(text, guid, host)
                self.assertEqual(len(summary["matched"]), matched)
                if matched:
                    self.assertEqual(summary["switch_count"], 2)

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

class RunEvidenceToolTests(unittest.TestCase):
    def test_tool_outcomes(self) -> None:
        for tool, outcome, expected in [
            ("mlxconfig", FileNotFoundError("mlxconfig"), ("", "tool not installed")),
            ("mlxlink", subprocess.TimeoutExpired("mlxlink", 10), ("", "timeout")),
            ("ibnetdiscover", completed([], returncode=2, stderr="ibwarn: discover failed\n"),
             ("", "exit 2: ibwarn: discover failed")),
            ("mlxconfig", completed([], stdout=MLXCONFIG_OK), (MLXCONFIG_OK, None)),
            ("mlxconfig", completed([], returncode=1,
             stderr="-E- Failed to open device: /dev/mst/mt4131_pciconf0\n"), None),
        ]:
            with self.subTest(tool=tool, outcome=outcome):
                def runner(command: Any, **_: Any):
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                result = nic.run_evidence_tool([tool], runner=runner)
                if expected is None:
                    self.assertIsNotNone(result[1])
                    self.assertTrue(result[1].startswith("insufficient privilege"))
                else:
                    self.assertEqual(result, expected)


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


class ToolDeviceTests(unittest.TestCase):
    def test_renamed_ibdev_resolves_to_pci_function(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pci = Path(tmp) / "devices" / "0000:aa:00.0"
            pci.mkdir(parents=True)
            (Path(tmp) / "rail0").mkdir()
            os.symlink(pci, Path(tmp) / "rail0" / "device")
            self.assertEqual(nic.tool_device(tmp, "rail0"), "0000:aa:00.0")
            # No sysfs device link: keep the ibdev name.
            self.assertEqual(nic.tool_device(tmp, "mlx5_0"), "mlx5_0")

    def test_local_collector_passes_pci_function_to_mlx_tools(self) -> None:
        import os
        import tempfile

        calls: list[list[str]] = []

        def runner(command: Any, **_: Any):
            calls.append(command)
            raise FileNotFoundError(command[0])

        with tempfile.TemporaryDirectory() as tmp:
            pci = Path(tmp) / "devices" / "0000:aa:00.0"
            pci.mkdir(parents=True)
            (Path(tmp) / "rail0").mkdir()
            os.symlink(pci, Path(tmp) / "rail0" / "device")
            nic.collect_plane_evidence(
                [{"name": "rail0", "role": "fabric", "layer": "InfiniBand"}],
                runner=runner,
                sysfs_root=tmp,
            )
        by_tool = {c[0]: c for c in calls}
        self.assertEqual(by_tool["mlxconfig"][2], "0000:aa:00.0")
        self.assertEqual(by_tool["mlxlink"][2], "0000:aa:00.0")
        # ibnetdiscover takes the ibdev name.
        self.assertEqual(by_tool["ibnetdiscover"][2], "rail0")

    def test_mlxconfig_gets_the_longer_timeout(self) -> None:
        timeouts: dict[str, Any] = {}

        def runner(command: Any, **kwargs: Any):
            timeouts[command[0]] = kwargs.get("timeout")
            raise FileNotFoundError(command[0])

        nic.collect_plane_evidence(
            [{"name": "mlx5_0", "role": "fabric", "layer": "InfiniBand"}],
            runner=runner,
            sysfs_root="/nonexistent",
        )
        self.assertEqual(timeouts["mlxconfig"], nic.PLANE_MLXCONFIG_TIMEOUT_S)
        self.assertEqual(timeouts["mlxlink"], nic.PLANE_TOOL_TIMEOUT_S)
        # A full query can take several seconds without the MST driver.
        self.assertGreaterEqual(nic.PLANE_MLXCONFIG_TIMEOUT_S, 15)
        # Budget plus one HCA at its timeouts stays inside the Slurm bound.
        worst = nic.PLANE_BUDGET_S + nic.PLANE_MLXCONFIG_TIMEOUT_S + 2 * nic.PLANE_TOOL_TIMEOUT_S
        self.assertLess(worst, nic.SLURM_TIMEOUT_S)

    def test_mlxlink_fields_drop_color_codes(self) -> None:
        text = "State : \x1b[32mActive\x1b[0m\nSpeed : \x1b[32mIB-NDR\x1b[0m\n"
        self.assertEqual(nic.parse_mlxlink(text), {"State": "Active", "Speed": "IB-NDR"})

    def test_failure_reason_skips_mstflint_lockfile_warning(self) -> None:
        raws, _ = nic._parse_k8s_plane(
            "@@PLANE@@ rail0 mlxlink BEGIN\n"
            "Warrning: Failed to create lockfile: /tmp/mstflint_lockfiles/x (parallel access not supported)\n"
            "\n-E- Device is busy\n"
            "@@PLANE@@ rail0 mlxlink END 1"
        )
        self.assertEqual(raws["rail0"]["mlxlink"][1], "exit 1: -E- Device is busy")

    def test_failure_reason_skips_color_only_lines(self) -> None:
        text = "\x1b[31m\n\x1b[0m-E- Failed to open device: \"rail0\", No such file or directory"
        raws, _ = nic._parse_k8s_plane(
            "@@PLANE@@ rail0 mlxlink BEGIN\n" + text + "\n@@PLANE@@ rail0 mlxlink END 1"
        )
        reason = raws["rail0"]["mlxlink"][1]
        self.assertNotIn("\x1b", reason)
        self.assertIn("Failed to open device", reason)


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
        self.assertTrue(raws["mlx5_ib0"]["ibnetdiscover"][1].startswith("insufficient privilege"))
        self.assertEqual(raws["mlx5_ib1"]["mlxconfig"], ("", "skipped (no timeout binary in pod)"))
        self.assertEqual(raws["mlx5_rail0"]["lldp"], ("", "no netdev exposed for this HCA"))
        self.assertEqual(raws["mlx5_ib2"]["mlxlink"], ("", "timeout"))

    def test_rate_raws_from_hca_lines(self) -> None:
        text = "@@HCA@@\tmlx5_ib0\t800 Gb/sec (4X XDR)\tInfiniBand\t4: ACTIVE\n"
        self.assertEqual(nic._k8s_rate_raws(text), {"mlx5_ib0": "800 Gb/sec (4X XDR)"})


class PayloadTests(unittest.TestCase):
    def test_plane_evidence_by_host_keeps_only_hosts_with_evidence(self) -> None:
        records = [
            {"host": "worker-0", "nics": [{"name": "mlx5_ib0", "role": "fabric"}],
             "plane_evidence": [{"ibdev": "mlx5_ib0"}]},
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


def synthetic_evidence():
    return nic.evidence_from_raw(
        "synthetic_ib", "InfiniBand", "200 Gb/sec",
        {"mlxconfig": ("SPLIT_MODE SPLIT_2X(1)\n", None)},
    )

def synthetic_records(*, include_failed_evidence=True):
    records = [{
        "host": f"synthetic-{index}", "topo_collected": True, "nvlinkExposed": False,
        "nics": [{
            "name": "synthetic_ib", "role": "fabric" if index < 2 else "storage",
            "state": "ACTIVE" if index < 2 else "DOWN",
            "rate_gbps": 200 if index < 2 else 0, "layer": "InfiniBand",
        }],
        "plane_evidence": [synthetic_evidence()],
    } for index in range(3)]
    if not include_failed_evidence:
        records[-1].pop("plane_evidence")
    return records

@pytest.mark.parametrize("include_failed_evidence", [True, False])
def test_recovered_fabric_port_has_measured_or_explicitly_missing_evidence(
    monkeypatch, include_failed_evidence,
):
    records = synthetic_records(include_failed_evidence=include_failed_evidence)
    monkeypatch.setattr(nic, "slurm_records", lambda **kwargs: (records, []))
    payload = nic.build_check_payload(harness="slurm", env={})
    port, = payload["nic_topology"]["synthetic-2"]
    assert port["role"] == "fabric"
    evidence, = payload["nic_plane_evidence"]["synthetic-2"]
    assert evidence["ibdev"] == "synthetic_ib"
    if include_failed_evidence:
        assert evidence == synthetic_evidence()
        assert evidence["presentation"]["status"] == "ok"
    else:
        assert evidence["presentation"]["status"] == "not determined"
        assert "not collected before fabric role aggregation" in evidence["presentation"]["reason"]
        assert evidence["neighbor"]["status"] == "not determined"

def test_unpromoted_storage_candidate_is_not_published_as_fabric_evidence():
    records = synthetic_records()
    # One healthy peer does not meet the two-peer recovery threshold.
    records.pop(1)
    topology = nic.aggregate(records)
    assert topology["synthetic-2"][0]["role"] == "storage"
    assert "synthetic-2" not in nic.plane_evidence_by_host(records, topology)

def test_local_collector_retains_down_ib_candidates_but_not_active_storage():
    nics = CollectPlaneEvidenceTests.NICS + [
        {"name": "synthetic_down", "role": "storage", "layer": "InfiniBand", "state": "DOWN"},
    ]
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        raise FileNotFoundError(command[0])

    evidence = nic.collect_plane_evidence(nics, runner=runner, sysfs_root="/nonexistent")
    assert [entry["ibdev"] for entry in evidence] == ["mlx5_ib0", "mlx5_ib1", "synthetic_down"]
    assert all("mlx5_st0" not in command for command in calls)
    assert {command[0] for command in calls} == {"mlxconfig", "mlxlink", "ibnetdiscover"}
    for record in evidence:
        assert record["mlxconfig"] == {"status": "not determined", "reason": "tool not installed"}
        assert record["presentation"]["status"] == "not determined"

def test_local_worker_collects_down_port_evidence_before_peer_recovery(monkeypatch):
    monkeypatch.setenv("NODE_NAME", "synthetic-down")
    monkeypatch.setattr(nic, "collect_topo", lambda **kwargs: ("", "synthetic topology unavailable"))
    monkeypatch.setattr(nic, "_collect_hcas_local", lambda: [
        ("synthetic_ib", 0.0, "InfiniBand", "DOWN"),
    ])
    monkeypatch.setattr(nic, "_collect_netdevs_local", lambda: [])
    monkeypatch.setattr(nic, "_read_sysfs", lambda path: "")

    def runner(command, **kwargs):
        if command[0] == "mlxconfig":
            return subprocess.CompletedProcess(command, 0, "SPLIT_MODE SPLIT_2X(1)\n", "")
        raise FileNotFoundError(command[0])

    record = nic.gather(runner=runner)
    assert record["nics"][0]["role"] != "fabric"
    assert record["plane_evidence"][0]["presentation"]["status"] == "ok"

def test_kubernetes_keeps_down_port_tool_output_through_peer_recovery():
    def runner(command, **kwargs):
        args = command[1:]
        if args[:2] == ["get", "nodes"]:
            return subprocess.CompletedProcess(command, 0, json.dumps({"items": [{
                "metadata": {"name": f"synthetic-{index}"},
                "status": {"capacity": {"nvidia.com/gpu": "1"}},
            } for index in range(3)]}), "")
        if args[:2] == ["get", "pods"]:
            node = args[args.index("--field-selector") + 1].split("=", 1)[1]
            return subprocess.CompletedProcess(command, 0, json.dumps({"items": [{
                "metadata": {"name": f"nvidia-driver-{node}"},
                "status": {"phase": "Running"},
            }]}), "")
        if args[0] == "exec":
            failed = args[3].endswith("-2")
            topo = "" if failed else (
                "\tGPU0\tNIC0\nGPU0\tX\tPIX\nNIC0\tPIX\tX\nNIC Legend:\nNIC0: synthetic_ib"
            )
            text = (
                f"@@TOPO_BEGIN@@\n{topo}\n@@TOPO_END@@\n"
                f"@@HCA@@\tsynthetic_ib\t{'0' if failed else '200'} Gb/sec\tInfiniBand\t"
                f"{'1: DOWN' if failed else '4: ACTIVE'}\n"
                "@@PLANE@@ synthetic_ib mlxconfig BEGIN\nSPLIT_MODE SPLIT_2X(1)\n"
                "@@PLANE@@ synthetic_ib mlxconfig END 0\n"
            )
            return subprocess.CompletedProcess(command, 0, text, "")
        raise AssertionError(args)

    payload = nic.build_check_payload(
        harness="k8s", env={"CLUSTERMAX_GPU_OPERATOR_NAMESPACE": "synthetic-operator"},
        runner=runner,
    )
    assert payload["nic_topology"]["synthetic-2"][0]["role"] == "fabric"
    failed, = payload["nic_plane_evidence"]["synthetic-2"]
    assert failed["presentation"]["status"] == "ok"
    assert failed["mlxconfig"]["fields"]["SPLIT_MODE"] == "SPLIT_2X(1)"
