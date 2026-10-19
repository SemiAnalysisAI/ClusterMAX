"""Independent synthetic cases for evidence after cross-host fabric recovery."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


CHECK = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/checks/fabric/nic-topology-check.py"
SPEC = importlib.util.spec_from_file_location("failed_fabric_evidence", CHECK)
assert SPEC and SPEC.loader
nic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nic)


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
    nics = [
        {"name": "synthetic_down", "role": "storage", "layer": "InfiniBand", "state": "DOWN"},
        {"name": "synthetic_storage", "role": "storage", "layer": "InfiniBand", "state": "ACTIVE"},
        {"name": "synthetic_fabric", "role": "fabric", "layer": "InfiniBand", "state": "ACTIVE"},
    ]
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        raise FileNotFoundError(command[0])

    evidence = nic.collect_plane_evidence(nics, runner=runner, sysfs_root="/nonexistent")
    assert [entry["ibdev"] for entry in evidence] == ["synthetic_fabric", "synthetic_down"]
    assert all("synthetic_storage" not in command for command in calls)


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
