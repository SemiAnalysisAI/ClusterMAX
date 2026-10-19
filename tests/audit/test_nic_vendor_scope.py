"""Synthetic namespace and GPU-vendor cases for NIC system-pod collection."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


CHECK = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/checks/fabric/nic-topology-check.py"
SPEC = importlib.util.spec_from_file_location("nic_vendor_scope", CHECK)
assert SPEC and SPEC.loader
nic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nic)


def completed(command, *, data=None, code=0, text=""):
    return subprocess.CompletedProcess(
        command, code, stdout=json.dumps(data) if data is not None else text, stderr=""
    )


@pytest.mark.parametrize("namespace", ["amd-gpu-operator", "synthetic-gpu-operator", "synthetic-nvidia-gpu"])
def test_namespace_discovery_reaches_standard_and_custom_operator_names(namespace):
    calls = []

    def runner(command, **kwargs):
        calls.append(command[1:])
        if command[1:3] == ["get", "namespaces"]:
            return completed(command, data={"items": [
                {"metadata": {"name": "unrelated"}},
                {"metadata": {"name": namespace}},
            ]})
        return completed(command, code=0 if command[-1] == namespace else 1)

    assert nic.k8s_gpu_namespace(env={}, runner=runner) == namespace
    if namespace.startswith("synthetic-"):
        assert ["get", "namespaces", "-o", "json"] in calls


@pytest.mark.parametrize("reply", ["not-json", "[]", '{"items":null}', '{"items":[null,{}]}'])
def test_unusable_namespace_inventory_retains_generic_fallback(reply):
    def runner(command, **kwargs):
        if command[1:3] == ["get", "namespaces"]:
            return completed(command, text=reply)
        return completed(command, code=0 if command[-1] == "gpu" else 1)

    assert nic.k8s_gpu_namespace(env={}, runner=runner) == "gpu"


@pytest.mark.parametrize("vendor", ["amd", "nvidia"])
def test_shipped_collector_only_runs_nvidia_topology_for_nvidia(tmp_path, vendor):
    marker = tmp_path / "called"
    binary = tmp_path / "nvidia-smi"
    binary.write_text('#!/bin/sh\nprintf called > "$MARKER"\nprintf "synthetic topology\\n"\n')
    binary.chmod(0o755)
    section = nic.K8S_COLLECTOR_SH.split("for d in /sys/class/infiniband/", 1)[0]
    result = subprocess.run(
        ["/bin/sh", "-c", f"CLUSTERMAX_GPU_VENDOR={vendor}\n{section}"],
        env={**os.environ, "PATH": str(tmp_path), "MARKER": str(marker)},
        capture_output=True, text=True, check=True,
    )
    assert marker.exists() == (vendor == "nvidia")
    assert ("synthetic topology" in result.stdout) == (vendor == "nvidia")


@pytest.mark.parametrize("vendors", [("amd",), ("nvidia", "amd")])
def test_amd_inventory_does_not_become_a_topology_failure_or_nvlink_proof(vendors, capsys):
    nodes = [{"metadata": {"name": f"synthetic-{vendor}"}, "status": {
        "capacity": {f"{vendor}.com/gpu": "1"},
    }} for vendor in vendors]

    def runner(command, **kwargs):
        args = command[1:]
        if args[:2] == ["get", "nodes"]:
            return completed(command, data={"items": nodes})
        if args[:2] == ["get", "pods"]:
            vendor = args[args.index("--field-selector") + 1].rsplit("-", 1)[1]
            return completed(command, data={"items": [{
                "metadata": {"name": f"{vendor}-device-plugin-synthetic"},
                "spec": {"containers": [{
                    "name": "synthetic-plugin", "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                }], "volumes": [{"name": "host", "hostPath": {"path": "/"}}]},
                "status": {"phase": "Running"},
            }]})
        if args[0] == "exec":
            vendor = "amd" if "amd-device-plugin-synthetic" in args else "nvidia"
            assert args[-1].startswith(f"CLUSTERMAX_GPU_VENDOR={vendor}\n")
            topo = "\tGPU0\tGPU1\nGPU0\tX\tNV2\nGPU1\tNV2\tX" if vendor == "nvidia" else ""
            return completed(command, text=(
                f"@@TOPO_BEGIN@@\n{topo}\n@@TOPO_END@@\n"
                "@@HCA@@\tsynthetic_rdma\t100 Gb/sec\tEthernet\t4: ACTIVE\n"
            ))
        raise AssertionError(args)

    payload = nic.build_check_payload(
        harness="k8s", env={"CLUSTERMAX_GPU_OPERATOR_NAMESPACE": "synthetic-gpu-operator"},
        runner=runner,
    )
    assert "nic_topology_status" not in payload
    assert "nvidia-smi topo -m failed" not in capsys.readouterr().err
    assert payload["nic_topology"]["synthetic-amd"][0]["name"] == "synthetic_rdma"
    assert payload["nvlink_topology"]["hosts"]["synthetic-amd"] == {
        "checked": False, "exposed": None, "applicable": False,
    }
    assert payload["nvlink_topology"]["coverageComplete"] == ("nvidia" in vendors)
    if "nvidia" in vendors:
        assert payload["nvlink_topology"]["hosts"]["synthetic-nvidia"] == {
            "checked": True, "exposed": True,
        }
