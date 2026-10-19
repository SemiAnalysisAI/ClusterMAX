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


@pytest.mark.parametrize(
    "nvidia_namespace,amd_namespace,list_allowed",
    [
        ("gpu-operator", "amd-gpu-operator", True),
        ("gpu-operator", "kube-amd-gpu", True),
        ("synthetic-nvidia-gpu", "synthetic-amd-gpu-operator", True),
        ("gpu-operator", "kube-amd-gpu", False),
    ],
)
@pytest.mark.parametrize("amd_available", [True, False])
def test_mixed_vendor_namespace_selection_without_a_shared_override(
    nvidia_namespace, amd_namespace, list_allowed, amd_available,
):
    namespaces = {"nvidia": nvidia_namespace, "amd": amd_namespace}
    calls = []

    def runner(command, **kwargs):
        args = command[1:]
        calls.append(args)
        if args[:2] == ["get", "nodes"]:
            return completed(command, data={"items": [{
                "metadata": {"name": f"synthetic-{vendor}"},
                "status": {"capacity": {f"{vendor}.com/gpu": "1"}},
            } for vendor in ("nvidia", "amd")]})
        if args[:2] == ["get", "namespaces"]:
            return completed(command, code=0 if list_allowed else 1, data={"items": [
                {"metadata": {"name": name}} for name in reversed(list(namespaces.values()))
            ]})
        if args[:2] == ["get", "namespace"]:
            return completed(command, code=0 if args[-1] in namespaces.values() else 1)
        if args[:2] == ["get", "pods"]:
            namespace = args[args.index("-n") + 1]
            vendor = args[args.index("--field-selector") + 1].rsplit("-", 1)[1]
            if namespace != namespaces[vendor] or (vendor == "amd" and not amd_available):
                return completed(command, data={"items": []})
            return completed(command, data={"items": [{
                "metadata": {"name": f"{vendor}-device-plugin-synthetic"},
                "spec": {
                    "containers": [{
                        "name": "synthetic-plugin", "securityContext": {"privileged": True},
                        "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                    }],
                    "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                },
                "status": {"phase": "Running"},
            }]})
        if args[0] == "exec":
            vendor = "amd" if "amd-device-plugin-synthetic" in args else "nvidia"
            assert args[args.index("-n") + 1] == namespaces[vendor]
            topo = "GPU0 X" if vendor == "nvidia" else ""
            return completed(command, text=(
                f"@@TOPO_BEGIN@@\n{topo}\n@@TOPO_END@@\n"
                "@@HCA@@\tsynthetic_rdma\t100 Gb/sec\tEthernet\t4: ACTIVE\n"
            ))
        raise AssertionError(args)

    records, errors = nic.k8s_records(env={}, runner=runner)
    assert {record["host"] for record in records} == (
        {"synthetic-nvidia", "synthetic-amd"} if amd_available else {"synthetic-nvidia"}
    )
    assert len([args for args in calls if args[:2] == ["get", "namespaces"]]) == 1
    if amd_available:
        assert errors == []
        amd, = [record for record in records if record["gpu_vendor"] == "amd"]
        assert amd["topo_applicable"] is False
    else:
        assert len(errors) == 1
        assert "synthetic-amd: no running amd" in errors[0]


@pytest.mark.parametrize(
    "vendor,pod",
    [
        ("amd", "nvidia-driver-synthetic"),
        ("amd", "gpu-feature-discovery-synthetic"),
        ("nvidia", "amd-device-plugin-synthetic"),
    ],
)
def test_pods_for_a_different_gpu_vendor_cannot_satisfy_the_check(vendor, pod):
    def runner(command, **kwargs):
        assert command[1:3] == ["get", "pods"]
        return completed(command, data={"items": [{
            "metadata": {"name": pod},
            "spec": {"containers": [{
                "name": "synthetic-plugin", "securityContext": {"privileged": True},
            }]},
            "status": {"phase": "Running"},
        }]})

    record, error = nic.run_k8s_node_check(
        "synthetic-shared", "synthetic-node", runner=runner, gpu_vendor=vendor,
    )
    assert record is None
    assert "no running GPU Operator system pod" in error
