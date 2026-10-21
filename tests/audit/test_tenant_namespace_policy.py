"""Synthetic namespace-policy failures must not establish tenant admission."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


PATH = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/checks/system/tenant_pod_defaults.py"
SPEC = importlib.util.spec_from_file_location("namespace_policy_under_test", PATH)
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


@pytest.mark.parametrize("failure", [
    OSError("synthetic command unavailable"),
    subprocess.TimeoutExpired("synthetic kubectl", 30),
    subprocess.CompletedProcess([], 1, "", "synthetic Forbidden"),
    subprocess.CompletedProcess([], 0, "not JSON", ""),
    subprocess.CompletedProcess([], 0, "null", ""),
    subprocess.CompletedProcess([], 0, "[]", ""),
    subprocess.CompletedProcess([], 0, "{}", ""),
    subprocess.CompletedProcess([], 0, '{"metadata":[]}', ""),
    subprocess.CompletedProcess([], 0, '{"metadata":{"labels":[]}}', ""),
    subprocess.CompletedProcess([], 0, '{"metadata":{"labels":{"pod-security.kubernetes.io/enforce":3}}}', ""),
])
def test_unreadable_or_malformed_policy_is_unknown(monkeypatch, failure):
    def kubectl(*args, **kwargs):
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr(check, "kubectl", kubectl)
    assert check.namespace_enforces_privileged("synthetic-tenant") is None


@pytest.mark.parametrize("labels,expected", [
    ({"pod-security.kubernetes.io/enforce": "privileged"}, True),
    ({"pod-security.kubernetes.io/enforce": " PRIVILEGED "}, True),
    ({"pod-security.kubernetes.io/enforce": "baseline"}, False),
    ({"pod-security.kubernetes.io/enforce": "restricted"}, False),
    ({}, False),
    (None, False),
])
def test_readable_policy_keeps_the_explicit_label_semantics(monkeypatch, labels, expected):
    monkeypatch.setattr(check, "kubectl", lambda *args, **kwargs:
        subprocess.CompletedProcess([], 0, json.dumps({"metadata": {"labels": labels}}), ""))
    assert check.namespace_enforces_privileged("synthetic-tenant") is expected


def healthy_facts():
    return check.pod_facts({
        "TENANT_MEMLOCK_SOFT_KB": "unlimited",
        "TENANT_MEMLOCK_HARD_KB": "unlimited",
        "TENANT_SHM_KB": str(2 * 1024 * 1024),
        "TENANT_CAP_EFF": hex(1 << 14)[2:],
        "TENANT_IB_UVERBS": "3",
        "TENANT_RDMA_CM": "true",
        "TENANT_GDRDRV": "true",
        "TENANT_NVIDIA_DEVS": "1",
        "TENANT_UID": "1000",
    })


@pytest.mark.parametrize("mode,expected", [
    ("readable", "pass"), ("privileged", "unknown"), ("forbidden", "unknown"),
    ("timeout", "unknown"), ("invalid-json", "unknown"),
])
def test_shipped_collection_does_not_pass_on_unreadable_namespace(monkeypatch, mode, expected):
    nodes = {"items": [{
        "metadata": {"name": "synthetic-worker"},
        "status": {
            "capacity": {"nvidia.com/gpu": "3"},
            "allocatable": {"nvidia.com/gpu": "3"},
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }]}

    def kubectl(args, **kwargs):
        if args[:2] == ["get", "nodes"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(nodes), "")
        if args[:2] == ["get", "namespace"]:
            if mode == "forbidden":
                return subprocess.CompletedProcess(args, 1, "", "synthetic Forbidden")
            if mode == "timeout":
                raise subprocess.TimeoutExpired(args, 30)
            if mode == "invalid-json":
                return subprocess.CompletedProcess(args, 0, "[", "")
            labels = {"pod-security.kubernetes.io/enforce": (
                "privileged" if mode == "privileged" else "baseline"
            )}
            return subprocess.CompletedProcess(args, 0, json.dumps({"metadata": {"labels": labels}}), "")
        if args[:2] == ["get", "deviceclasses.resource.k8s.io"]:
            return subprocess.CompletedProcess(args, 0, '{"items":[]}', "")
        raise AssertionError(args)

    monkeypatch.setattr(check, "kubectl", kubectl)
    monkeypatch.setattr(check, "run_pod_check", lambda *args, **kwargs: {
        "admitted": True, "ready": True, "reason": "", "node": "synthetic-worker",
        "facts": healthy_facts(),
    })
    result = check.run_k8s_check()
    assert result["checks"]["tunedPodAdmission"]["status"] == expected
    if mode in {"forbidden", "timeout", "invalid-json"}:
        assert result["namespaceEnforcesPrivileged"] is None
        assert result["status"] == "unknown"
        assert "policy could not be read" in result["message"]
    elif mode == "readable":
        assert result["status"] == "pass"


def test_measured_warning_retains_priority_over_unknown_policy():
    facts = healthy_facts()
    result = check.aggregate(
        {"memlock": {"status": "warning", "detail": "synthetic low memlock"},
         "tunedPodAdmission": {"status": "unknown", "detail": "unreadable policy"}},
        default_pod={"facts": facts}, tuned={}, errors=[],
        context={"namespaceEnforcesPrivileged": None},
    )
    assert result["status"] == "warning"
    assert "synthetic low memlock" in result["message"]


def test_measured_admission_rejection_retains_warning_when_policy_is_unknown():
    checks = check.evaluate_checks(
        healthy_facts(), {"attempted": True, "admitted": False, "reason": "synthetic rejection"},
        gpu_requested=True, rdma_resources=[], memlock_min_mb=65536, shm_min_mb=1024,
        privileged_namespace=None,
    )
    assert checks["tunedPodAdmission"]["status"] == "warning"
