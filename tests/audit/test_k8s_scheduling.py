"""Verify scheduling evidence with independent synthetic resource fixtures."""

import importlib.util
import json
import os
import subprocess
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"
CHECK = WORKLOAD / "checks/system/k8s_scheduling.py"
spec = importlib.util.spec_from_file_location("k8s_scheduling", CHECK)
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)


@pytest.mark.parametrize(
    "quantity",
    [
        0, 0.0, "0", "+0", "-0", "0.000", ".0", "000",
        "0n", "0u", "0m", "0k", "0K", "0M", "0G", "0T", "0P", "0E",
        "0Ki", "0Mi", "0Gi", "0Ti", "0Pi", "0Ei", "0.0Gi",
        "0e6", "0E-4", "-0.00e+7",
    ],
)
def test_zero_quota_includes_valid_unit_suffixes(quantity):
    def read(resource, namespace="", name=""):
        items = []
        if resource == "nodes":
            items = [{"metadata": {"name": "synthetic-node"}}]
        elif resource == f"clusterqueues.{scheduling.GROUP}":
            items = [{
                "metadata": {"name": "synthetic-queue"},
                "spec": {"resourceGroups": [{"flavors": [{
                    "name": "synthetic-flavor",
                    "resources": [{"name": "memory", "nominalQuota": quantity}],
                }]}]},
            }]
        return {
            "resource": resource, "namespace": namespace,
            "status": "collected" if items else "empty",
            "complete": True, "items": items,
        }

    with patch.object(scheduling, "read_resource", side_effect=read):
        result = scheduling.collect("synthetic-tenant")
    messages = [finding["message"] for finding in result["findings"]]
    assert len(messages) == 1
    assert "zero nominal quota for memory" in messages[0]
    assert result["status"] == "warning"


@pytest.mark.parametrize(
    "quantity",
    [
        None, False, "", "0bogus", "0GiGi", "NaN", "Infinity", " 0Gi",
        1, "1m", "0.001Gi", "1e-999999", "-1Gi", ".01",
    ],
)
def test_zero_quota_does_not_round_or_accept_invalid_quantities(quantity):
    assert scheduling.zero_quantity(quantity) is False


def synthetic_controller_volumes():
    return [
        {
            "name": "kube-api-access-synthetic",
            "projected": {"sources": [
                {"serviceAccountToken": {"path": "token"}},
                {"configMap": {"name": "kube-root-ca.crt"}},
                {"downwardAPI": {"items": []}},
            ]},
        },
        {"name": "configuration", "configMap": {"name": "synthetic-config"}},
    ]


def test_controller_configmaps_exclude_default_ca_in_all_volume_forms():
    controller = {
        "metadata": {"name": "kueue-synthetic", "namespace": "synthetic-system"},
        "spec": {"template": {"spec": {
            "volumes": synthetic_controller_volumes() + [
                {"name": "ca-copy", "configMap": {"name": "kube-root-ca.crt"}},
                {"name": "extra", "projected": {"sources": [
                    {"configMap": {"name": "synthetic-extra"}},
                ]}},
            ],
        }}},
    }
    selected = scheduling.select(controller, "controllers")
    assert selected["configMaps"] == ["synthetic-config", "synthetic-extra"]


@pytest.mark.parametrize("config_complete", [True, False])
def test_default_ca_is_never_read_or_reported_as_controller_config(config_complete):
    calls = []

    def read(resource, namespace="", name=""):
        calls.append((resource, namespace, name))
        row = {
            "resource": resource, "namespace": namespace, "status": "empty",
            "complete": True, "items": [],
        }
        if resource == "nodes":
            row.update(status="collected", items=[{"metadata": {"name": "synthetic-node"}}])
        elif resource == "deployments.apps":
            row.update(status="collected", items=[{
                "metadata": {"name": "kueue-synthetic", "namespace": "synthetic-system"},
                "spec": {"template": {"spec": {"volumes": synthetic_controller_volumes()}}},
            }])
        elif resource == "configmaps":
            assert name == "synthetic-config", "default CA must not be queried"
            row.update(
                status="collected" if config_complete else "forbidden",
                complete=config_complete,
                items=[{
                    "metadata": {"name": name},
                    "data": {"config.yaml": "apiVersion: config.kueue.x-k8s.io/v1beta1\n"},
                }] if config_complete else [],
            )
        return row

    with patch.object(scheduling, "read_resource", side_effect=read):
        result = scheduling.collect("synthetic-tenant")
    config_reads = [call for call in calls if call[0] == "configmaps"]
    assert config_reads == [("configmaps", "synthetic-system", "synthetic-config")]
    assert [config["name"] for config in result["controllerConfigs"]] == ["synthetic-config"]
    assert len(result["findings"]) == (0 if config_complete else 1)
    if not config_complete:
        assert "synthetic-config read is forbidden" in result["findings"][0]["message"]


def test_entrypoint_uses_tenant_namespace_over_benchmark_namespace(monkeypatch, capsys):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, '{"items":[]}', "")
    monkeypatch.setenv("CLUSTERMAX_AUDIT_HARNESS", "k8s")
    monkeypatch.setenv("CLUSTERMAX_AUDIT_TENANT_NAMESPACE", "tenant-a")
    monkeypatch.setenv("K8S_NAMESPACE", "bench-b")
    monkeypatch.setattr(subprocess, "run", run)
    runpy.run_path(str(CHECK), run_name="__main__")
    capsys.readouterr()
    scoped = [args for args in calls if args[2].startswith(("localqueues", "workloads", "resourcequotas", "limitranges"))]
    assert scoped
    assert all(args[args.index("-n") + 1] == "tenant-a" for args in scoped)


@pytest.mark.parametrize(
    ("code", "stdout", "stderr", "status", "complete"),
    [
        (0, '{"items": []}', "", "empty", True),
        (
            1,
            "",
            'the server doesn\'t have a resource type "clusterqueues"',
            "absent",
            True,
        ),
        (1, "", "Error from server (Forbidden)", "forbidden", False),
        (1, "", 'Error from server (NotFound): namespaces "missing" not found', "error", False),
        (
            1,
            "",
            "getting credentials: exec: executable plugin not found",
            "error",
            False,
        ),
        (0, '{"items": [{}]}', "", "error", False),
        (0, "invalid json", "", "error", False),
    ],
)
def test_collection_status(code, stdout, stderr, status, complete):
    with patch.object(
        scheduling.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], code, stdout, stderr),
    ):
        row = scheduling.read_resource("nodes")
    assert (row["status"], row["complete"]) == (status, complete)


@pytest.mark.parametrize(
    "error", [FileNotFoundError(), subprocess.TimeoutExpired("kubectl", 15)]
)
def test_unavailable_command_keeps_coverage_unknown(error):
    with patch.object(scheduling.subprocess, "run", side_effect=error):
        row = scheduling.read_resource("nodes")
    assert row["status"] == "error" and not row["complete"]


def test_collection_retains_policy_and_redacts_controller_configuration():
    fixtures = {
        "nodes": [
            {
                "metadata": {
                    "name": "gpu-0",
                    "labels": {"pool": "gpu"},
                    "annotations": {"private": "private-value"},
                },
                "spec": {
                    "taints": [
                        {"key": "dedicated", "value": "b300", "effect": "NoSchedule"}
                    ]
                },
            },
            {
                "metadata": {"name": "gpu-1"},
                "spec": {
                    "taints": [
                        {"key": "dedicated", "value": "b300", "effect": "NoSchedule"}
                    ],
                    "unschedulable": True,
                },
                "status": {
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "True",
                            "reason": "KubeletReady",
                            "message": "kubelet is posting ready status",
                            "lastHeartbeatTime": "2026-09-12T00:00:00Z",
                            "lastTransitionTime": "2026-09-12T00:00:00Z",
                        }
                    ]
                },
            },
        ],
        f"clusterqueues.{scheduling.GROUP}": [
            {
                "metadata": {"name": "train"},
                "spec": {
                    "cohort": "shared",
                    "resourceGroups": [
                        {
                            "flavors": [
                                {
                                    "name": "gpu",
                                    "resources": [
                                        {
                                            "name": "nvidia.com/gpu",
                                            "nominalQuota": "0",
                                            "borrowingLimit": "8",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                },
            }
        ],
        "deployments.apps": [
            {
                "metadata": {"name": "kueue-manager", "namespace": "custom"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "manager",
                                    "image": "private/kueue:v1",
                                    "args": [
                                        "--config",
                                        "/config/a.yaml",
                                        "--password=private-value",
                                    ],
                                    "env": [
                                        {"name": "SECRET", "value": "private-value"}
                                    ],
                                }
                            ],
                            "volumes": [
                                {
                                    "projected": {
                                        "sources": [{"configMap": {"name": "config"}}]
                                    }
                                }
                            ],
                        }
                    }
                },
            }
        ],
    }

    def run(args, **kwargs):
        assert args[:2] == ["kubectl", "get"]
        assert kwargs["timeout"] == 15
        assert "secrets" not in args
        if args[2] == "configmaps":
            assert args[3:6] == ["config", "-n", "custom"]
            data = {
                "metadata": {"name": "config"},
                "data": {
                    "a.yaml": "apiVersion: config.kueue.x-k8s.io/v1beta1\nmanageJobsWithoutQueueName: true\npassword: private-value\n"
                },
            }
        else:
            if args[2] == "localqueues.kueue.x-k8s.io":
                assert "tenant" in args
            data = {"items": fixtures.get(args[2], [])}
        return subprocess.CompletedProcess(args, 0, json.dumps(data), "")

    with patch.object(scheduling.subprocess, "run", side_effect=run):
        result = scheduling.collect("tenant")
        with (
            patch.object(scheduling, "MAX_BYTES", 1),
            patch.object(scheduling, "NODE_MAX_BYTES", 1),
        ):
            limited = scheduling.collect("tenant")
    assert (
        result["resources"]["nodes"]["items"][0]["spec"]["taints"][0]["value"] == "b300"
    )
    assert result["resources"]["nodes"]["items"][1]["status"]["conditions"] == [
        {"type": "Ready", "status": "True", "reason": "KubeletReady"}
    ]
    assert (
        result["resources"]["clusterQueues"]["items"][0]["spec"]["cohort"] == "shared"
    )
    assert (
        result["controllerConfigs"][0]["configuration"]["a.yaml"][
            "manageJobsWithoutQueueName"
        ]
        is True
    )
    assert "private-value" not in json.dumps(result)
    messages = [finding["message"] for finding in result["findings"]]
    assert (
        "2 nodes have taint dedicated=b300:NoSchedule, for example gpu-0, gpu-1."
        in messages
    )
    assert "Node gpu-1 is cordoned." in messages
    assert "zero nominal quota" in json.dumps(result["findings"])
    assert not limited["resources"]["nodes"]["complete"]
    assert not limited["resources"]["nodes"]["items"]
    limited_messages = [finding["message"] for finding in limited["findings"]]
    assert (
        "2 nodes have taint dedicated=b300:NoSchedule, for example gpu-0, gpu-1."
        in limited_messages
    )
    assert (
        "The nodes inventory is truncated at the retention limit." in limited_messages
    )


def test_check_runner_merge_and_report_preserve_visible_findings(tmp_path):
    checks = tmp_path / "checks"
    checks.mkdir()
    (checks / "scheduling.py").symlink_to(CHECK)
    kubectl = tmp_path / "kubectl"
    node = {
        "metadata": {"name": "gpu-0"},
        "spec": {
            "taints": [{"key": "dedicated", "value": "b300", "effect": "NoSchedule"}]
        },
    }
    kubectl.write_text(
        f"#!{sys.executable}\nimport json,sys\nprint(json.dumps({{'items': [{node!r}]}} if sys.argv[2] == 'nodes' else {{'items': []}}))\n"
    )
    kubectl.chmod(0o755)
    env = {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]}
    evidence, raw, values = (
        tmp_path / p for p in ("checks.json", "raw.json", "audit.values.json")
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(WORKLOAD / "run_checks.py"),
            str(checks),
            str(evidence),
            "k8s",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "k8s_scheduling: WARNING" in proc.stdout
    raw.write_text(
        json.dumps(
            {"audit": {"timestamp": "2026-09-12T00:00:00Z"}, "nodes": {"total": 1}}
        )
    )
    subprocess.run(
        [
            sys.executable,
            str(WORKLOAD / "merge_audit.py"),
            str(raw),
            str(values),
            "fixture",
            "k8s",
            str(evidence),
        ],
        check=True,
    )
    report = subprocess.run(
        [sys.executable, str(WORKLOAD / "audit_findings.py"), str(values)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "dedicated=b300:NoSchedule" in report.stdout
    assert (
        json.loads(values.read_text())["audit_data"]["k8s_scheduling"]
        == json.loads(evidence.read_text())["k8s_scheduling"]
    )
    proc = subprocess.run(
        [sys.executable, str(CHECK)],
        env={**env, "CLUSTERMAX_AUDIT_HARNESS": "slurm"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout == ""


def test_prefer_no_schedule_taint_is_retained_but_not_reported():
    nodes = [
        {
            "metadata": {"name": "gpu-0"},
            "spec": {"taints": [{"key": "is_gpu", "value": "true", "effect": "PreferNoSchedule"}]},
        },
        {
            "metadata": {"name": "gpu-1"},
            "spec": {"taints": [{"key": "dedicated", "value": "b300", "effect": "NoSchedule"}]},
        },
    ]

    def run(args, **kwargs):
        data = {"items": nodes if args[2] == "nodes" else []}
        return subprocess.CompletedProcess(args, 0, json.dumps(data), "")

    with patch.object(scheduling.subprocess, "run", side_effect=run):
        result = scheduling.collect("tenant")
    messages = [finding["message"] for finding in result["findings"]]
    assert not any("PreferNoSchedule" in message for message in messages)
    assert "Node gpu-1 has taint dedicated=b300:NoSchedule." in messages
    kept = result["resources"]["nodes"]["items"][0]["spec"]["taints"][0]
    assert kept["effect"] == "PreferNoSchedule"
