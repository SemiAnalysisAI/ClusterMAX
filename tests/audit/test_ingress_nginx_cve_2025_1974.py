"""Synthetic pod metadata tests for the read-only ingress-nginx CVE check."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

import pytest

from cmax import audit_report, audit_runner, runtime_paths, security


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "cmax/scripts/1-audit"
CHECK = SCRIPTS / "checks/system/ingress_nginx_cve_2025_1974.py"
SPEC = importlib.util.spec_from_file_location("ingress_cve", CHECK)
assert SPEC and SPEC.loader
ingress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingress)
CHECK_ID = "ingress-nginx-cve-2025-1974"
IMAGE = "registry.k8s.io/ingress-nginx/controller"


def pod(image=f"{IMAGE}:v1.12.0", *, name="test-controller", labels=None):
    return {
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "test-ingress", "labels": labels or {}},
        "spec": {"containers": [{"name": "controller", "image": image}]},
        "status": {"phase": "Running"},
    }


def inventory(*pods, **metadata):
    return {"kind": "PodList", "metadata": metadata, "items": list(pods)}


def evaluate(*pods, **metadata):
    return ingress.evaluate_inventory(inventory(*pods, **metadata))


@pytest.mark.parametrize("version", ["0.49.3", "1.0.0", "1.10.7", "1.11.0", "1.11.4", "1.12.0"])
def test_affected_versions(version):
    result = evaluate(pod(f"{IMAGE}:v{version}"))
    assert result["status"] == "fail"
    assert result["controllers"][0]["version"] == f"v{version}"


@pytest.mark.parametrize("version", ["1.11.5", "1.11.6", "1.12.1", "1.12.10", "1.13.0", "1.14.1"])
def test_fixed_versions(version):
    assert evaluate(pod(f"{IMAGE}:v{version}"))["status"] == "pass"


@pytest.mark.parametrize("image", [
    f"{IMAGE}@sha256:" + "a" * 64,
    f"{IMAGE}:latest",
    f"{IMAGE}:v1.11.5-rc.1",
    f"{IMAGE}:v1.12.1-beta.0",
    f"{IMAGE}:v1.12.1-vendor.1",
    f"{IMAGE}:v2.0.0",
    "mirror.example.test/ingress-nginx/controller:v1.12.1",
])
def test_ambiguous_versions_cannot_pass(image):
    assert evaluate(pod(image))["status"] == "unknown"


def test_tag_plus_digest_is_tag_evidence_not_digest_attestation():
    image = f"{IMAGE}:v1.12.1@sha256:" + "b" * 64
    result = evaluate(pod(image))
    assert result["status"] == "pass"
    assert result["controllers"][0]["image"] == image
    verdict = security._ingress_nginx_cve_2025_1974({ingress.KEY: result})
    assert "not binary identity" in verdict[2]


@pytest.mark.parametrize("repository", sorted(ingress.UPSTREAM_IMAGES))
def test_upstream_repository_names(repository):
    assert evaluate(pod(f"{repository}:v1.11.4"))["status"] == "fail"


def test_labels_and_command_find_custom_controllers_without_trusting_label_version():
    labels = {
        "app.kubernetes.io/name": "ingress-nginx",
        "app.kubernetes.io/component": "controller",
        "app.kubernetes.io/version": "1.12.1",
    }
    custom = pod("registry.example.test/custom:fixed", labels=labels)
    assert evaluate(custom)["status"] == "unknown"
    custom["metadata"]["labels"] = {}
    custom["spec"]["containers"][0]["command"] = ["/nginx-ingress-controller"]
    assert evaluate(custom)["status"] == "unknown"


def test_unresolved_labelled_pod_is_unknown():
    custom = pod("registry.example.test/custom:fixed", labels={"app.kubernetes.io/name": "ingress-nginx"})
    custom["spec"]["containers"][0]["name"] = "custom"
    assert evaluate(custom)["status"] == "unknown"


def test_nginx_inc_and_certgen_are_not_the_community_controller():
    f5 = pod("nginx/nginx-ingress:3.7.0")
    job = pod("registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.5.0", labels={
        "app.kubernetes.io/name": "ingress-nginx",
        "app.kubernetes.io/component": "admission-webhook",
    })
    assert evaluate(f5, job)["status"] == "not_applicable"


def test_sidecar_does_not_override_the_controller_version():
    controller = pod(f"{IMAGE}:v1.12.1", labels={"app.kubernetes.io/name": "ingress-nginx"})
    controller["spec"]["containers"].append({"name": "metrics", "image": "test/metrics:v1"})
    result = evaluate(controller)
    assert result["status"] == "pass"
    assert len(result["controllers"]) == 1


def test_all_replicas_are_graded_and_known_failure_wins():
    result = evaluate(pod(f"{IMAGE}:v1.12.1"), pod(name="test-old"), pod(f"{IMAGE}:latest"))
    assert result["status"] == "fail"
    assert len(result["controllers"]) == 3
    assert evaluate(pod(), **{"continue": "next"})["status"] == "fail"
    assert evaluate(pod(f"{IMAGE}:v1.12.1"), pod(f"{IMAGE}:latest"))["status"] == "unknown"


@pytest.mark.parametrize("phase", ["Succeeded", "Failed"])
def test_terminal_pods_do_not_represent_active_controllers(phase):
    old = pod()
    old["status"]["phase"] = phase
    assert evaluate(old)["status"] == "not_applicable"


def test_pending_and_terminating_pods_are_in_scope():
    pending = pod()
    pending["status"]["phase"] = "Pending"
    assert evaluate(pending)["status"] == "fail"
    pending["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    assert evaluate(pending)["status"] == "fail"


def test_empty_inventory_is_scoped_not_applicable():
    result = evaluate()
    assert result["status"] == "not_applicable"
    verdict = security._ingress_nginx_cve_2025_1974({ingress.KEY: result})
    assert verdict[0] == security.NOT_APPLICABLE
    assert "Scaled-to-zero" in verdict[2]


@pytest.mark.parametrize("payload", [
    None, {}, {"items": {}}, inventory(42), inventory({"kind": "Deployment"}),
    inventory(**{"continue": "next"}), inventory(remainingItemCount=1),
    {"items": [], "metadata": []},
])
def test_missing_malformed_or_partial_inventory_cannot_pass(payload):
    result = ingress.evaluate_inventory(payload)
    assert result["status"] == "unknown"
    assert result["inventoryComplete"] is False
    assert result["errors"]


@pytest.mark.parametrize("field,value", [
    ("metadata", None), ("spec", []), ("status", False),
])
def test_malformed_pod_fields(field, value):
    value_pod = pod()
    value_pod[field] = value
    assert evaluate(value_pod)["status"] == "unknown"


@pytest.mark.parametrize("container", [
    None, {}, {"name": "controller", "image": 4},
    {"name": "controller", "image": f"{IMAGE}:v1.12.1", "command": None},
    {"name": "controller", "image": f"{IMAGE}:v1.12.1", "command": [1]},
])
def test_malformed_container_cannot_pass(container):
    value_pod = pod()
    value_pod["spec"]["containers"] = [container]
    assert evaluate(value_pod)["status"] == "unknown"


@pytest.mark.parametrize("harness", ["slurm", "standalone", ""])
def test_non_kubernetes_never_runs_kubectl(harness):
    with mock.patch.dict(os.environ, {"CLUSTERMAX_AUDIT_HARNESS": harness}), mock.patch.object(
        ingress.subprocess, "run"
    ) as run:
        assert ingress.collect()[ingress.KEY]["status"] == "not_applicable"
        run.assert_not_called()


@pytest.mark.parametrize("outcome", [
    FileNotFoundError(), subprocess.TimeoutExpired("kubectl", 20),
    subprocess.CompletedProcess("kubectl", 1, "", "Forbidden secret-sentinel"),
    subprocess.CompletedProcess("kubectl", 0, "bad-json", ""),
])
def test_transport_failure_is_unknown_and_does_not_echo_raw_response(outcome):
    with mock.patch.dict(os.environ, {"CLUSTERMAX_AUDIT_HARNESS": "k8s"}), mock.patch.object(
        ingress.subprocess, "run",
        side_effect=outcome if isinstance(outcome, BaseException) else None,
        return_value=outcome,
    ):
        result = ingress.collect()[ingress.KEY]
    assert result["status"] == "unknown"
    assert "secret-sentinel" not in json.dumps(result)


def test_collection_is_one_bounded_read_and_saves_only_selected_metadata():
    value_pod = pod()
    value_pod["spec"]["containers"][0]["env"] = [{"name": "SENSITIVE", "value": "secret-sentinel"}]
    with mock.patch.dict(os.environ, {"CLUSTERMAX_AUDIT_HARNESS": "k8s"}), mock.patch.object(
        ingress.subprocess, "run",
        return_value=subprocess.CompletedProcess("kubectl", 0, json.dumps(inventory(value_pod)), ""),
    ) as run:
        result = ingress.collect()
    assert run.call_args.args[0] == [
        "kubectl", "get", "pods", "--all-namespaces", "-o", "json", "--request-timeout=15s"
    ]
    assert run.call_args.kwargs["timeout"] == 20
    assert "secret-sentinel" not in json.dumps(result)
    assert run.call_count == 1


@pytest.mark.parametrize("mutation", [
    {"inventoryComplete": False}, {"errors": ["denied"]}, {"controllers": []},
    {"controllers": [{}]}, {"status": "unknown"},
])
def test_report_does_not_accept_incomplete_pass(mutation):
    result = evaluate(pod(f"{IMAGE}:v1.12.1"))
    result.update(mutation)
    assert security._ingress_nginx_cve_2025_1974({ingress.KEY: result})[0] == security.WARNING


def test_report_missing_and_malformed_evidence_is_warning():
    for value in ({}, {ingress.KEY: None}, {ingress.KEY: {"status": "pass"}}):
        assert security._ingress_nginx_cve_2025_1974(value)[0] == security.WARNING


def test_report_failure_wins_over_missing_coverage():
    result = evaluate(pod())
    result.update(inventoryComplete=False, errors=["denied"])
    assert security._ingress_nginx_cve_2025_1974({ingress.KEY: result})[0] == security.CRITICAL


def test_disabling_admission_does_not_claim_a_fixed_image():
    value_pod = pod()
    value_pod["spec"]["containers"][0]["args"] = ["--validating-webhook="]
    assert evaluate(value_pod)["status"] == "fail"


def test_profile_selection_and_harness_gating():
    spec = importlib.util.spec_from_file_location("ingress_run_checks", SCRIPTS / "run_checks.py")
    assert spec and spec.loader
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    for profile in ("full", "security", "isolation"):
        assert CHECK in runner.iter_checks(SCRIPTS / "checks", "k8s", profile)
        for harness in ("slurm", "standalone"):
            assert CHECK not in runner.iter_checks(SCRIPTS / "checks", harness, profile)
    assert CHECK not in runner.iter_checks(SCRIPTS / "checks", "k8s", "hardware")


def test_full_security_and_isolation_reports_match_and_other_targets_skip():
    values = {"cluster": {"orchestrator": "k8s"}, "audit_data": {ingress.KEY: evaluate(pod())}}
    runtime = runtime_paths.package_runtime_root()
    reports = [
        next(check for check in audit_report.evaluate(values, runtime, category=category)
             if check.key == CHECK_ID)
        for category in (None, "security", "isolation")
    ]
    assert reports[0] == reports[1] == reports[2]
    assert reports[0].status == "fail"
    for harness in ("slurm", "standalone"):
        check = next(check for check in audit_report.evaluate(values, runtime, harness=harness)
                     if check.key == CHECK_ID)
        assert check.status == "skipped"


def test_check_runner_merge_saved_review_and_security_exit(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl = bin_dir / "kubectl"
    kubectl.write_text("#!/bin/sh\nprintf '%s' '" + json.dumps(inventory(pod())) + "'\n")
    kubectl.chmod(0o755)
    check_root = tmp_path / "checks"
    (check_root / "system").mkdir(parents=True)
    (check_root / "system" / CHECK.name).symlink_to(CHECK)
    collected = tmp_path / "check-data.json"
    process = subprocess.run(
        [sys.executable, str(SCRIPTS / "run_checks.py"), str(check_root), str(collected), "k8s", "security"],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"},
    )
    assert process.returncode == 0, process.stderr
    assert f"{ingress.KEY}: FAIL" in process.stdout
    raw = tmp_path / "raw.json"
    raw.write_text("{}")
    saved = tmp_path / "audit.values.json"
    process = subprocess.run(
        [sys.executable, str(SCRIPTS / "merge_audit.py"), str(raw), str(saved), "test", "k8s", str(collected)],
        capture_output=True, text=True, timeout=30,
    )
    assert process.returncode == 0, process.stderr
    values = json.loads(saved.read_text())
    assert values["audit_data"][ingress.KEY]["status"] == "fail"
    process = subprocess.run(
        [sys.executable, "-m", "cmax.cli", "audit", "review", str(saved),
         "--command", f"show {CHECK_ID}", "--no-interactive"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert process.returncode == 0, process.stderr
    assert "status: fail" in process.stdout
    assert "CVE-2025-1974" in process.stdout

    def finish_collection(*args, **kwargs):
        audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (audit_dir / "audit.values.json").write_text(json.dumps(values))
        return 0, ""

    with mock.patch.object(audit_runner, "_audit_dir", return_value=tmp_path / "audit"), mock.patch.object(
        audit_runner.progress, "run_with_progress", side_effect=finish_collection,
    ):
        assert audit_runner.run(
            category="security", resolved_target=security.SecurityTarget("k8s", "k8s", True),
            exit_on_fail=True,
        ) == 2
