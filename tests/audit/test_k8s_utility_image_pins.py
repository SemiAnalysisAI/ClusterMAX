#!/usr/bin/env python3
"""Security contracts for temporary Kubernetes audit utility pods."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-k8s.sh"
)
CURL_IMAGE = (
    "curlimages/curl:8.21.0@"
    "sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13"
)
UBUNTU_IMAGE = (
    "ubuntu:24.04@"
    "sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea"
)


def _applied_manifest(function_name: str, setup: str) -> dict:
    function = bashtest.extract_function(SCRIPT, function_name)
    with tempfile.TemporaryDirectory() as temp_dir:
        applied = Path(temp_dir) / "applied.yaml"
        run = bashtest.run_bash(
            f"{function}\n{setup}",
            stubs={"kubectl": 'cat > "$APPLIED_MANIFEST"'},
            env={"APPLIED_MANIFEST": str(applied)},
        )
        assert run.returncode == 0, run.stderr
        return yaml.safe_load(applied.read_text())


def test_geolocation_pod_uses_reviewed_image_and_no_service_account_token():
    manifest = _applied_manifest(
        "apply_geolocation_check_pod",
        "GEO_POD=cmax-audit-geo-test\napply_geolocation_check_pod",
    )

    assert manifest["kind"] == "Pod"
    assert manifest["spec"]["automountServiceAccountToken"] is False
    assert manifest["spec"]["containers"][0]["image"] == CURL_IMAGE


def test_privileged_host_pod_uses_reviewed_image_and_no_service_account_token():
    manifest = _applied_manifest(
        "apply_privileged_host_check_pod",
        """
ensure_audit_check_namespace() { return 0; }
check_log() { return 0; }
audit_check_wait_ready() { return 0; }
cleanup_audit_check_pod() { return 0; }
K8S_AUDIT_CHECK_NS=test-ns
apply_privileged_host_check_pod gpu-1
""",
    )

    assert manifest["kind"] == "Pod"
    assert manifest["spec"]["automountServiceAccountToken"] is False
    assert manifest["spec"]["hostPID"] is True
    assert manifest["spec"]["hostNetwork"] is True
    assert manifest["spec"]["containers"][0]["image"] == UBUNTU_IMAGE
    assert manifest["spec"]["containers"][0]["securityContext"]["privileged"] is True
