"""Verify the packaged collector and report integration."""
import importlib.util
from pathlib import Path
import pytest

from cmax import audit_report, runtime_paths

ROOT = runtime_paths.package_runtime_root()
WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"


def test_tenant_check_is_executable_and_excluded_from_security():
    spec = importlib.util.spec_from_file_location("tenant_run_checks", WORKLOAD / "run_checks.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    path = WORKLOAD / "checks/system/tenant_pod_defaults.py"
    assert path in runner.iter_checks(WORKLOAD / "checks", "k8s", "orchestration")
    assert path not in runner.iter_checks(WORKLOAD / "checks", "k8s", "security")
    assert path not in runner.iter_checks(WORKLOAD / "checks", "slurm")


def test_tenant_warning_preserves_detail_and_recommendation():
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "warning", "checks": {"memlock": {
            "status": "warning", "detail": "The pod has an 8 MiB limit."
        }}
    }}}
    checks = audit_report.evaluate(values, ROOT, harness="k8s")
    result = next(c for c in checks if c.key == "tenant_pod_defaults.checks.memlock.status")
    assert result.status == audit_report.WARNING
    assert result.assessment == "The pod has an 8 MiB limit."
    assert result.recommendation


def test_unreadable_namespace_policy_never_renders_as_pass():
    detail = "the namespace pod-security policy could not be read"
    values = {"audit_data": {"tenant_pod_defaults": {
        "status": "unknown", "message": detail, "namespaceEnforcesPrivileged": None,
        "checks": {"tunedPodAdmission": {"status": "unknown", "detail": detail}},
    }}}
    checks = audit_report.evaluate(values, ROOT, harness="k8s")
    rows = [row for row in checks if row.key in {
        "tenant_pod_defaults.status", "tenant_pod_defaults.checks.tunedPodAdmission.status",
    }]
    assert len(rows) == 2
    assert all(row.status != audit_report.PASS for row in rows)
    assert any("policy could not be read" in row.assessment for row in rows)


@pytest.mark.parametrize("ports", [None, "unknown", 0, "2", 2])
def test_absent_rdma_devices_do_not_crash_report(ports):
    values = {"audit_data": {
        "networking": {"hostRdma": {"activePorts": ports}},
        "tenant_pod_defaults": {"checks": {"rdmaDevices": {"status": "absent"}}},
    }}
    checks = audit_report.evaluate(values, ROOT, harness="k8s")
    check = next(c for c in checks if c.key == "tenant_pod_defaults.checks.rdmaDevices.status")
    assert check.status == (audit_report.WARNING if ports in (2, "2") else audit_report.SKIPPED)
    if ports == 0:
        assert "no active RDMA" in check.assessment
    elif ports in (None, "unknown"):
        assert "unverified" in check.assessment.lower()


@pytest.mark.parametrize("loaded", [False, "false", None])
def test_gdrcopy_skip_uses_collected_host_path(loaded):
    values = {"audit_data": {
        "gpus": {"gdrcopy": {"gdrdrvLoaded": loaded}},
        "tenant_pod_defaults": {"checks": {"gdrcopyDevice": {"status": "absent"}}},
    }}
    checks = audit_report.evaluate(values, ROOT, harness="k8s")
    check = next(c for c in checks if c.key == "tenant_pod_defaults.checks.gdrcopyDevice.status")
    assert check.status == audit_report.SKIPPED
    if loaded is None:
        assert "unverified" in check.assessment.lower()
    else:
        assert "gdrdrv is not loaded" in check.assessment
