"""Verify the packaged collector and report integration."""
import importlib.util
from pathlib import Path

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
