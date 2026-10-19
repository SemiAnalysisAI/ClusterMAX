from unittest.mock import patch

from cmax import audit_report, obs_check, obs_discovery, runtime_paths, security


def test_non_kubernetes_audit_does_not_discover_other_kube_contexts():
    values = {}
    with patch.object(obs_discovery, "discover", return_value=obs_discovery.Discovery((), (), ())) as discover:
        security._inject_observability(values, target=security.SecurityTarget("slurm", "bare-metal"))
    assert discover.call_args.kwargs["services"] == {}


def test_captured_cross_tenant_result_reaches_both_reports(monkeypatch):
    monkeypatch.setenv("CLUSTERMAX_OBS_TARGETS", "https://metrics.example")
    summary = {
        "configured": True, "backends_reachable": 1, "read_open": True,
        "cross_tenant_series_visible": True, "foreign_tenant_counts": {"namespace": 2},
    }
    values = {}
    with patch.object(obs_check, "check", return_value=summary) as check:
        security._inject_observability(values, target=security.SecurityTarget("standalone", "bare-metal"))
    assert "credentials_by_target" not in check.call_args.kwargs
    assert next(c for c in security.evaluate_security(values)
                if c.id == "observability-isolation").status == security.CRITICAL
    rows = audit_report.evaluate(values, runtime_paths.package_runtime_root())
    assert next(c for c in rows if c.key == "observability-isolation").status == audit_report.FAIL


def test_missing_observability_evidence_is_not_a_pass():
    rows = security.evaluate_security({})
    assert next(c for c in rows if c.id == "observability-isolation").status == security.WARNING
