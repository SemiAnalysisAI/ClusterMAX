from unittest.mock import patch

import pytest

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


@pytest.mark.parametrize("discovered", [False, True])
@pytest.mark.parametrize("exposure", [False, True])
def test_target_cap_preserves_incomplete_coverage_and_exposure(monkeypatch, discovered, exposure):
    targets = [f"http://metrics-{i}:9090" for i in range(obs_check.MAX_TARGETS + 2)]
    values = {}
    if discovered:
        monkeypatch.delenv("CLUSTERMAX_OBS_TARGETS", raising=False)
        monkeypatch.setenv("CLUSTERMAX_OBS_DISCOVER", "1")
        values = {"audit_data": {"healthChecks": {"monitoringStack": {
            "endpoints": [target.removeprefix("http://") for target in targets],
        }}}}
    else:
        # Duplicate aliases must not consume the target cap.
        monkeypatch.setenv("CLUSTERMAX_OBS_TARGETS", ",".join(targets + [targets[0] + "/"]))
    messages = []
    with patch.object(obs_discovery, "collect_local_sockets", return_value=""), \
         patch.object(obs_discovery, "collect_local_processes", return_value=""), \
         patch.object(obs_check, "check_endpoint", return_value={
             "reachable": True, "query_ok": True, "requests": 1,
             "unauth_query_ok": exposure,
         }) as endpoint:
        security._inject_observability(
            values, progress=messages.append,
            target=security.SecurityTarget("slurm", "bare-metal"),
        )
    summary = values["audit_data"]["security"]["observability"]
    assert summary["targets_found"] == len(targets)
    assert summary["targets_checked"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == 2
    assert endpoint.call_count == obs_check.MAX_TARGETS
    assert any("2 target(s) skipped" in message for message in messages)
    result = next(c for c in security.evaluate_security(values) if c.id == "observability-isolation")
    assert result.status == (security.CRITICAL if exposure else security.WARNING)


def test_target_cap_and_budget_skips_are_added():
    with patch.object(obs_check, "check_endpoint", return_value={"budget_exhausted": True}):
        summary = obs_check.check(
            [f"http://metrics-{i}:9090" for i in range(obs_check.MAX_TARGETS + 2)],
            own_namespace="default",
        )
    assert summary["targets_checked"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == obs_check.MAX_TARGETS + 2


@pytest.mark.parametrize("audit_count", [obs_check.MAX_TARGETS - 1, obs_check.MAX_TARGETS])
def test_summary_source_label_uses_selected_targets_only(monkeypatch, audit_count):
    monkeypatch.delenv("CLUSTERMAX_OBS_TARGETS", raising=False)
    monkeypatch.setenv("CLUSTERMAX_OBS_DISCOVER", "1")
    values = {"audit_data": {"healthChecks": {"monitoringStack": {
        "endpoints": [f"synthetic-metrics-{index}:9090" for index in range(audit_count)],
    }}}}
    services = {"items": [{
        "metadata": {"name": "synthetic-grafana", "namespace": "synthetic-monitoring"},
        "spec": {"ports": [{"port": 3000}]},
    }]}
    with patch.object(obs_discovery, "collect_local_sockets", return_value=""), \
         patch.object(obs_discovery, "collect_local_processes", return_value=""), \
         patch.object(obs_discovery, "collect_kubernetes_services", return_value=services), \
         patch.object(obs_check, "check_endpoint", return_value={
             "reachable": True, "query_ok": True, "requests": 1,
         }) as endpoint:
        security._inject_observability(
            values, target=security.SecurityTarget("k8s", "bare-metal"),
        )
    summary = values["audit_data"]["security"]["observability"]
    assert summary["targets_found"] == audit_count + 1
    assert summary["targets_checked"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == max(0, audit_count + 1 - obs_check.MAX_TARGETS)
    assert endpoint.call_count == obs_check.MAX_TARGETS
    expected = "audit" if audit_count == obs_check.MAX_TARGETS else "audit+k8s-services"
    assert summary["discovery"] == expected
    assert "grafana" in summary["platforms_detected"]


def test_source_label_does_not_count_a_deduplicated_url_alias(monkeypatch):
    monkeypatch.delenv("CLUSTERMAX_OBS_TARGETS", raising=False)
    monkeypatch.setenv("CLUSTERMAX_OBS_DISCOVER", "1")
    endpoints = [
        obs_discovery.Endpoint(f"http://synthetic-{index}:9090", "prometheus", "audit")
        for index in range(obs_check.MAX_TARGETS)
    ]
    endpoints.append(obs_discovery.Endpoint(
        endpoints[0].url + "/", "prometheus", "k8s-services",
    ))
    discovery = obs_discovery.Discovery(
        tuple(endpoints), ("prometheus",), ("audit", "k8s-services"),
    )
    values = {}
    with patch.object(obs_discovery, "discover", return_value=discovery), \
         patch.object(obs_check, "check_endpoint", return_value={
             "reachable": True, "query_ok": True, "requests": 1,
         }) as endpoint:
        security._inject_observability(
            values, target=security.SecurityTarget("k8s", "bare-metal"),
        )
    summary = values["audit_data"]["security"]["observability"]
    assert summary["discovery"] == "audit"
    assert summary["targets_found"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == 0
    assert endpoint.call_count == obs_check.MAX_TARGETS
