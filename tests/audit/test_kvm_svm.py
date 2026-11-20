"""Tests for the passive AMD KVM kernel check in the focused audit."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from cmax import audit_report, minimum_refresh, runtime_paths, security

ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
sys.path[:0] = [str(WORKLOAD), str(Path(__file__).resolve().parent)]

import bashtest
import host_fleet
import kvm_svm
import minimum_versions

audit_findings = bashtest.load_python_script(WORKLOAD / "audit_findings.py", "audit_findings_kvm_svm")


CNA_RECORD = Path(__file__).resolve().parent / "fixtures/minimum_refresh/linux-cna-cve-2026-99312.json"


class FrozenFeed(minimum_refresh.Fetcher):
    def get_json(self, url):
        return json.loads(CNA_RECORD.read_text())

    def get_text_head(self, url, max_bytes=1200):
        return None


@pytest.fixture(autouse=True)
def frozen_table(tmp_path, monkeypatch):
    """Grade against the generator output for the frozen CVE record, not the daily table."""
    spec = minimum_refresh.LINUX_KERNEL_CVE_SPECS[0]
    policy = minimum_refresh.linux_kernel_cve_minimums(spec, fetch=FrozenFeed())
    table = tmp_path / "minimums.json"
    table.write_text(json.dumps({"schemaVersion": 1, "components": {spec["key"]: policy}}))
    monkeypatch.setenv(minimum_versions.MINIMUMS_ENV, str(table))
    monkeypatch.setattr(minimum_versions, "_CACHE", None)


def test_shipped_table_carries_the_policy(monkeypatch):
    monkeypatch.delenv(minimum_versions.MINIMUMS_ENV)
    monkeypatch.setattr(minimum_versions, "_CACHE", None)
    assert kvm_svm.grade(facts("5.14.0"))["status"] == "not-applicable"


def facts(running="6.12.118", **extra):
    return {
        "WORKER_GUEST_KERNEL_RUNNING": running,
        "WORKER_VIRT_TYPE": "none",
        "WORKER_VIRT_GUEST": "false",
        "WORKER_CPU_VENDOR": "AuthenticAMD",
        "WORKER_NESTED_MODULE": "kvm_amd",
        "WORKER_NESTED_ENABLED": "true",
        "WORKER_PWNESCAPE_LIVEPATCH": "none",
        **extra,
    }


@pytest.mark.parametrize(("running", "status", "floor"), [
    ("6.12.117", "fail", "6.12.118"), ("6.12.118", "pass", "6.12.118"),
    ("6.18.63", "fail", "6.18.64"), ("6.18.64", "pass", "6.18.64"),
    ("7.3.4", "fail", "7.3.5"), ("7.3.5", "pass", "7.3.5"),
    ("7.4-rc1", "fail", "7.4-rc2"), ("7.4-rc2", "pass", "7.4-rc2"),
    ("7.4.0", "pass", "7.4-rc2"), ("6.19.100", "fail", "unknown"),
    ("5.15.80", "not-applicable", "unknown"), ("5.15.81", "fail", "unknown"),
    ("6.0.10", "not-applicable", "unknown"), ("6.0.11", "fail", "unknown"),
    ("6.8.0-135-generic", "unknown", "unknown"),
])
def test_upstream_floors_and_affected_ranges(running, status, floor):
    result = kvm_svm.grade(facts(running))
    assert (result["status"], result["minimum"]) == (status, floor)
    assert result["exploitTested"] is False


@pytest.mark.parametrize(("extra", "status"), [
    ({"WORKER_NESTED_ENABLED": "false"}, "not-applicable"),
    ({"WORKER_NESTED_ENABLED": "unknown"}, "unknown"),
    ({"WORKER_VIRT_GUEST": "true"}, "unknown"),
    ({"WORKER_VIRT_GUEST": "unknown"}, "unknown"),
    ({"WORKER_VIRT_TYPE": "kvm"}, "unknown"),
    ({"WORKER_CPU_VENDOR": "GenuineIntel"}, "unknown"),
    ({"WORKER_CPU_VENDOR": "GenuineIntel", "WORKER_NESTED_MODULE": "none"}, "not-applicable"),
    ({"WORKER_NESTED_MODULE": "none", "WORKER_KVM_AMD_LOADED": "false",
      "WORKER_KVM_DEVICE": "false"}, "not-applicable"),
    ({"WORKER_NESTED_MODULE": "none", "WORKER_KVM_AMD_LOADED": "true"}, "unknown"),
    ({"WORKER_PWNESCAPE_LIVEPATCH": "active-or-unreadable"}, "unknown"),
    ({"WORKER_PWNESCAPE_PACKAGE": "ii|linux|6.12.117-1"}, "unknown"),
])
def test_missing_or_out_of_scope_evidence(extra, status):
    assert kvm_svm.grade(facts("6.12.117", **extra))["status"] == status


def test_collector_uses_same_host_facts_for_both_paths(tmp_path, monkeypatch):
    for name in ("proc", "sys/module", "dev"):
        (tmp_path / name).mkdir(parents=True)
    (tmp_path / "proc/cpuinfo").write_text("processor\t: 0\nvendor_id\t: AuthenticAMD\n")
    monkeypatch.setenv("CLUSTERMAX_AUDIT_ROOT", str(tmp_path))
    name = "collect_kvm_svm_facts"
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", name)
    assert function == bashtest.extract_function(WORKLOAD / "pwnescape-host-facts.sh", name)
    command = ["bash", "-c", f"{function}\n{name}"]
    output = subprocess.check_output(command, text=True)
    assert "WORKER_CPU_VENDOR=AuthenticAMD" in output
    assert "WORKER_KVM_AMD_LOADED=false" in output
    (tmp_path / "sys/module/kvm_amd").mkdir()
    assert "WORKER_KVM_AMD_LOADED=true" in subprocess.check_output(command, text=True)


def test_fleet_and_default_cli_report_critical_and_unknown():
    def host(node, role, data):
        text = "\n".join(f"{key}={value}" for key, value in data.items())
        return {"node": node, "role": role, "checked": True, "facts": text}

    check_id = "kvm-svm-cve-2026-99312"
    control = {"discovered": True}
    worker = host("gpu-1", "worker", facts())
    unpatched = host("cp-1", "control-plane", facts("6.12.117"))
    guest = host("cp-1", "control-plane", facts(WORKER_VIRT_GUEST="true"))
    for plane, expected, cli_status in [
        (unpatched, "fail", security.CRITICAL), (guest, "unknown", security.WARNING)
    ]:
        result = host_fleet.grade_fleet([worker, plane], control)["kvmSvm"]
        assert result["status"] == expected
        assert "cp-1" in result["reason"]
        check = next(
            item for item in security.evaluate_security({"security": {"kvmSvm": result}})
            if item.id == check_id
        )
        assert check.status == cli_status

    assert host_fleet.grade_fleet([worker], {})["kvmSvm"]["status"] == "coverage-incomplete"


def test_shell_advisory_includes_the_running_kernel_verdict():
    data = "\n".join(f"{key}={value}" for key, value in facts("7.3.4").items())
    command = [
        "bash", "-c",
        'source "$1/audit-common.sh"; printf \'{%s "_end":null}\' '
        '"$(build_security_advisory_json --host-facts "$2")"',
        "bash", str(WORKLOAD), data,
    ]
    result = json.loads(subprocess.check_output(command, text=True))["kvmSvm"]
    assert (result["status"], result["minimum"]) == ("fail", "7.3.5")


@pytest.mark.parametrize(("host", "severity", "report_status"), [
    (facts("6.12.117"), audit_findings.VERSION, audit_report.FAIL),
    (facts(WORKER_VIRT_GUEST="true"), audit_findings.CONFIG, audit_report.WARNING),
    (facts(WORKER_NESTED_ENABLED="false"), None, audit_report.SKIPPED),
    (facts(), None, audit_report.PASS),
])
def test_full_audit_reports_only_fail_and_unverified_hosts(host, severity, report_status):
    values = {"audit_data": {"security": {"kvmSvm": kvm_svm.grade(host)}}}
    findings = audit_findings.detect_findings(values)
    assert [finding.severity for finding in findings] == ([severity] if severity else [])
    for finding in findings:
        assert finding.cves == (kvm_svm.CVE,)
    if severity == audit_findings.VERSION:
        assert "6.12.117" in findings[0].detected and "6.12.118" in findings[0].detected
    check = next(
        item for item in audit_report.evaluate(values, runtime_paths.package_runtime_root())
        if item.key == "security.kvmSvm.status"
    )
    assert check.status == report_status
    if report_status != audit_report.SKIPPED:
        spec = next(item for item in security.CHECK_SPECS if item.id == "kvm-svm-cve-2026-99312")
        cited = [reference.url for reference in spec.references]
        assert [url for _, url in check.references][:len(cited)] == cited
