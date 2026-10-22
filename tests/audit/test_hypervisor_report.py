import pytest
from cmax import audit_report, runtime_paths, security


@pytest.mark.parametrize("name,key,unverified", [
    ("qemu-virtio-serial", "qemuCve20243446", "host-version-required"),
    ("vmscape", "vmscape", "host-mitigation-required"),
])
@pytest.mark.parametrize("status,expected", [
    ("fail", security.CRITICAL), ("pass", security.PASS),
    ("unknown", security.WARNING), (None, security.WARNING),
    ("not-applicable", security.NOT_APPLICABLE),
])
def test_hypervisor_status_reaches_security_and_full_reports(name, key, unverified, status, expected):
    values = {"audit_data": {"security": {key: {"status": status}}}}
    check = next(c for c in security.evaluate_security(values) if c.id == name)
    assert check.status == expected
    row = next(c for c in audit_report.evaluate(values, runtime_paths.package_runtime_root())
               if c.key == name)
    assert row.status == {
        security.CRITICAL: audit_report.FAIL, security.PASS: audit_report.PASS,
        security.WARNING: audit_report.WARNING, security.NOT_APPLICABLE: audit_report.SKIPPED,
    }[expected]
    values["audit_data"]["security"][key]["status"] = unverified
    assert next(c for c in security.evaluate_security(values) if c.id == name).status == security.WARNING
