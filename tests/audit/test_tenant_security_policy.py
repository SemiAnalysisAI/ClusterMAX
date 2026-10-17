"""Tenant assessment scope, fixed ranges and current controller exposure."""
import json

import pytest

from cmax import security
from cmax import audit_report
from test_minimum_refresh import StubFetcher, baseline
from cmax import minimum_refresh
from test_security_release_evidence import WORK, bashtest, runtime

policy = runtime.policy


def test_csaf_ga_ranges_retain_products_and_or_newer():
    result = minimum_refresh.connectx_minimums(fetch=StubFetcher())
    assert result["gaRanges"] == [
        {"product": "BlueField GA", "architectures": "BlueField-2(46), BlueField-3(46)",
         "minimum": "46.3008", "relation": "or-newer"},
        {"product": "ConnectX GA",
         "architectures": "ConnectX-6 DE, ConnectX-6 DX, ConnectX-6 LX, ConnectX-7, ConnectX-8",
         "minimum": "46.3008", "relation": "or-newer"},
    ]


@pytest.mark.parametrize("version,expected", [
    ("40.47.2526", "pass"), ("32.47.2526", "pass"),
    ("99.47.2526", "unknown"), ("12.47.2526", "unknown"),
    ("40.45.9999", "unknown"), ("32.43.8001", "fail"),
    ("40.46.3007", "fail"), ("40.46.3008", "pass"),
])
def test_product_scoped_ga_range(tmp_path, monkeypatch, version, expected):
    block = minimum_refresh.connectx_minimums(fetch=StubFetcher())
    table = tmp_path / "minimum.json"
    table.write_text(json.dumps({"schemaVersion": 1, "components": {"connectxFirmware": block}}))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(table))
    monkeypatch.setattr(policy.minimum_versions, "_CACHE", None)
    assert policy.connectx_firmware_verdict(version).status == expected


def test_without_vendor_range_a_newer_train_is_unknown(tmp_path, monkeypatch):
    table = tmp_path / "minimum.json"
    table.write_text(json.dumps({"schemaVersion": 1, "components": {
        "connectxFirmware": {"trains": {"46": 3008}},
    }}))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(table))
    monkeypatch.setattr(policy.minimum_versions, "_CACHE", None)
    assert policy.connectx_firmware_verdict("40.47.2526").status == "unknown"


@pytest.mark.parametrize("change", ["removed", "lowered"])
def test_refresh_cannot_lose_a_previously_verified_ga_range(change):
    previous = baseline()
    updated = baseline()
    if change == "removed":
        updated["components"]["connectxFirmware"].pop("gaRanges")
    else:
        updated["components"]["connectxFirmware"]["gaRanges"][0]["minimum"] = "45.1"
    with pytest.raises(RuntimeError, match="GA"):
        minimum_refresh.verify(updated, existing=previous)


@pytest.mark.parametrize("version", ["unknown", "1.0.0", "99.0.0"])
def test_complete_current_nic_mode_passes_without_certifying_stored_firmware(version):
    record = policy.virtio_net_result(
        version, mode="nic", coverage_complete=True, every_bluefield_host_read=False,
    )
    assert record["status"] == "pass"
    assert record["exposure"] == "none"
    assert record["assessmentBasis"] == "current-nic-mode"
    assert record["everyBluefieldHostRead"] is False
    verdict = security._virtio_net_bluefield({"securityVersions": {"virtioNetBluefield": record}})
    assert verdict[0] == security.PASS
    assert "not certified" in verdict[2]


def test_nic_sample_cannot_clear_unread_fleet():
    record = policy.virtio_net_result("unknown", mode="nic", coverage_complete=False)
    assert record["status"] == "unknown"
    assert record["assessmentBasis"] != "current-nic-mode"


def test_report_names_current_exposure_not_an_unread_firmware_pass():
    record = policy.virtio_net_result(
        "unknown", mode="nic", coverage_complete=True, every_bluefield_host_read=False,
    )
    checks = audit_report.evaluate(
        {"cluster": {"orchestrator": "k8s"},
         "audit_data": {"securityVersions": {"virtioNetBluefield": record}}},
        WORK.parent.parent,
    )
    check = next(row for row in checks if row.key == "securityVersions.virtioNetBluefield.status")
    assert check.status == audit_report.PASS
    assert "stored firmware not certified" in check.observed


def test_ufm_provider_control_is_skipped_not_passed():
    record = {"status": "provider_attestation_required", "applicable": True}
    grade, _, detail = security._ufm({"security": {"ufmSecuredBareMetalCloud": record}})
    assert grade == security.NOT_APPLICABLE
    assert "not a fabric-security pass" in detail


@pytest.mark.parametrize("complete,exclusive,expected", [
    (True, True, security.PASS), (False, True, security.WARNING),
    (True, False, security.CRITICAL), (True, None, security.WARNING),
])
def test_nvlink_requires_topology_and_ownership(complete, exclusive, expected):
    record = {"topologyChecked": True, "topologyCoverageComplete": complete,
              "domainExclusive": exclusive, "nvlinkExposed": True}
    result = security._nvlink_boundary({"security": {"nvlinkBoundary": record}})
    assert result[0] == expected
    if expected == security.PASS:
        assert "operator attests" in result[2]


@pytest.mark.parametrize("mc,chassis,checked,exposed", [
    ("error-response", "error-response", True, False),
    ("blocked", "error-response", True, False),
    ("error-response", "unknown", False, False),
    ("unknown", "unknown", False, False),
    ("not-installed", "not-installed", False, False),
    ("allowed", "error-response", True, True),
])
def test_bmc_error_response_is_scoped_no_usable_read(mc, chassis, checked, exposed):
    function = (WORK / "cluster-audit-slurm-security.sh").read_text().split(
        "k8s_bmc_record_for_current_pod() {", 1
    )[1].split("\ncollect_k8s_bmc_fleet()", 1)[0]
    script = (
        'run_k8s_security_script() { cat >/dev/null; '
        f'printf "DEVICE=true\\nPATH=/usr/bin/ipmitool\\nINSTALLED=true\\nMC={mc}\\nCHASSIS={chassis}\\n"; }}\n'
        + "k8s_bmc_record_for_current_pod() {" + function
        + '\nk8s_bmc_record_for_current_pod test-node\n'
    )
    result = bashtest.run_bash(script)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["checked"] is checked
    assert record["exposed"] is exposed
    assert record["errorResponseIsAccessDenial"] is False
