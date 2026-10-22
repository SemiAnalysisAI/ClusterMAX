"""Tenant assessment scope, fixed ranges and current controller exposure."""
import json

import pytest

from cmax import audit_report, minimum_refresh, runtime_paths, security
from test_minimum_refresh import StubFetcher, baseline
from test_security_release_evidence import WORK, bashtest, runtime

policy = runtime.policy
BMC_RECORD = bashtest.extract_function(
    WORK / "cluster-audit-slurm-security.sh", "k8s_bmc_record_for_current_pod"
)


def bmc_record(setup, **kwargs):
    run = bashtest.run_bash(
        setup + BMC_RECORD + "\nk8s_bmc_record_for_current_pod fixture-node", **kwargs
    )
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


@pytest.fixture(scope="module")
def connectx_block():
    return minimum_refresh.connectx_minimums(fetch=StubFetcher())


@pytest.mark.parametrize("message", [
    "Get Chassis Status failed: 0xff Unspecified error",
    "Unable to get Chassis Status: 0xff Unspecified error",
    "Get Device ID command failed: 0xff Unspecified error",
])
def test_bmc_chassis_command_error_is_preserved(message):
    record = bmc_record(
        "run_k8s_security_script() { bash; }\n",
        env={"CHASSIS_ERROR": message},
        stubs={"ipmitool": (
            'if [ "$1" = mc ]; then echo "Get Device ID command failed: 0xff Unspecified error"; '
            'else echo "$CHASSIS_ERROR"; fi\nexit 1'
        )},
    )
    assert record["checked"] is True
    assert record["exposed"] is False
    assert record["errorResponseIsAccessDenial"] is False


def test_csaf_ga_ranges_retain_products_and_or_newer(connectx_block):
    assert connectx_block["gaRanges"] == [
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
def test_product_scoped_ga_range(tmp_path, monkeypatch, connectx_block, version, expected):
    table = tmp_path / "minimum.json"
    table.write_text(json.dumps({
        "schemaVersion": 1, "components": {"connectxFirmware": connectx_block},
    }))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(table))
    monkeypatch.setattr(policy.minimum_versions, "_CACHE", None)
    assert policy.connectx_firmware_verdict(version).status == expected


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
    checks = audit_report.evaluate(
        {"cluster": {"orchestrator": "k8s"},
         "audit_data": {"securityVersions": {"virtioNetBluefield": record}}},
        WORK.parent.parent,
    )
    check = next(row for row in checks if row.key == "securityVersions.virtioNetBluefield.status")
    assert check.status == audit_report.PASS
    assert "stored firmware not certified" in check.observed


def test_nic_sample_cannot_clear_unread_fleet():
    record = policy.virtio_net_result("unknown", mode="nic", coverage_complete=False)
    assert record["status"] == "unknown"
    assert record["assessmentBasis"] != "current-nic-mode"


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
    record = bmc_record(
        'run_k8s_security_script() { cat >/dev/null; '
        f'printf "DEVICE=true\\nPATH=/usr/bin/ipmitool\\nINSTALLED=true\\nMC={mc}\\nCHASSIS={chassis}\\n"; }}\n'
    )
    assert record["checked"] is checked
    assert record["exposed"] is exposed
    assert record["errorResponseIsAccessDenial"] is False


@pytest.mark.parametrize("name,key,unverified", [
    ("qemu-virtio-serial", "qemuCve20243446", "host-version-required"),
    ("vmscape", "vmscape", "host-mitigation-required"),
])
@pytest.mark.parametrize("status,expected", [
    ("fail", security.CRITICAL), ("pass", security.PASS),
    ("unknown", security.WARNING), (None, security.WARNING),
    ("not-applicable", security.NOT_APPLICABLE),
    ("unverified", security.WARNING),
])
def test_hypervisor_status_reaches_security_and_full_reports(
    name, key, unverified, status, expected,
):
    if status == "unverified":
        status = unverified
    values = {"audit_data": {"security": {key: {"status": status}}}}
    check = next(c for c in security.evaluate_security(values) if c.id == name)
    assert check.status == expected
    row = next(c for c in audit_report.evaluate(values, runtime_paths.package_runtime_root())
               if c.key == name)
    assert row.status == {
        security.CRITICAL: audit_report.FAIL, security.PASS: audit_report.PASS,
        security.WARNING: audit_report.WARNING, security.NOT_APPLICABLE: audit_report.SKIPPED,
    }[expected]


def _nvlink_with(**boundary):
    audit = {"security": {
        "nvlinkBoundary": {
            "nvlinkExposed": False, "topologyChecked": True,
            "topologyCoverageComplete": True, "nvidiaGpuPresent": True,
            "targetIsVm": False, **boundary,
        },
        "virtualization": {"guest": False, "type": "none"},
    }}
    return security._nvlink_boundary(audit)


def test_container_seeing_some_host_gpus_cannot_clear_nvlink():
    status, observed, detail = _nvlink_with(
        allHostGpusVisible=False, hostGpuCount="4", visibleGpuCount="1")
    assert status == security.WARNING
    assert "host GPUs visible=1 of 4" in observed
    assert "other tenants" in detail


@pytest.mark.parametrize("boundary", [
    {"allHostGpusVisible": True, "hostGpuCount": "4", "visibleGpuCount": "4"},
    {},
])
def test_whole_host_view_or_no_visibility_evidence_keeps_not_applicable(boundary):
    assert _nvlink_with(**boundary)[0] == security.NOT_APPLICABLE


def test_visible_nvlink_is_still_reported_with_partial_view():
    assert _nvlink_with(nvlinkExposed=True, allHostGpusVisible=False)[0] == security.WARNING
