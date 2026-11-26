"""Offline fixtures for the passive SCTP SCTP_SENDALL collector and report path."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from cmax import security


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/audit"))
import bashtest


WORKLOAD = ROOT / "cmax/scripts/1-audit"
SPEC = importlib.util.spec_from_file_location("sctp_sendall", WORKLOAD / "sctp_sendall.py")
sctp_sendall = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sctp_sendall)


def facts(version="6.12.90", guest="false", technology="none", **extra):
    return {
        "WORKER_GUEST_KERNEL_RUNNING": version,
        "WORKER_VIRT_GUEST": guest,
        "WORKER_VIRT_TYPE": technology,
        "WORKER_SCTP_SENDALL_LIVEPATCH": "none",
        **extra,
    }


@pytest.mark.parametrize("minimum", sctp_sendall.FIXED_RELEASES.values())
def test_each_upstream_branch_boundary(minimum):
    major, minor, patch = map(int, minimum.split("."))
    assert sctp_sendall.grade(facts(minimum))["status"] == "pass"
    older = f"{major}.{minor}.{patch - 1}"
    assert sctp_sendall.grade(facts(older))["status"] == "fail"
    newer = f"{major}.{minor}.{patch + 1}"
    assert sctp_sendall.grade(facts(newer))["status"] == "pass"


@pytest.mark.parametrize("flavor", ["generic", "generic-64k"])
@pytest.mark.parametrize("upload,abi", sctp_sendall.UBUNTU_FIXED.items())
def test_each_ubuntu_train_boundary(upload, abi, flavor):
    assert sctp_sendall.grade(facts(f"{upload}-{abi}-{flavor}"))["status"] == "pass"
    assert sctp_sendall.grade(facts(f"{upload}-{abi - 1}-{flavor}"))["status"] == "fail"
    assert sctp_sendall.grade(facts(f"{upload}-{abi + 1}-{flavor}"))["status"] == "pass"


VENDOR_KERNEL = {
    "WORKER_GUEST_KERNEL_RUNNING": "6.17.0-1021-nvidia-64k",
    "WORKER_VIRT_GUEST": "false",
    "WORKER_VIRT_TYPE": "none",
    "WORKER_SCTP_SENDALL_LIVEPATCH": "none",
    "WORKER_KERNEL_DISTRIBUTION": "ubuntu 24.04",
    "WORKER_KERNEL_SOURCE_PACKAGE": "linux-nvidia-6.17 6.17.0-1021.21",
}


def test_vendor_kernel_asks_for_evidence_instead_of_guessing_a_verdict():
    value = sctp_sendall.grade(VENDOR_KERNEL)
    assert value["status"] == "unknown"
    assert value["kernelFlavor"] == "nvidia-64k"
    assert value["kernelAbi"] == "1021"
    assert value["exploitTested"] is False
    assert "neither a pass nor a fail" in value["reason"]
    assert "not unpatched" in value["reason"]
    assert sctp_sendall.FIX_SUBJECT in value["reason"]
    for evidence in ("distribution", "kernel flavor", "kernel ABI", "source package version", "upstream fix", "livepatch"):
        assert any(evidence in item for item in value["providerEvidence"])


@pytest.mark.parametrize(
    "version",
    [
        "6.12.90-custom", "6.12.91+", "6.2.0-39-generic", "6.8.0-136-lowlatency",
        "6.12.90-aws", "5.14.0-503.el9.x86_64", "7.3-rc7", "7.4.0",
        "6.12", "unknown", "", "6.12.90; touch /tmp/do-not-create",
    ],
)
def test_distribution_custom_rc_unlisted_and_malformed_need_evidence(version):
    assert sctp_sendall.grade(facts(version))["status"] == "unknown"


def test_vendor_kernel_names_the_provider_evidence_and_stays_unverified():
    value = sctp_sendall.grade(facts(
        version="6.17.0-1021-nvidia-64k",
        WORKER_KERNEL_DISTRIBUTION="ubuntu 24.04",
        WORKER_KERNEL_SOURCE_PACKAGE="linux-signed-nvidia-6.17 6.17.0-1021.21",
    ))
    assert value["status"] == "unknown"
    for expected in (
        "6.17.0-1021-nvidia-64k", "nvidia-64k", "1021",
        "linux-signed-nvidia-6.17 6.17.0-1021.21", sctp_sendall.FIX_SUBJECT, "livepatch",
    ):
        assert expected in value["reason"]
    assert "unverified" in value["reason"]
    assert "not unpatched" in value["reason"]
    assert value["kernelFlavor"] == "nvidia-64k"
    assert value["kernelAbi"] == "1021"
    assert value["minimum"] == "unknown"
    assert any("source package version" in item for item in value["providerEvidence"])


def test_vendor_kernel_observation_reaches_the_common_report():
    value = sctp_sendall.grade(facts(
        version="6.17.0-1021-nvidia-64k",
        WORKER_KERNEL_DISTRIBUTION="ubuntu 24.04",
        WORKER_KERNEL_SOURCE_PACKAGE="linux-signed-nvidia-6.17 6.17.0-1021.21",
    ))
    check = next(
        c for c in security.evaluate_security({"security": {"sctpSendall": value}})
        if c.id == "sctp-sendall"
    )
    assert check.status == security.WARNING
    assert "flavor=nvidia-64k" in check.observed
    assert "abi=1021" in check.observed
    status, observed, assessment = security._sctp_sendall(
        {"security": {"sctpSendall": value}}
    )
    assert status == security.WARNING
    assert "flavor=nvidia-64k" in observed
    assert sctp_sendall.FIX_SUBJECT in assessment


@pytest.mark.parametrize("technology", ["kvm", "qemu", "docker", "xen", "unknown"])
@pytest.mark.parametrize("version", ["6.12.89", "6.12.90"])
def test_guest_kernel_never_certifies_hidden_host(technology, version):
    value = sctp_sendall.grade(facts(version, "true", technology))
    assert value["status"] == "host-version-required"
    assert value["localKernelStatus"] == ("fail" if version.endswith("89") else "pass")
    assert value["exploitTested"] is False


def test_missing_and_conflicting_virtualization_never_pass():
    assert sctp_sendall.grade({})["status"] == "host-version-required"
    for guest, technology in [("unknown", "none"), ("false", "kvm"), ("true", "none")]:
        assert sctp_sendall.grade(facts(guest=guest, technology=technology))["status"] == "host-version-required"


@pytest.mark.parametrize("livepatch", ["unknown", "active-or-unreadable", "active"])
@pytest.mark.parametrize("version", ["6.12.89", "6.12.90"])
def test_livepatch_needs_cve_specific_evidence(version, livepatch):
    value = sctp_sendall.grade(facts(version, WORKER_SCTP_SENDALL_LIVEPATCH=livepatch))
    assert value["status"] == "unknown"


def test_ubuntu_kernel_below_fixed_abi_fails_on_bare_metal():
    # The incident kernel: jammy 5.15.0-181-generic is below the 5.15.0-186 fix.
    value = sctp_sendall.grade(facts("5.15.0-181-generic"))
    assert value["status"] == "fail"
    assert value["minimum"] == "5.15.0-186"


def test_installed_kernel_and_missing_guest_devices_do_not_clear_host():
    value = sctp_sendall.grade(facts(
        "6.12.89",
        WORKER_SCTP_SENDALL_SCTP_LOADED="false",
        WORKER_SCTP_SENDALL_USERNS_MAX="0",
    ))
    assert value["status"] == "fail"


def test_fact_parser_preserves_conflicts():
    raw = "\n".join(f"{k}={v}" for k, v in facts().items())
    raw += "\nWORKER_GUEST_KERNEL_RUNNING=6.12.89\n"
    output = subprocess.check_output(
        [sys.executable, str(WORKLOAD / "sctp_sendall.py")], input=raw, text=True
    )
    assert json.loads(output)["status"] == "unknown"


@pytest.mark.parametrize("version,expected", [("6.12.89", security.CRITICAL), ("6.12.90", security.PASS)])
def test_common_json_to_cli_report(version, expected):
    raw = "\n".join(f"{k}={v}" for k, v in facts(version).items())
    fragment = subprocess.check_output(
        ["bash", "-c",
         'source "$1/audit-common.sh"; build_security_advisory_json --host-facts "$2"',
         "bash", str(WORKLOAD), raw],
        text=True,
    )
    audit = {"security": json.loads("{" + fragment + '"sentinel": null}')}
    check = next(c for c in security.evaluate_security(audit) if c.id == "sctp-sendall")
    assert check.status == expected
    assert version in check.observed
    assert "CVE-2026-46227" in check.remediation


def test_old_audit_missing_facts_warns():
    check = next(c for c in security.evaluate_security({}) if c.id == "sctp-sendall")
    assert check.status == security.WARNING


def test_read_only_collector_re_roots_facts(tmp_path):
    # Invoke only the new passive function, never the whole hardware collector.
    source = (WORKLOAD / "host-check.sh").read_text()
    function = re.search(r"^collect_sctp_sendall_facts\(\) \{.*?^\}", source, re.M | re.S).group()
    (tmp_path / "sys/kernel/livepatch").mkdir(parents=True)
    (tmp_path / "sys/module/sctp").mkdir(parents=True)
    (tmp_path / "proc/sys/user").mkdir(parents=True)
    (tmp_path / "proc/sys/user/max_user_namespaces").write_text("0\n")
    env = {**os.environ, "CLUSTERMAX_AUDIT_ROOT": str(tmp_path)}
    output = subprocess.check_output(["bash", "-c", function + "\ncollect_sctp_sendall_facts"], env=env, text=True)
    assert "WORKER_SCTP_SENDALL_LIVEPATCH=none" in output
    assert "WORKER_SCTP_SENDALL_SCTP_LOADED=true" in output
    assert "WORKER_SCTP_SENDALL_USERNS_MAX=0" in output
    (tmp_path / "sys/kernel/livepatch/fix").mkdir()
    (tmp_path / "sys/kernel/livepatch/fix/enabled").write_text("1\n")
    output = subprocess.check_output(["bash", "-c", function + "\ncollect_sctp_sendall_facts"], env=env, text=True)
    assert "WORKER_SCTP_SENDALL_LIVEPATCH=active-or-unreadable" in output


@pytest.mark.parametrize("collector", ["k8s", "common"])
@pytest.mark.parametrize("version,expected", [("6.12.89", "fail"), ("6.12.90", "pass")])
def test_k8s_and_worker_collectors_feed_their_actual_host_facts(collector, version, expected):
    if collector == "k8s":
        script = WORKLOAD / "cluster-audit-k8s.sh"
        target = "SECURITY_ADVISORY_JSON"
        raw_variable = "HOST_CHECK_OUT"
        end = '--vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")'
    else:
        script = WORKLOAD / "audit-common.sh"
        target = "security_advisory_json"
        raw_variable = "WORKER_CHECK_OUTPUT"
        end = '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")'
    call = bashtest.extract_block(script, target + "=$(build_security_advisory_json \\", end)
    raw = "\n".join(f"{key}={value}" for key, value in facts(version).items())
    run = bashtest.run_bash(
        f'source "{WORKLOAD}/audit-common.sh"\n' + call + f'\nprintf "%s\\n" "${target}"',
        env={
            raw_variable: raw,
            "HP_JANUSCAPE_EXPOSED_JSON": '"unknown"',
            "januscape_exposed_json": '"unknown"',
        },
    )
    assert run.returncode == 0, run.stderr
    value = json.loads("{" + run.stdout + '"sentinel": null}')["sctpSendall"]
    assert value["runningKernel"] == version
    assert value["status"] == expected


@pytest.mark.parametrize("version,expected", [("6.12.89", "fail"), ("6.12.90", "pass")])
def test_absent_livepatch_interface_on_readable_sysfs_allows_version_verdict(tmp_path, version, expected):
    (tmp_path / "sys/kernel").mkdir(parents=True)
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_sctp_sendall_facts")
    run = bashtest.run_bash(
        function + "\ncollect_sctp_sendall_facts",
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    collected = dict(line.split("=", 1) for line in run.stdout.splitlines())
    assert collected["WORKER_SCTP_SENDALL_LIVEPATCH"] == "not-supported"
    assert sctp_sendall.grade({**facts(version), **collected})["status"] == expected


def test_missing_sysfs_and_dangling_livepatch_link_remain_unknown(tmp_path):
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_sctp_sendall_facts")
    for broken_link in (False, True):
        if broken_link:
            (tmp_path / "sys/kernel").mkdir(parents=True)
            (tmp_path / "sys/kernel/livepatch").symlink_to("/nonexistent-livepatch")
        run = bashtest.run_bash(
            function + "\ncollect_sctp_sendall_facts",
            env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
        )
        assert run.returncode == 0, run.stderr
        assert "WORKER_SCTP_SENDALL_LIVEPATCH=unknown" in run.stdout


def test_immediate_findings_keep_unknown_distinct_from_version_failure():
    spec = importlib.util.spec_from_file_location("sctp_sendall_findings", WORKLOAD / "audit_findings.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for status, severity in [("pass", None), ("fail", "VERSION"), ("unknown", "CONFIG"), ("host-version-required", "CONFIG")]:
        findings = module.detect_findings({"audit_data": {"security": {"sctpSendall": {"status": status}}}})
        found = [f for f in findings if f.key == "security.sctpSendall.status"]
        assert len(found) == (0 if severity is None else 1)
        if found:
            assert found[0].severity == severity
