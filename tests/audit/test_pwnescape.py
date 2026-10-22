"""Offline fixtures for the passive PwnEscape collector and report path."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from cmax import audit_report, security


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/audit"))
import bashtest


WORKLOAD = ROOT / "cmax/scripts/1-audit"
SPEC = importlib.util.spec_from_file_location("pwnescape", WORKLOAD / "pwnescape.py")
pwnescape = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pwnescape)


def facts(version="6.12.113", guest="false", technology="none", **extra):
    return {
        "WORKER_GUEST_KERNEL_RUNNING": version,
        "WORKER_VIRT_GUEST": guest,
        "WORKER_VIRT_TYPE": technology,
        "WORKER_PWNESCAPE_LIVEPATCH": "none",
        **extra,
    }


@pytest.mark.parametrize("minimum", pwnescape.FIXED_RELEASES.values())
def test_each_upstream_branch_boundary(minimum):
    major, minor, patch = map(int, minimum.split("."))
    assert pwnescape.grade(facts(minimum))["status"] == "pass"
    older = f"{major}.{minor}.{patch - 1}"
    assert pwnescape.grade(facts(older))["status"] == "fail"
    newer = f"{major}.{minor}.{patch + 1}"
    assert pwnescape.grade(facts(newer))["status"] == "pass"


@pytest.mark.parametrize(
    "version",
    [
        "6.12.113-custom", "6.12.114+", "6.8.0-106-generic",
        "6.12.113-aws", "5.14.0-503.el9.x86_64", "7.3-rc7", "7.4.0",
        "6.12", "unknown", "", "6.12.113; touch /tmp/do-not-create",
    ],
)
def test_distribution_custom_rc_unlisted_and_malformed_need_evidence(version):
    assert pwnescape.grade(facts(version))["status"] == "unknown"


@pytest.mark.parametrize("technology", ["kvm", "qemu", "docker", "xen", "unknown"])
@pytest.mark.parametrize("version", ["6.12.112", "6.12.113"])
def test_guest_kernel_never_certifies_hidden_host(technology, version):
    value = pwnescape.grade(facts(version, "true", technology))
    assert value["status"] == "host-version-required"
    assert value["localKernelStatus"] == ("fail" if version.endswith("112") else "pass")
    assert value["exploitTested"] is False


def test_missing_and_conflicting_virtualization_never_pass():
    assert pwnescape.grade({})["status"] == "host-version-required"
    for guest, technology in [("unknown", "none"), ("false", "kvm"), ("true", "none")]:
        assert pwnescape.grade(facts(guest=guest, technology=technology))["status"] == "host-version-required"


@pytest.mark.parametrize("livepatch", ["unknown", "active-or-unreadable", "active"])
@pytest.mark.parametrize("version", ["6.12.112", "6.12.113"])
def test_livepatch_needs_cve_specific_evidence(version, livepatch):
    value = pwnescape.grade(facts(version, WORKER_PWNESCAPE_LIVEPATCH=livepatch))
    assert value["status"] == "unknown"


def test_installed_kernel_and_missing_guest_devices_do_not_clear_host():
    value = pwnescape.grade(facts(
        "6.12.112",
        WORKER_GUEST_KERNEL_INSTALLED="6.12.113",
        WORKER_KVM_DEVICE="false",
        WORKER_NESTED_ENABLED="false",
        WORKER_PWNESCAPE_TUN_PRESENT="false",
        WORKER_PWNESCAPE_VIRTIO_NET="false",
        WORKER_PWNESCAPE_USERNS_MAX="0",
    ))
    assert value["status"] == "fail"


def test_fact_parser_preserves_conflicts():
    raw = "\n".join(f"{k}={v}" for k, v in facts().items())
    raw += "\nWORKER_GUEST_KERNEL_RUNNING=6.12.112\n"
    output = subprocess.check_output(
        [sys.executable, str(WORKLOAD / "pwnescape.py")], input=raw, text=True
    )
    assert json.loads(output)["status"] == "unknown"


@pytest.mark.parametrize("version,expected", [("6.12.112", security.CRITICAL), ("6.12.113", security.PASS)])
def test_common_json_to_cli_report(version, expected):
    raw = "\n".join(f"{k}={v}" for k, v in facts(version).items())
    fragment = subprocess.check_output(
        ["bash", "-c",
         'source "$1/audit-common.sh"; build_security_advisory_json --host-facts "$2"',
         "bash", str(WORKLOAD), raw],
        text=True,
    )
    audit = {"security": json.loads("{" + fragment + '"sentinel": null}')}
    check = next(c for c in security.evaluate_security(audit) if c.id == "pwnescape")
    assert check.status == expected
    assert version in check.observed
    assert "CVE-2026-99999" in check.remediation


def test_old_audit_missing_facts_warns():
    check = next(c for c in security.evaluate_security({}) if c.id == "pwnescape")
    assert check.status == security.WARNING


def test_read_only_collector_re_roots_facts(tmp_path):
    # Invoke only the new passive function, never the whole hardware collector.
    source = (WORKLOAD / "host-check.sh").read_text()
    function = re.search(r"^collect_pwnescape_facts\(\) \{.*?^\}", source, re.M | re.S).group()
    (tmp_path / "sys/kernel/livepatch").mkdir(parents=True)
    (tmp_path / "sys/class/net/eth0/device").mkdir(parents=True)
    (tmp_path / "sys/class/net/eth0/device/driver").symlink_to("/sys/bus/virtio/drivers/virtio_net")
    (tmp_path / "dev/net").mkdir(parents=True)
    (tmp_path / "proc/sys/user").mkdir(parents=True)
    (tmp_path / "proc/sys/user/max_user_namespaces").write_text("0\n")
    env = {**os.environ, "CLUSTERMAX_AUDIT_ROOT": str(tmp_path)}
    output = subprocess.check_output(["bash", "-c", function + "\ncollect_pwnescape_facts"], env=env, text=True)
    assert "WORKER_PWNESCAPE_LIVEPATCH=none" in output
    assert "WORKER_PWNESCAPE_TUN_PRESENT=false" in output
    assert "WORKER_PWNESCAPE_VIRTIO_NET=true" in output
    assert "WORKER_PWNESCAPE_USERNS_MAX=0" in output
    (tmp_path / "sys/kernel/livepatch/fix").mkdir()
    (tmp_path / "sys/kernel/livepatch/fix/enabled").write_text("1\n")
    output = subprocess.check_output(["bash", "-c", function + "\ncollect_pwnescape_facts"], env=env, text=True)
    assert "WORKER_PWNESCAPE_LIVEPATCH=active-or-unreadable" in output


@pytest.mark.parametrize("collector", ["k8s", "common"])
@pytest.mark.parametrize("version,expected", [("6.12.112", "fail"), ("6.12.113", "pass")])
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
    value = json.loads("{" + run.stdout + '"sentinel": null}')["pwnescape"]
    assert value["runningKernel"] == version
    assert value["status"] == expected


@pytest.mark.parametrize("version,expected", [("6.12.112", "fail"), ("6.12.113", "pass")])
def test_absent_livepatch_interface_on_readable_sysfs_allows_version_verdict(tmp_path, version, expected):
    (tmp_path / "sys/kernel").mkdir(parents=True)
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_pwnescape_facts")
    run = bashtest.run_bash(
        function + "\ncollect_pwnescape_facts",
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    collected = dict(line.split("=", 1) for line in run.stdout.splitlines())
    assert collected["WORKER_PWNESCAPE_LIVEPATCH"] == "not-supported"
    assert pwnescape.grade({**facts(version), **collected})["status"] == expected


def test_missing_sysfs_and_dangling_livepatch_link_remain_unknown(tmp_path):
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_pwnescape_facts")
    for broken_link in (False, True):
        if broken_link:
            (tmp_path / "sys/kernel").mkdir(parents=True)
            (tmp_path / "sys/kernel/livepatch").symlink_to("/nonexistent-livepatch")
        run = bashtest.run_bash(
            function + "\ncollect_pwnescape_facts",
            env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
        )
        assert run.returncode == 0, run.stderr
        assert "WORKER_PWNESCAPE_LIVEPATCH=unknown" in run.stdout


def test_immediate_findings_keep_unknown_distinct_from_version_failure():
    spec = importlib.util.spec_from_file_location("pwnescape_findings", WORKLOAD / "audit_findings.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for status, severity in [("pass", None), ("fail", "VERSION"), ("unknown", "CONFIG"), ("host-version-required", "CONFIG")]:
        findings = module.detect_findings({"audit_data": {"security": {"pwnescape": {"status": status}}}})
        found = [f for f in findings if f.key == "security.pwnescape.status"]
        assert len(found) == (0 if severity is None else 1)
        if found:
            assert found[0].severity == severity


def test_security_only_collector_includes_raw_host_facts():
    block = bashtest.extract_block(
        WORKLOAD / "cluster-audit-slurm-security.sh",
        "SECURITY_ADVISORY_JSON=$(printf",
        "    | jq 'del(._end)')",
    )
    raw = "\n".join(f"{key}={value}" for key, value in facts().items())
    run = bashtest.run_bash(
        f'source "{WORKLOAD}/audit-common.sh"\n' + block + '\nprintf "%s\\n" "$SECURITY_ADVISORY_JSON"',
        env={"WORKER_CHECK_OUTPUT": raw, "JANUSCAPE_EXPOSED_JSON": '"unknown"'},
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["pwnescape"]["status"] == "pass"


@pytest.mark.parametrize("guest,expected", [("false", audit_report.PASS), ("true", audit_report.WARNING)])
def test_full_report_preserves_pwnescape_scope(guest, expected):
    value = pwnescape.grade(facts(guest=guest, technology="kvm" if guest == "true" else "none"))
    checks = audit_report.evaluate({"audit_data": {"security": {"pwnescape": value}}}, ROOT / "cmax")
    check = next(c for c in checks if c.key == "security.pwnescape.status")
    assert check.status == expected
    assert "CVE-2026-99999" in check.observed
    assert "6.12.113" in check.observed
