"""Offline fixtures for the passive PwnEscape collector and report path."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from cmax import audit_report, security


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/audit"))
import bashtest


WORKLOAD = ROOT / "cmax/scripts/1-audit"
sys.path.insert(0, str(WORKLOAD))
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


def ubuntu_facts(release="24.04", abi=139, upload=None, signed=False):
    family = "7.0.0" if release == "26.04" else "6.8.0"
    version = f"{family}-{abi}.{upload or abi}"
    source = "linux-hwe-6.8" if release == "22.04" else "linux"
    if release == "22.04":
        version += "~22.04.1"
    if signed:
        source = source.replace("linux", "linux-signed", 1)
    return facts(
        f"{family}-{abi}-generic",
        WORKER_OS_ID="ubuntu",
        WORKER_OS_VERSION_ID=release,
        WORKER_PWNESCAPE_SIGNATURE=f"Ubuntu {version}-generic 6.8.12",
        WORKER_PWNESCAPE_PACKAGE=f"ii |{source}|{version}",
    )


@pytest.fixture(autouse=True)
def ubuntu_minimums(tmp_path, monkeypatch):
    # Frozen vendor states, independent of daily refreshes. Released fixes in
    # boundary tests below are synthetic, not a claim of fix availability.
    data = {"schemaVersion": 1, "components": {
        component: {"packages": {"linuxPwnescape": {
            "cve": pwnescape.CVE, "package": package, "status": state, "fixed": fixed,
        }}}
        for component, package, state, fixed in (
            ("ubuntuNoble", "linux", "pending", "6.8.0-149.149i1"),
            ("ubuntuResolute", "linux", "pending", "7.0.0-43.43i1"),
            ("ubuntuJammy", "linux-hwe-6.8", "needed", ""),
        )
    }}
    path = tmp_path / "minimums.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(path))
    monkeypatch.setattr(pwnescape.minimum_versions, "_CACHE", None)
    yield path, data
    pwnescape.minimum_versions._CACHE = None


@pytest.mark.parametrize("release,abi", [("24.04", 139), ("26.04", 14), ("22.04", 138)])
@pytest.mark.parametrize("signed", [False, True])
def test_verified_ubuntu_running_image_uses_vendor_affected_status(release, abi, signed):
    result = pwnescape.grade(ubuntu_facts(release, abi, signed=signed))
    assert result["status"] == result["localKernelStatus"] == "fail"
    assert result["vendorStatus"] == ("needed" if release == "22.04" else "pending")
    assert result["minimum"] == "unknown"
    assert "no fixed package has been released" in result["reason"]
    assert result["exploitTested"] is False


@pytest.mark.parametrize("release,abi", [("24.04", 149), ("26.04", 43)])
def test_pending_build_is_not_a_released_minimum(release, abi):
    value = pwnescape.grade(ubuntu_facts(release, abi))
    assert value["status"] == "fail"
    assert value["minimum"] == "unknown"


@pytest.mark.parametrize("release,component,fixed,abi", [
    ("24.04", "ubuntuNoble", "6.8.0-150.151", 150),
    ("26.04", "ubuntuResolute", "7.0.0-44.45", 44),
    ("22.04", "ubuntuJammy", "6.8.0-150.151~22.04.1", 150),
])
@pytest.mark.parametrize("delta,upload_delta,expected", [(-1, 0, "fail"), (0, -1, "fail"), (0, 0, "pass"), (1, 1, "pass")])
def test_released_vendor_fix_boundaries(ubuntu_minimums, release, component, fixed, abi, delta, upload_delta, expected):
    path, data = ubuntu_minimums
    data["components"][component]["packages"]["linuxPwnescape"].update(status="released", fixed=fixed)
    path.write_text(json.dumps(data))
    fixed_upload = 45 if release == "26.04" else 151
    value = pwnescape.grade(ubuntu_facts(release, abi + delta, fixed_upload + upload_delta))
    assert value["status"] == expected
    assert value["minimum"] == fixed


@pytest.mark.parametrize("change", [
    {"WORKER_OS_ID": "debian"},
    {"WORKER_OS_VERSION_ID": "26.04"},
    {"WORKER_GUEST_KERNEL_RUNNING": "6.8.0-139-aws"},
    {"WORKER_PWNESCAPE_SIGNATURE": "unknown"},
    {"WORKER_PWNESCAPE_SIGNATURE": "Ubuntu 6.8.0-138.138-generic 6.8.12"},
    {"WORKER_PWNESCAPE_SIGNATURE": "Ubuntu 6.8.0-139.139-generic"},
    {"WORKER_PWNESCAPE_PACKAGE": "unknown"},
    {"WORKER_PWNESCAPE_PACKAGE": "rc |linux|6.8.0-139.139"},
    {"WORKER_PWNESCAPE_PACKAGE": "hiR|linux|6.8.0-139.139"},
    {"WORKER_PWNESCAPE_PACKAGE": "ii |linux-aws|6.8.0-139.139"},
    {"WORKER_PWNESCAPE_PACKAGE": "ii |linux|6.8.0-140.140"},
    {"WORKER_PWNESCAPE_PACKAGE": "ii |linux|6.8.0-139.139+custom"},
])
def test_ubuntu_identity_mismatches_remain_unknown(change):
    assert pwnescape.grade(ubuntu_facts() | change)["status"] == "unknown"


@pytest.mark.parametrize("state", ["hi ", "ri ", "pi ", "ui "])
def test_installed_selection_is_not_installation_state(state):
    value = ubuntu_facts()
    value["WORKER_PWNESCAPE_PACKAGE"] = value["WORKER_PWNESCAPE_PACKAGE"].replace("ii ", state)
    assert pwnescape.grade(value)["status"] == "fail"


@pytest.mark.parametrize("change", [
    {"cve": "CVE-2026-46242"}, {"package": "linux-aws"},
    {"status": "needs-triage"}, {"status": "ignored"}, {"status": "DNE"},
    {"status": ["released"]}, {"status": None},
    {"status": "released", "fixed": ""},
    {"status": "released", "fixed": "7.0.0-44.44"},
    {"status": "released", "fixed": "6.8.0-149.149i1"},
])
def test_unknown_or_invalid_vendor_records_cannot_grade(ubuntu_minimums, change):
    path, data = ubuntu_minimums
    data["components"]["ubuntuNoble"]["packages"]["linuxPwnescape"].update(change)
    path.write_text(json.dumps(data))
    assert pwnescape.grade(ubuntu_facts())["status"] == "unknown"


def test_missing_and_unreadable_vendor_data_remain_unknown(ubuntu_minimums):
    path, data = ubuntu_minimums
    del data["components"]["ubuntuNoble"]["packages"]["linuxPwnescape"]
    path.write_text(json.dumps(data))
    assert pwnescape.grade(ubuntu_facts())["status"] == "unknown"
    pwnescape.minimum_versions._CACHE = None
    path.write_text("not JSON")
    assert pwnescape.grade(ubuntu_facts())["status"] == "unknown"


@pytest.mark.parametrize("livepatch", ["active", "unknown", "active-or-unreadable"])
def test_ubuntu_livepatch_cannot_prove_fixed_or_vulnerable(livepatch):
    value = pwnescape.grade(ubuntu_facts() | {"WORKER_PWNESCAPE_LIVEPATCH": livepatch})
    assert value["status"] == "unknown"
    assert "CVE-specific evidence" in value["reason"]


def test_ubuntu_guest_reports_local_failure_without_certifying_outer_host():
    value = pwnescape.grade(ubuntu_facts() | {"WORKER_VIRT_GUEST": "true", "WORKER_VIRT_TYPE": "kvm"})
    assert value["status"] == "host-version-required"
    assert value["localKernelStatus"] == "fail"


@pytest.mark.parametrize("version,expected", [
    ("6.8.12", "fail"), ("7.0.14", "fail"), ("6.17.13", "fail"),
    ("7.3.0", "pass"), ("7.3.1", "pass"), ("7.4.0", "pass"),
    ("2.6.26", "unknown"),
])
def test_cna_default_affected_and_mainline_fix(version, expected):
    assert pwnescape.grade(facts(version))["status"] == expected


def test_ubuntu_signature_base_version_is_not_upstream_patch_evidence():
    value = ubuntu_facts()
    value["WORKER_PWNESCAPE_SIGNATURE"] = "Ubuntu 6.8.0-139.139-generic 6.12.113"
    assert pwnescape.grade(value)["status"] == "fail"


def test_ubuntu_collector_to_grader_to_report(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version_signature").write_text("Ubuntu 6.8.0-139.139-generic 6.8.12\n")
    (tmp_path / "sys/kernel").mkdir(parents=True)
    run = bashtest.run_bash(
        f'bash "{WORKLOAD}/pwnescape-host-facts.sh"',
        stubs={
            "uname": "echo 6.8.0-139-generic",
            "systemd-detect-virt": "echo none; exit 1",
            "dpkg-query": "printf 'ii |linux-signed|6.8.0-139.139'",
        },
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    assert run.calls("dpkg-query")[0][-1] == "linux-image-6.8.0-139-generic"
    output = subprocess.check_output(
        [sys.executable, str(WORKLOAD / "pwnescape.py")], input=run.stdout, text=True,
    )
    value = json.loads(output)
    assert value["status"] == "fail"
    check = next(c for c in security.evaluate_security({"security": {"pwnescape": value}}) if c.id == "pwnescape")
    assert check.status == security.CRITICAL
    assert "vendor=pending" in check.observed


def test_vendor_failure_and_evidence_survive_fleet_aggregation():
    raw = "\n".join(f"{k}={v}" for k, v in ubuntu_facts().items())
    value = pwnescape.grade_fleet(
        [host("cp-1", "control-plane"), {"node": "gpu-ubuntu", "checked": True, "facts": raw}],
        CONTROL_FOUND,
    )
    assert value["status"] == "fail"
    assert value["failingNodes"] == ["gpu-ubuntu"]
    assert value["vendorStatus"] == "pending"
    entry = next(e for e in value["hosts"] if e["node"] == "gpu-ubuntu")
    assert entry["osId"] == "ubuntu"
    assert entry["packageEvidence"] == ubuntu_facts()["WORKER_PWNESCAPE_PACKAGE"]
    assert "no fixed package has been released" in value["reason"]


@pytest.mark.parametrize("minimum", pwnescape.FIXED_RELEASES.values())
def test_each_upstream_branch_boundary(minimum):
    major, minor, patch = map(int, minimum.split("."))
    assert pwnescape.grade(facts(minimum))["status"] == "pass"
    older = f"{major}.{minor}.{patch - 1}"
    assert pwnescape.grade(facts(older))["status"] == "fail"
    newer = f"{major}.{minor}.{patch + 1}"
    assert pwnescape.grade(facts(newer))["status"] == "pass"


VENDOR_KERNEL = {
    "WORKER_GUEST_KERNEL_RUNNING": "6.17.0-1021-nvidia-64k",
    "WORKER_VIRT_GUEST": "false",
    "WORKER_VIRT_TYPE": "none",
    "WORKER_PWNESCAPE_LIVEPATCH": "none",
    "WORKER_KERNEL_DISTRIBUTION": "ubuntu 24.04",
    "WORKER_KERNEL_VERSION_SIGNATURE": "Ubuntu 6.17.0-1021.21-nvidia-64k 6.17.13",
    "WORKER_KERNEL_SOURCE_PACKAGE": "linux-signed-nvidia-6.17 6.17.0-1021.21",
}


def test_vendor_kernel_asks_for_evidence_instead_of_guessing_a_verdict():
    value = pwnescape.grade(VENDOR_KERNEL)
    assert value["status"] == "unknown"
    assert value["exploitTested"] is False
    # The report must name the exact facts a provider has to send: it must not
    # imply a pass, and it must not imply that the kernel lacks the fix.
    assert "neither a pass nor a fail" in value["reason"]
    assert "unverified" in value["reason"]
    assert "not unpatched" in value["reason"]
    for expected in (
        "6.17.0-1021-nvidia-64k", "nvidia-64k", "1021",
        "linux-signed-nvidia-6.17 6.17.0-1021.21", pwnescape.FIX_COMMIT, "livepatch",
    ):
        assert expected in value["reason"]
    assert value["kernelDistribution"] == "ubuntu 24.04"
    assert value["kernelFlavor"] == "nvidia-64k"
    assert value["kernelAbi"] == "1021"
    assert value["kernelSourcePackage"] == "linux-signed-nvidia-6.17 6.17.0-1021.21"
    assert value["minimum"] == "unknown"
    for evidence in ("distribution", "kernel flavor", "kernel ABI", "source package version", "fix commit", "livepatch"):
        assert any(evidence in item for item in value["providerEvidence"])


def test_generic_kernel_does_not_request_vendor_evidence():
    value = pwnescape.grade(facts("6.8.0-147-generic"))
    assert "kernelFlavor" not in value
    assert "providerEvidence" not in value


@pytest.mark.parametrize(
    "version",
    [
        "6.12.113-custom", "6.12.114+", "6.8.0-106-generic",
        "6.12.113-aws", "5.14.0-503.el9.x86_64", "7.3-rc7",
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
    function = bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_pwnescape_facts")
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


@pytest.mark.parametrize("collector", ["k8s", "common", "security"])
@pytest.mark.parametrize("version,expected", [("6.12.112", "fail"), ("6.12.113", "pass")])
def test_collectors_feed_their_actual_host_facts(collector, version, expected):
    if collector == "security":
        target = "SECURITY_ADVISORY_JSON"
        raw_variable = "WORKER_CHECK_OUTPUT"
        call = bashtest.extract_block(
            WORKLOAD / "cluster-audit-slurm-security.sh",
            "SECURITY_ADVISORY_JSON=$(printf",
            "    | jq 'del(._end)')",
        )
    elif collector == "k8s":
        script = WORKLOAD / "cluster-audit-k8s.sh"
        target = "SECURITY_ADVISORY_JSON"
        raw_variable = "HOST_CHECK_OUT"
        end = '--vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")'
    else:
        script = WORKLOAD / "audit-common.sh"
        target = "security_advisory_json"
        raw_variable = "WORKER_CHECK_OUTPUT"
        end = '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")'
    if collector != "security":
        call = bashtest.extract_block(script, target + "=$(build_security_advisory_json \\", end)
    raw = "\n".join(f"{key}={value}" for key, value in facts(version).items())
    run = bashtest.run_bash(
        f'source "{WORKLOAD}/audit-common.sh"\n' + call + f'\nprintf "%s\\n" "${target}"',
        env={
            raw_variable: raw,
            "HP_JANUSCAPE_EXPOSED_JSON": '"unknown"',
            "januscape_exposed_json": '"unknown"',
            "JANUSCAPE_EXPOSED_JSON": '"unknown"',
        },
    )
    assert run.returncode == 0, run.stderr
    payload = run.stdout if collector == "security" else "{" + run.stdout + '"sentinel": null}'
    value = json.loads(payload)["pwnescape"]
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


@pytest.mark.parametrize("guest,expected", [("false", audit_report.PASS), ("true", audit_report.WARNING)])
def test_full_report_preserves_pwnescape_scope(guest, expected):
    value = pwnescape.grade(facts(guest=guest, technology="kvm" if guest == "true" else "none"))
    checks = audit_report.evaluate({"audit_data": {"security": {"pwnescape": value}}}, ROOT / "cmax")
    check = next(c for c in checks if c.key == "security.pwnescape.status")
    assert check.status == expected
    assert "CVE-2026-99999" in check.observed
    assert "6.12.113" in check.observed


# --- Fleet coverage: every worker and control-plane host -------------------

SECURITY_SCRIPT = WORKLOAD / "cluster-audit-slurm-security.sh"
FLEET_HELPERS = ("add_pwnescape_host_record", "apply_pwnescape_fleet")


def fact_text(version="6.12.113", host="node"):
    return "\n".join(
        f"{key}={value}"
        for key, value in {"WORKER_HOSTNAME": host, **facts(version)}.items()
    )


def host(node, role="worker", version="6.12.113", checked=True):
    return {
        "node": node,
        "role": role,
        "checked": checked,
        "facts": fact_text(version, node) if checked else "",
        "error": None if checked else "unreachable",
    }


CONTROL_FOUND = {"discovered": True, "detail": "found"}


def test_host_fact_script_shares_the_host_check_collector():
    for name in ("collect_pwnescape_facts", "collect_kernel_identity_facts"):
        assert bashtest.extract_function(
            WORKLOAD / "pwnescape-host-facts.sh", name
        ) == bashtest.extract_function(WORKLOAD / "host-check.sh", name)


def test_kernel_identity_collector_reads_the_vendor_build_record(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version_signature").write_text(
        "Ubuntu 6.17.0-1021.21-nvidia-64k 6.17.13\n"
    )
    function = bashtest.extract_function(
        WORKLOAD / "pwnescape-host-facts.sh", "collect_kernel_identity_facts"
    )
    run = bashtest.run_bash(
        function + "\ncollect_kernel_identity_facts",
        stubs={
            "uname": '[[ "$1" == "-r" ]] && echo 6.17.0-1021-nvidia-64k',
            "dpkg-query": 'echo "linux-signed-nvidia-6.17 6.17.0-1021.21"',
        },
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    collected = dict(line.split("=", 1) for line in run.stdout.splitlines())
    assert collected["WORKER_KERNEL_DISTRIBUTION"] == "ubuntu 24.04"
    assert collected["WORKER_KERNEL_VERSION_SIGNATURE"] == (
        "Ubuntu 6.17.0-1021.21-nvidia-64k 6.17.13"
    )
    assert collected["WORKER_KERNEL_FLAVOR"] == "nvidia-64k"
    assert collected["WORKER_KERNEL_ABI"] == "1021"
    assert collected["WORKER_KERNEL_SOURCE_PACKAGE"] == (
        "linux-signed-nvidia-6.17 6.17.0-1021.21"
    )


def test_guest_kernel_unknown_inventory_names_the_missing_evidence():
    grade, observed, assessment = security._guest_kernel(
        {"security": {"guestKernel": {
            "running": "6.17.0-1021-nvidia-64k",
            "newestInstalled": "unknown",
        }}}
    )
    assert grade == security.WARNING
    assert "nvidia-64k" in assessment and "ABI 1021" in assessment
    assert "dpkg-query" in assessment
    assert "/proc/version_signature" in assessment


@pytest.mark.parametrize(
    "stub,cpuinfo,virt_type,guest",
    [
        ("echo kvm; exit 0", "", "kvm", "true"),
        ("echo none; exit 1", "", "none", "false"),
        # A failed reading is not bare metal; only the hypervisor flag can decide.
        ("exit 2", "flags : fpu hypervisor\n", "unknown", "true"),
        ("exit 2", "flags : fpu\n", "unknown", "unknown"),
    ],
)
def test_host_fact_script_classifies_virtualization(tmp_path, stub, cpuinfo, virt_type, guest):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/cpuinfo").write_text(cpuinfo)
    run = bashtest.run_bash(
        f'bash "{WORKLOAD}/pwnescape-host-facts.sh"',
        stubs={"systemd-detect-virt": stub},
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    collected = dict(line.split("=", 1) for line in run.stdout.splitlines())
    assert collected["WORKER_GUEST_KERNEL_RUNNING"] not in {"", "unknown"}
    assert collected["WORKER_VIRT_TYPE"] == virt_type
    assert collected["WORKER_VIRT_GUEST"] == guest


def test_fleet_passes_only_when_every_worker_and_control_plane_host_passes():
    value = pwnescape.grade_fleet(
        [host("gpu-1"), host("gpu-2"), host("cp-1", "control-plane")], CONTROL_FOUND
    )
    assert value["status"] == "pass"
    assert value["coverageComplete"] is True
    assert value["nodesChecked"] == value["nodesTotal"] == 3
    assert value["controlPlane"]["hosts"] == ["cp-1"]


@pytest.mark.parametrize("role", ["worker", "control-plane", "login"])
def test_one_unpatched_host_fails_the_fleet(role):
    value = pwnescape.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane"), host("bad", role, "6.12.112")],
        CONTROL_FOUND,
    )
    assert value["status"] == "fail"
    assert value["failingNodes"] == ["bad"]
    assert value["runningKernel"] == "6.12.112"
    assert "bad" in value["reason"]


def test_failure_outranks_an_incomplete_fleet():
    value = pwnescape.grade_fleet(
        [host("gpu-1", version="6.12.112"), host("gpu-2", checked=False)], {"discovered": False}
    )
    assert value["status"] == "fail"
    assert value["unassessedNodes"] == ["gpu-2"]


@pytest.mark.parametrize(
    "hosts,control",
    [
        ([host("gpu-1"), host("gpu-2", checked=False), host("cp-1", "control-plane")], CONTROL_FOUND),
        ([host("gpu-1"), host("cp-1", "control-plane", checked=False)], CONTROL_FOUND),
        ([host("gpu-1")], {"discovered": False, "detail": "Managed control plane."}),
        ([host("gpu-1")], CONTROL_FOUND),
        ([], CONTROL_FOUND),
    ],
)
def test_unread_hosts_and_hidden_control_planes_block_a_pass(hosts, control):
    value = pwnescape.grade_fleet(hosts, control)
    assert value["status"] == "coverage-incomplete"
    assert value["coverageComplete"] is False
    assert "evidence" in value["reason"]


def test_partial_fact_block_is_unassessed_not_graded():
    partial = {**host("gpu-1"), "facts": "WORKER_HOSTNAME=gpu-1\n"}
    value = pwnescape.grade_fleet([partial, host("cp-1", "control-plane")], CONTROL_FOUND)
    assert value["status"] == "coverage-incomplete"
    assert value["unassessedNodes"] == ["gpu-1"]


def test_distribution_kernels_across_a_complete_fleet_need_vendor_evidence():
    value = pwnescape.grade_fleet(
        [host("gpu-1", version="6.8.0-106-generic"), host("cp-1", "control-plane")], CONTROL_FOUND
    )
    assert value["status"] == "unknown"
    assert value["runningKernels"] == ["6.12.113", "6.8.0-106-generic"]
    assert "gpu-1" in value["reason"]


def test_vendor_kernel_reaches_the_common_report_observation():
    raw = "\n".join(
        f"{key}={item}"
        for key, item in facts(
            version="6.17.0-1021-nvidia-64k",
            WORKER_KERNEL_DISTRIBUTION="ubuntu 24.04",
            WORKER_KERNEL_SOURCE_PACKAGE="linux-signed-nvidia-6.17 6.17.0-1021.21",
        ).items()
    )
    fragment = subprocess.check_output(
        ["bash", "-c",
         'source "$1/audit-common.sh"; build_security_advisory_json --host-facts "$2"',
         "bash", str(WORKLOAD), raw],
        text=True,
    )
    audit = {"security": json.loads("{" + fragment + '"sentinel": null}')}
    check = next(c for c in security.evaluate_security(audit) if c.id == "pwnescape")
    assert check.status == security.WARNING
    for expected in ("flavor=nvidia-64k", "abi=1021", "linux-signed-nvidia-6.17"):
        assert expected in check.observed


def test_fleet_cli_reads_the_collector_document():
    document = {"hosts": [host("gpu-1", version="6.12.112")], "controlPlane": CONTROL_FOUND}
    output = subprocess.check_output(
        [sys.executable, str(WORKLOAD / "pwnescape.py"), "--fleet"],
        input=json.dumps(document), text=True,
    )
    assert json.loads(output)["status"] == "fail"


K8S_NODES = {
    "items": [
        {"metadata": {"name": "cp-1", "labels": {"node-role.kubernetes.io/control-plane": ""}}},
        {"metadata": {"name": "gpu-1", "labels": {}}},
        {"metadata": {"name": "gpu-2", "labels": {}}},
        {"metadata": {"name": "broken", "labels": {}}},
    ]
}


def run_k8s_fleet(nodes, bad_kernel_node=""):
    workers = [
        item for item in nodes["items"]
        if "node-role.kubernetes.io/control-plane" not in item["metadata"]["labels"]
    ]
    functions = "\n".join(
        bashtest.extract_function(SECURITY_SCRIPT, name)
        for name in (*FLEET_HELPERS, "k8s_pwnescape_record_for_current_pod",
                     "k8s_node_role", "k8s_bmc_unchecked_record", "collect_k8s_host_fleet")
    )
    script = (
        'print_info() { :; }\ncleanup_k8s_security_pod() { :; }\n'
        'create_k8s_security_pod() { K8S_SECURITY_NODE="$1"; [[ "$1" != broken ]]; }\n'
        'k8s_bmc_record_for_current_pod() { printf \'{"node":"%s","checked":true,"exposed":false}\' "$1"; }\n'
        'run_k8s_security_script() {\n  cat >/dev/null\n'
        '  kernel=6.12.113; [[ "$K8S_SECURITY_NODE" == "$BAD_NODE" ]] && kernel=6.12.112\n'
        '  printf "WORKER_HOSTNAME=%s\\nWORKER_GUEST_KERNEL_RUNNING=%s\\nWORKER_VIRT_GUEST=false\\n'
        'WORKER_VIRT_TYPE=none\\nWORKER_PWNESCAPE_LIVEPATCH=none\\n" "$K8S_SECURITY_NODE" "$kernel"\n}\n'
        + functions
        + 'K8S_SECURITY_NODE=gpu-1\nPWNESCAPE_HOST_RECORDS=""\n'
        'SECURITY_ADVISORY_JSON=\'{"pwnescape": {"status": "pass", "scope": "sampled-worker"}}\'\n'
        'collect_k8s_host_fleet\napply_pwnescape_fleet\n'
        'printf "%s\\n" "$K8S_BMC_IPMI_JSON" "$SECURITY_ADVISORY_JSON" | jq -cs .\n'
    )
    run = bashtest.run_bash(script, env={
        "WORKLOAD_DIR": str(WORKLOAD),
        "K8S_SECURITY_NODES_JSON": json.dumps(nodes),
        "K8S_SECURITY_WORKER_NODES_JSON": json.dumps(workers or nodes["items"]),
        "BAD_NODE": bad_kernel_node,
    })
    assert run.returncode == 0, run.stderr
    bmc, advisory = json.loads(run.stdout)
    return bmc, advisory["pwnescape"]


def test_k8s_reads_every_node_including_the_control_plane():
    bmc, value = run_k8s_fleet(K8S_NODES)
    roles = {entry["node"]: (entry["role"], entry["checked"]) for entry in value["hosts"]}
    assert roles == {
        "gpu-1": ("worker", True),
        "cp-1": ("control-plane", True),
        "gpu-2": ("worker", True),
        "broken": ("worker", False),
    }
    assert value["scope"] == "fleet"
    assert value["status"] == "coverage-incomplete"
    assert value["unassessedNodes"] == ["broken"]
    # The BMC probe keeps its worker-only scope.
    assert [entry["node"] for entry in bmc["hosts"]] == ["gpu-1", "gpu-2", "broken"]


def test_k8s_control_plane_kernel_failure_fails_the_check():
    _, value = run_k8s_fleet(K8S_NODES, bad_kernel_node="cp-1")
    assert value["status"] == "fail"
    assert value["failingNodes"] == ["cp-1"]


def test_k8s_managed_control_plane_never_passes():
    nodes = {"items": [item for item in K8S_NODES["items"] if item["metadata"]["name"] in {"gpu-1", "gpu-2"}]}
    _, value = run_k8s_fleet(nodes)
    assert value["nodesChecked"] == 2
    assert value["controlPlane"]["discovered"] is False
    assert value["status"] == "coverage-incomplete"
    assert "managed control plane" in value["reason"]


def run_slurm_fleet(tmp_path, ssh_body="exit 255", bad_node=""):
    facts_script = (
        'kernel=6.12.113; [[ "$(hostname)" == "$BAD_NODE" ]] && kernel=6.12.112\n'
        'printf "WORKER_HOSTNAME=%s\\nWORKER_GUEST_KERNEL_RUNNING=%s\\nWORKER_VIRT_GUEST=false\\n'
        'WORKER_VIRT_TYPE=none\\nWORKER_PWNESCAPE_LIVEPATCH=none\\n" "$(hostname)" "$kernel"\n'
    )
    workload = tmp_path / "workload"
    workload.mkdir()
    (workload / "pwnescape-host-facts.sh").write_text(facts_script)
    (workload / "pwnescape.py").symlink_to(WORKLOAD / "pwnescape.py")
    (workload / "minimum_versions.py").symlink_to(WORKLOAD / "minimum_versions.py")
    remote = (
        'cat >/dev/null\nkernel=6.12.113; [[ "$NODE" == "$BAD_NODE" ]] && kernel=6.12.112\n'
        'printf "WORKER_HOSTNAME=%s\\nWORKER_GUEST_KERNEL_RUNNING=%s\\nWORKER_VIRT_GUEST=false\\n'
        'WORKER_VIRT_TYPE=none\\nWORKER_PWNESCAPE_LIVEPATCH=none\\n" "$NODE" "$kernel"\n'
    )
    functions = "\n".join(
        bashtest.extract_function(SECURITY_SCRIPT, name)
        for name in (*FLEET_HELPERS, "slurm_control_hosts",
                     "slurm_pwnescape_facts_on_node", "collect_slurm_pwnescape_fleet")
    )
    run = bashtest.run_bash(
        'print_info() { :; }\nAUDIT_SRUN_FLAGS=()\n' + functions
        + 'PWNESCAPE_HOST_RECORDS=""\n'
        'SECURITY_ADVISORY_JSON=\'{"pwnescape": {"status": "pass", "scope": "sampled-worker"}}\'\n'
        'collect_slurm_pwnescape_fleet\napply_pwnescape_fleet\n'
        'jq -c .pwnescape <<< "$SECURITY_ADVISORY_JSON"\n',
        stubs={
            "hostname": "echo login-1",
            "sinfo": "printf 'gpu-1|gpu*\\ngpu-2|gpu\\ngpu-1|debug\\n'",
            "scontrol": (
                "printf 'SlurmctldHost[0]        = ctl-1(10.0.0.1)\\n"
                "AccountingStorageHost   = gpu-2\\nClusterName = test\\n'"
            ),
            "srun": 'while [[ $# -gt 0 && "$1" != -w ]]; do shift; done\nNODE="$2"\n' + remote,
            "ssh": 'NODE=ctl-1\n' + ssh_body,
        },
        # One worker at a time keeps the stub call logs from interleaving.
        env={
            "WORKLOAD_DIR": str(workload), "BAD_NODE": bad_node, "SLURM_JOB_ID": "",
            "CLUSTERMAX_AUDIT_PWNESCAPE_CONCURRENCY": "1",
        },
    )
    assert run.returncode == 0, run.stderr
    return run, json.loads(run.stdout)


def test_slurm_reads_compute_login_and_controller_hosts(tmp_path):
    run, value = run_slurm_fleet(tmp_path)
    roles = sorted((entry["node"], entry["role"], entry["checked"]) for entry in value["hosts"])
    assert roles == [
        ("ctl-1", "control-plane", False),
        ("gpu-1", "worker", True),
        ("gpu-2", "control-plane", True),
        ("gpu-2", "worker", True),
        ("login-1", "login", True),
    ]
    assert value["status"] == "coverage-incomplete"
    assert value["unassessedNodes"] == ["ctl-1"]
    srun_calls = run.calls("srun")
    assert sorted(call[call.index("-w") + 1] for call in srun_calls) == ["gpu-1", "gpu-2"]
    assert all("--immediate=30" in call for call in srun_calls)
    for call in srun_calls:
        # The first listed partition wins, with the default marker removed.
        assert call[call.index("-p") + 1] == "gpu"
    assert "BatchMode=yes" in run.calls("ssh")[0]


def test_slurm_fleet_passes_when_ssh_reaches_the_controller(tmp_path):
    _, value = run_slurm_fleet(tmp_path, ssh_body=bashtest.exec_from("bash").replace(
        'exec "$@"', 'cat >/dev/null; printf "WORKER_HOSTNAME=ctl-1\\nWORKER_GUEST_KERNEL_RUNNING=6.12.113\\n'
        'WORKER_VIRT_GUEST=false\\nWORKER_VIRT_TYPE=none\\nWORKER_PWNESCAPE_LIVEPATCH=none\\n"'))
    assert value["status"] == "pass"
    assert value["controlPlane"]["coverageComplete"] is True


def test_slurm_unpatched_compute_node_fails(tmp_path):
    _, value = run_slurm_fleet(tmp_path, bad_node="gpu-1")
    assert value["status"] == "fail"
    assert value["failingNodes"] == ["gpu-1"]


def test_fleet_report_names_failing_and_unread_hosts():
    value = pwnescape.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane", "6.12.112"), host("gpu-2", checked=False)],
        CONTROL_FOUND,
    )
    check = next(c for c in security.evaluate_security({"security": {"pwnescape": value}}) if c.id == "pwnescape")
    assert check.status == security.CRITICAL
    assert "hosts checked 2/3" in check.observed
    assert "control plane checked 1/1" in check.observed
    assert "failing cp-1" in check.observed
    assert "unassessed gpu-2" in check.observed
    checks = audit_report.evaluate({"audit_data": {"security": {"pwnescape": value}}}, ROOT / "cmax")
    report = next(c for c in checks if c.key == "security.pwnescape.status")
    assert report.status == audit_report.FAIL
    assert "failing cp-1" in report.observed


def test_coverage_incomplete_report_requests_provider_evidence():
    value = {"status": "coverage-incomplete", "controlPlaneVisible": False}
    checks = audit_report.evaluate({"audit_data": {"security": {"pwnescape": value}}}, ROOT / "cmax")
    report = next(c for c in checks if c.key == "security.pwnescape.status")
    assert report.status == audit_report.WARNING
    assert "not a pass" in report.assessment
    assert "control-plane" in report.recommendation
    assert "Correct the reported configuration" not in report.recommendation
