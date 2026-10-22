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
    assert bashtest.extract_function(
        WORKLOAD / "pwnescape-host-facts.sh", "collect_pwnescape_facts"
    ) == bashtest.extract_function(WORKLOAD / "host-check.sh", "collect_pwnescape_facts")


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
