"""Fleet coverage for the host-kernel CVEs that share passive facts."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

WORKLOAD = ROOT / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(WORKLOAD))
SPEC = importlib.util.spec_from_file_location("host_fleet", WORKLOAD / "host_fleet.py")
host_fleet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host_fleet)


def facts(version="6.8.0-140-generic", **extra):
    return {
        "WORKER_GUEST_KERNEL_RUNNING": version,
        "WORKER_VIRT_GUEST": "false",
        "WORKER_VIRT_TYPE": "none",
        "WORKER_OS_ID": "ubuntu",
        "WORKER_OS_VERSION_ID": "24.04",
        "WORKER_PWNESCAPE_LIVEPATCH": "none",
        "WORKER_FRAGNESIA_ABI": "140",
        "WORKER_FRAGNESIA_ABI_FLOOR": "136",
        "WORKER_FRAGNESIA_STATUS": "pass",
        "WORKER_NESTED_CPU_EXPOSED": "false",
        "WORKER_KVM_DEVICE": "false",
        "WORKER_NESTED_MODULE": "none",
        "WORKER_NESTED_ENABLED": "unknown",
        "WORKER_JANUSCAPE_EXPOSED": "false",
        "WORKER_JANUSCAPE_STATUS": "pass",
        **extra,
    }


def fact_text(host, **extra):
    return "\n".join(f"{key}={value}" for key, value in {"WORKER_HOSTNAME": host, **facts(**extra)}.items())


def host(node, role="worker", checked=True, **extra):
    return {
        "node": node,
        "role": role,
        "checked": checked,
        "facts": fact_text(node, **extra) if checked else "",
        "error": None if checked else "unreachable",
    }


CONTROL = {"discovered": True, "detail": "found"}


def test_clean_worker_and_control_plane_pass_the_shared_checks():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane")], CONTROL, "136"
    )
    assert value["fragnesia"]["status"] == "pass"
    assert value["januscape"]["status"] == "pass"
    assert value["januscape"]["exposed"] is False
    assert value["fragnesia"]["coverageComplete"] is True
    assert value["fragnesia"]["scope"] == "fleet"


def test_one_below_floor_fragnesia_host_fails_the_fleet():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host("gpu-2", WORKER_FRAGNESIA_ABI="135", WORKER_FRAGNESIA_STATUS="fail")],
        CONTROL,
        "136",
    )
    assert value["fragnesia"]["status"] == "fail"
    assert value["fragnesia"]["failingNodes"] == ["gpu-2"]


def test_fragnesia_grace_period_keeps_a_below_floor_host_from_failing():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane"),
         host("gpu-2", WORKER_FRAGNESIA_ABI="135", WORKER_FRAGNESIA_STATUS="fail")],
        CONTROL,
        "136",
        True,
    )
    assert value["fragnesia"]["status"] == "pass"
    assert any("grace period" in entry["reason"] for entry in value["fragnesia"]["hosts"])


def test_nested_kvm_host_exposes_januscape_and_fails_the_fleet():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host(
            "gpu-2",
            WORKER_NESTED_CPU_EXPOSED="true",
            WORKER_KVM_DEVICE="true",
            WORKER_NESTED_MODULE="kvm_amd",
            WORKER_NESTED_ENABLED="true",
            WORKER_JANUSCAPE_EXPOSED="true",
            WORKER_JANUSCAPE_STATUS="fail",
        )], CONTROL, "136"
    )
    assert value["januscape"]["status"] == "fail"
    assert value["januscape"]["exposed"] is True
    assert value["januscape"]["failingNodes"] == ["gpu-2"]


def test_unread_host_and_hidden_control_plane_block_every_pass():
    value = host_fleet.grade_fleet([host("gpu-1"), host("gpu-2", checked=False)], CONTROL, "136")
    assert value["fragnesia"]["status"] == "coverage-incomplete"
    assert value["januscape"]["status"] == "coverage-incomplete"
    assert value["januscape"]["exposed"] == "unknown"
    assert value["fragnesia"]["unassessedNodes"] == ["gpu-2"]


def test_control_plane_absence_blocks_the_fleet():
    value = host_fleet.grade_fleet([host("gpu-1")], {"discovered": False}, "136")
    assert value["fragnesia"]["status"] == "coverage-incomplete"
    assert value["januscape"]["status"] == "coverage-incomplete"
    assert "control-plane" in value["fragnesia"]["reason"]


def test_host_fact_script_reports_the_shared_facts(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/cpuinfo").write_text("flags : fpu svm\n")
    (tmp_path / "proc/sys/user").mkdir(parents=True)
    (tmp_path / "proc/sys/user/max_user_namespaces").write_text("1000\n")
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/kvm").touch()
    (tmp_path / "sys/kernel").mkdir(parents=True)
    (tmp_path / "sys/module/kvm_amd/parameters").mkdir(parents=True)
    (tmp_path / "sys/module/kvm_amd/parameters/nested").write_text("1\n")
    run = bashtest.run_bash(
        f'bash "{WORKLOAD}/pwnescape-host-facts.sh"',
        stubs={"uname": "echo 6.8.0-140-generic", "hostname": "echo gpu-1", "systemd-detect-virt": "echo none"},
        env={
            "CLUSTERMAX_AUDIT_ROOT": str(tmp_path),
            "CLUSTERMAX_FRAGNESIA_ABI_MINIMUM": "136",
        },
    )
    assert run.returncode == 0, run.stderr
    collected = dict(line.split("=", 1) for line in run.stdout.splitlines())
    assert collected["WORKER_FRAGNESIA_STATUS"] == "pass"
    assert collected["WORKER_NESTED_ENABLED"] == "true"
    assert collected["WORKER_JANUSCAPE_EXPOSED"] == "true"
    graded = host_fleet.grade_fleet(
        [{"node": "gpu-1", "role": "worker", "checked": True,
          "facts": run.stdout},
         {"node": "cp-1", "role": "control-plane", "checked": True,
          "facts": run.stdout}],
        CONTROL,
        "136",
    )
    assert graded["fragnesia"]["status"] == "pass"
    assert graded["januscape"]["status"] == "fail"


def test_unresolved_fragnesia_verdict_names_the_missing_evidence():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane", WORKER_FRAGNESIA_STATUS="unknown")],
        CONTROL,
        "136",
    )
    assert value["fragnesia"]["status"] == "unknown"
    assert "unresolved Fragnesia verdict" in value["fragnesia"]["reason"]
    assert "cp-1" in value["fragnesia"]["reason"]
    assert "Every audited host" not in value["fragnesia"]["reason"]


def test_unresolved_januscape_verdict_names_the_missing_evidence():
    value = host_fleet.grade_fleet(
        [host("gpu-1"), host("cp-1", "control-plane", WORKER_JANUSCAPE_EXPOSED="unknown")],
        CONTROL,
        "136",
    )
    assert value["januscape"]["status"] == "unknown"
    assert "unresolved Januscape verdict" in value["januscape"]["reason"]
    assert "cp-1" in value["januscape"]["reason"]
    assert "No audited host exposes" not in value["januscape"]["reason"]


def test_collector_wires_the_fleet_grader_into_the_security_advisory():
    source = (WORKLOAD / "cluster-audit-slurm-security.sh").read_text()
    assert "apply_host_fleet" in source
    assert 'python3 "$WORKLOAD_DIR/host_fleet.py"' in source
    assert ".pwnescape = $fleet.pwnescape" in source
    assert ".fragnesia = ((.fragnesia // {})" in source


def test_login_host_read_carries_the_fragnesia_floor():
    collector = WORKLOAD / "cluster-audit-slurm-security.sh"
    script = (
        "minimum_version() { echo 136; }\n"
        "minimum_version_grace() { echo false; }\n"
        "print_info() { :; }\n"
        + bashtest.extract_function(collector, "add_pwnescape_host_record")
        + bashtest.extract_function(collector, "slurm_control_hosts")
        + bashtest.extract_function(collector, "collect_slurm_pwnescape_fleet")
        + "\ncollect_slurm_pwnescape_fleet\n"
        'printf \'%s\\n\' "$PWNESCAPE_HOST_RECORDS"\n'
    )
    run = bashtest.run_bash(
        script,
        stubs={
            "sinfo": ":",  # no compute rows
            "scontrol": ":",  # no control hosts reported
            "hostname": "echo audit-login",
        },
        env={
            "WORKLOAD_DIR": str(WORKLOAD),
            "CLUSTERMAX_AUDIT_PWNESCAPE_CONCURRENCY": "1",
        },
    )
    assert run.returncode == 0, run.stderr
    record = run.stdout.splitlines()[0]
    import json

    entry = json.loads(record)
    assert entry["node"] == "audit-login"
    assert entry["checked"] is True
    # The login-host read must receive the published floor, so its on-host
    # comparison never guesses a minimum.
    assert "WORKER_FRAGNESIA_ABI_FLOOR=136" in entry["facts"]
