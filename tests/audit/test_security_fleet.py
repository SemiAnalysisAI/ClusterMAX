"""Fleet verdicts for host-level security checks."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from cmax import audit_report

ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = ROOT / "cmax/scripts/1-audit"
SPEC = importlib.util.spec_from_file_location("security_fleet", WORKLOAD / "security_fleet.py")
fleet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleet)


def _cx(status, *devices):
    return {
        "status": status,
        "minimum": "43.8002",
        "devices": [{"device": d, "version": v, "status": s} for d, v, s in devices],
    }


def _host(node, versions=None, security=None):
    return {
        "node": node,
        "checked": True,
        "securityVersions": versions or {},
        "security": security or {},
    }


def test_one_failing_host_fails_the_fleet_even_when_the_sample_passes():
    sampled = {"nvidiaDriver": {"status": "pass", "version": "580.200.01", "detail": "ok"}}
    payload = {
        "sampled": {"securityVersions": sampled, "security": {}},
        "hostsTotal": 2,
        "hosts": [
            _host("gpu-a", {"nvidiaDriver": {"status": "pass", "version": "580.200.01", "detail": "ok"}}),
            _host("gpu-b", {"nvidiaDriver": {"status": "fail", "version": "580.10.01", "detail": "below"}}),
        ],
    }
    driver = fleet.merge(payload)["securityVersions"]["nvidiaDriver"]
    assert driver["status"] == "fail"
    assert driver["version"] == "580.10.01"
    assert driver["detail"] == "gpu-b: below"
    assert driver["fleet"]["worstHost"] == "gpu-b"
    assert driver["fleet"]["coverageComplete"] is True
    assert [h["node"] for h in driver["fleet"]["hosts"]] == ["gpu-a", "gpu-b"]


def test_connectx_devices_keep_their_host():
    payload = {
        "sampled": {"securityVersions": {"connectxFirmware": _cx("pass")}, "security": {}},
        "hostsTotal": 2,
        "hosts": [
            _host("gpu-a", {"connectxFirmware": _cx("pass", ("rail0", "28.47.1000", "pass"))}),
            _host("gpu-b", {"connectxFirmware": _cx("fail", ("rail0", "28.43.1000", "fail"))}),
        ],
    }
    cx = fleet.merge(payload)["securityVersions"]["connectxFirmware"]
    assert cx["status"] == "fail"
    assert [d["device"] for d in cx["devices"]] == ["gpu-a/rail0", "gpu-b/rail0"]
    assert [d["host"] for d in cx["devices"]] == ["gpu-a", "gpu-b"]


def test_single_host_keeps_device_names_and_detail():
    payload = {
        "sampled": {"securityVersions": {}, "security": {}},
        "hostsTotal": 1,
        "hosts": [_host("gpu-a", {
            "connectxFirmware": _cx("pass", ("rail0", "28.47.1000", "pass")),
            "runc": {"status": "pass", "detail": "ok"},
        })],
    }
    merged = fleet.merge(payload)["securityVersions"]
    assert merged["connectxFirmware"]["devices"][0]["device"] == "rail0"
    assert merged["runc"]["detail"] == "ok"


def test_unread_host_blocks_a_pass():
    payload = {
        "sampled": {"securityVersions": {}, "security": {}},
        "hostsTotal": 2,
        "hosts": [
            _host("gpu-a", {"runc": {"status": "pass", "version": "1.3.6", "detail": "ok"}}),
            {"node": "gpu-b", "checked": False, "error": "pod could not be created"},
        ],
    }
    runc = fleet.merge(payload)["securityVersions"]["runc"]
    assert runc["status"] == "unknown"
    assert "1 of 2 GPU hosts" in runc["detail"]
    assert runc["fleet"]["unassessedHosts"] == ["gpu-b"]
    assert runc["fleet"]["coverageComplete"] is False


def test_unread_host_does_not_hide_a_failure():
    payload = {
        "sampled": {"securityVersions": {}, "security": {}},
        "hostsTotal": 3,
        "hosts": [
            _host("gpu-a", {"runc": {"status": "fail", "detail": "below"}}),
            {"node": "gpu-b", "checked": False, "error": "busy"},
        ],
    }
    runc = fleet.merge(payload)["securityVersions"]["runc"]
    assert runc["status"] == "fail"
    # One host was never listed at all; it still counts as unread.
    assert runc["fleet"]["hostsTotal"] == 3
    assert runc["fleet"]["coverageComplete"] is False


def test_unknown_vocabulary_ranks_as_unknown_not_pass():
    assert fleet.rank("some-new-word") == fleet.rank("unknown")
    assert fleet.rank("fail") > fleet.rank("some-new-word") > fleet.rank("pass")
    assert fleet.rank("host-patch-required") == fleet.rank("fail")
    assert fleet.rank("not-applicable") < fleet.rank("pass")


def test_kernel_advisories_take_the_worst_host():
    payload = {
        "sampled": {"securityVersions": {}, "security": {"badEpoll": {"status": "pass"}}},
        "hostsTotal": 2,
        "hosts": [
            _host("gpu-a", security={"badEpoll": {"status": "pass"}, "januscape": {"status": "not-exposed"}}),
            _host("gpu-b", security={"badEpoll": {"status": "fail"}, "januscape": {"status": "host-patch-required"}}),
        ],
    }
    security = fleet.merge(payload)["security"]
    assert security["badEpoll"]["status"] == "fail"
    assert security["januscape"]["status"] == "host-patch-required"


def test_cluster_level_checks_are_left_alone():
    sampled = {
        "dcgmExporter": {"status": "pass"},
        "virtioNetBluefield": {"status": "unknown"},
        "dpuHostIsolation": {"status": "fail"},
    }
    payload = {
        "sampled": {"securityVersions": sampled, "security": {"pwnescape": {"status": "fail"}}},
        "hostsTotal": 1,
        "hosts": [_host(
            "gpu-a",
            {"dcgmExporter": {"status": "fail"}, "dpuHostIsolation": {"status": "unknown"}},
            {"pwnescape": {"status": "pass"}},
        )],
    }
    merged = fleet.merge(payload)
    assert merged["securityVersions"]["dcgmExporter"] == {"status": "pass"}
    assert merged["securityVersions"]["virtioNetBluefield"] == {"status": "unknown"}
    # DPU host isolation comes from the fabric-wide virtio-net check, which the
    # per-host grade skips, so a per-host "unknown" must not replace the fail.
    assert merged["securityVersions"]["dpuHostIsolation"] == {"status": "fail"}
    assert merged["security"]["pwnescape"] == {"status": "fail"}


def test_no_host_records_keep_the_sampled_verdict():
    sampled = {"nvidiaDriver": {"status": "pass"}}
    merged = fleet.merge({"sampled": {"securityVersions": sampled, "security": {}}, "hosts": []})
    assert merged["securityVersions"] == sampled


def test_command_line_round_trip():
    payload = {
        "sampled": {"securityVersions": {}, "security": {}},
        "hostsTotal": 1,
        "hosts": [_host("gpu-a", {"runc": {"status": "pass"}})],
    }
    out = subprocess.run(
        [sys.executable, str(WORKLOAD / "security_fleet.py")],
        input=json.dumps(payload), capture_output=True, text=True, check=True,
    )
    assert json.loads(out.stdout)["securityVersions"]["runc"]["status"] == "pass"
    bad = subprocess.run(
        [sys.executable, str(WORKLOAD / "security_fleet.py")],
        input="not json", capture_output=True, text=True,
    )
    assert bad.returncode == 1


def test_report_shows_the_failing_host():
    merged = fleet.merge({
        "sampled": {"securityVersions": {}, "security": {}},
        "hostsTotal": 2,
        "hosts": [
            _host("gpu-a", {"connectxFirmware": _cx("pass", ("rail0", "28.47.1000", "pass"))}),
            _host("gpu-b", {"connectxFirmware": _cx("fail", ("rail0", "28.43.1000", "fail"))}),
        ],
    })
    checks = audit_report.evaluate(
        {"audit_data": {"securityVersions": merged["securityVersions"]}}, ROOT / "cmax"
    )
    report = next(c for c in checks if c.key == "securityVersions.connectxFirmware.status")
    assert report.status == audit_report.FAIL
    assert "gpu-b/rail0" in report.observed


# --- Collector plumbing -----------------------------------------------------

sys.path.insert(0, str(ROOT / "tests/audit"))
import bashtest  # noqa: E402

SECURITY_SCRIPT = WORKLOAD / "cluster-audit-slurm-security.sh"
HELPERS = (
    "security_host_record", "add_security_host_record", "apply_security_host_fleet",
    "add_pwnescape_host_record", "k8s_pwnescape_record_for_current_pod",
    "k8s_label_driver", "k8s_security_host_record_for_current_pod",
    "k8s_node_role", "k8s_bmc_unchecked_record", "collect_k8s_host_fleet",
)
# Grade the driver from the version each host reports, and record which
# driver each call received so the test can see per-host isolation.
STUBS = r'''
print_info() { :; }
cleanup_k8s_security_pod() { :; }
json_int() { printf '%s' "${1:-0}"; }
json_bool_or_unknown() { printf '"unknown"'; }
amd_gpu_check_present() { return 1; }
create_k8s_security_pod() { K8S_SECURITY_NODE="$1"; [[ "$1" != broken ]]; }
k8s_bmc_record_for_current_pod() { printf '{"node":"%s","checked":true,"exposed":false}' "$1"; }
run_k8s_security_script() {
  local script; script=$(cat)
  case "$script" in
    "$(cat "$WORKLOAD_DIR/container-check.sh")") printf 'WORKER_CONTAINER_HOSTNAME=%s\nWORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6\n' "$K8S_SECURITY_NODE" ;;
    "$(cat "$WORKLOAD_DIR/pwnescape-host-facts.sh")") printf 'WORKER_HOSTNAME=%s\nWORKER_GUEST_KERNEL_RUNNING=6.12.113\n' "$K8S_SECURITY_NODE" ;;
    *)
      driver=580.200.01; [[ "$K8S_SECURITY_NODE" == "$BAD_NODE" ]] && driver=580.10.01
      [[ "$K8S_SECURITY_NODE" == nodriver ]] && driver=unknown
      printf 'WORKER_HOSTNAME=%s\nWORKER_DRIVER_VERSION=%s\n' "$K8S_SECURITY_NODE" "$driver" ;;
  esac
}
build_security_version_audit() {
  local status=pass; [[ "$2" == 580.10.01 || "$2" == unknown ]] && status=fail
  printf '{"nvidiaDriver":{"status":"%s","version":"%s","detail":"d"},"runc":{"status":"pass","version":"%s"}}' "$status" "$2" "$4"
}
build_security_advisory_json() { printf '"badEpoll": {"status": "pass"},'; }
'''


def _k8s_nodes(*names, cpu=()):
    items = [
        {"metadata": {"name": n, "labels": {
            "nvidia.com/cuda.driver.major": "580", "nvidia.com/cuda.driver.minor": "200",
            "nvidia.com/cuda.driver.rev": "01"}},
         "status": {"capacity": {"nvidia.com/gpu": "8"}}}
        for n in names
    ] + [{"metadata": {"name": n, "labels": {}}, "status": {"capacity": {}}} for n in cpu]
    return {"items": items}


def run_k8s(nodes, sampled_out, bad_node="", limit="32"):
    functions = "\n".join(bashtest.extract_function(SECURITY_SCRIPT, n) for n in HELPERS)
    gpu = [i["metadata"]["name"] for i in nodes["items"] if i["status"]["capacity"]]
    script = (
        STUBS + functions
        + '\nK8S_SECURITY_NODE=gpu-1\nPWNESCAPE_HOST_RECORDS=""\nSECURITY_HOST_RECORDS=""\n'
        + "K8S_SECURITY_GPU_NODES=$'\\n'" + '"$GPU_NODES"' + "$'\\n'\n"
        + 'SECURITY_VERSION_AUDIT_JSON=\'{"nvidiaDriver":{"status":"pass"},"dcgmExporter":{"status":"pass"}}\'\n'
        + 'SECURITY_ADVISORY_JSON=\'{"badEpoll":{"status":"pass"}}\'\n'
        + 'collect_k8s_host_fleet\napply_security_host_fleet\n'
        + 'jq -cn --argjson v "$SECURITY_VERSION_AUDIT_JSON" --argjson s "$SECURITY_ADVISORY_JSON" \'{v:$v,s:$s}\'\n'
        + 'printf "WORKER_SAMPLED=%s\\n" "${WORKER_DRIVER_VERSION:-unset}"\n'
    )
    run = bashtest.run_bash(script, env={
        "WORKLOAD_DIR": str(WORKLOAD),
        "K8S_SECURITY_NODES_JSON": json.dumps(nodes),
        "K8S_SECURITY_WORKER_NODES_JSON": json.dumps(nodes["items"]),
        "GPU_NODES": "\n".join(gpu),
        "BAD_NODE": bad_node,
        "WORKER_CHECK_OUTPUT": sampled_out,
        "WORKER_DRIVER_VERSION": "580.200.01",
        "CONTAINER_CHECK_OUTPUT": "WORKER_CONTAINER_HOSTNAME=gpu-1\nWORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6\n",
        "K8S_SECURITY_DRIVER_VERSION": "580.200.01",
        "SECURITY_HOST_LIMIT": limit,
    })
    assert run.returncode == 0, run.stderr
    lines = run.stdout.strip().splitlines()
    return json.loads(lines[-2]), lines[-1]


SAMPLED = "WORKER_HOSTNAME=gpu-1\nWORKER_DRIVER_VERSION=580.200.01\n"


def test_k8s_reads_every_gpu_node_and_fails_on_the_unsampled_one():
    out, sampled_after = run_k8s(_k8s_nodes("gpu-1", "gpu-2", "gpu-3", cpu=("cpu-1",)), SAMPLED, bad_node="gpu-3")
    driver = out["v"]["nvidiaDriver"]
    assert driver["status"] == "fail"
    assert driver["fleet"]["worstHost"] == "gpu-3"
    assert [h["node"] for h in driver["fleet"]["hosts"]] == ["gpu-1", "gpu-2", "gpu-3"]
    assert driver["fleet"]["coverageComplete"] is True
    # A CPU node is not a GPU host, and cluster-level checks stay as built.
    assert out["v"]["dcgmExporter"] == {"status": "pass"}
    assert out["v"]["runc"]["fleet"]["hostsChecked"] == 3
    assert out["s"]["badEpoll"]["fleet"]["hostsChecked"] == 3
    # Grading other hosts never overwrites the sampled worker's values.
    assert sampled_after == "WORKER_SAMPLED=580.200.01"


def test_k8s_unreachable_gpu_node_blocks_a_pass():
    out, _ = run_k8s(_k8s_nodes("gpu-1", "broken"), SAMPLED)
    driver = out["v"]["nvidiaDriver"]
    assert driver["status"] == "unknown"
    assert driver["fleet"]["unassessedHosts"] == ["broken"]


def test_k8s_host_limit_leaves_the_rest_unassessed():
    out, _ = run_k8s(_k8s_nodes("gpu-1", "gpu-2", "gpu-3"), SAMPLED, limit="2")
    driver = out["v"]["nvidiaDriver"]
    assert driver["fleet"]["hostsChecked"] == 2
    assert driver["fleet"]["unassessedHosts"] == ["gpu-3"]
    assert driver["status"] == "unknown"


def test_k8s_node_label_driver_fills_an_unread_driver():
    out, _ = run_k8s(_k8s_nodes("gpu-1", "nodriver"), SAMPLED)
    versions = {h["node"]: h.get("version") for h in out["v"]["nvidiaDriver"]["fleet"]["hosts"]}
    assert versions == {"gpu-1": "580.200.01", "nodriver": "580.200.01"}


SLURM_HELPERS = (
    "security_host_record", "add_security_host_record", "apply_security_host_fleet",
    "slurm_security_script_on_node", "collect_slurm_security_host_fleet",
)


def run_slurm(tmp_path, bad_node="", busy_node=""):
    workload = tmp_path / "workload"
    workload.mkdir()
    (workload / "security_fleet.py").symlink_to(WORKLOAD / "security_fleet.py")
    (workload / "host-check.sh").write_text("HOST_CHECK\n")
    (workload / "container-check.sh").write_text("CONTAINER_CHECK\n")
    functions = "\n".join(bashtest.extract_function(SECURITY_SCRIPT, n) for n in SLURM_HELPERS)
    srun = (
        'while [[ $# -gt 0 && "$1" != -w ]]; do shift; done\nNODE="$2"\n'
        '[[ "$NODE" == "$BUSY_NODE" ]] && exit 1\n'
        'script=$(cat)\n'
        'if [[ "$script" == CONTAINER_CHECK ]]; then\n'
        '  printf "WORKER_CONTAINER_HOSTNAME=%s\\nWORKER_CONTAINER_SECURITY_RUNC_VERSION=1.3.6\\n" "$NODE"\n'
        'else\n'
        '  d=580.200.01; [[ "$NODE" == "$BAD_NODE" ]] && d=580.10.01\n'
        '  printf "WORKER_HOSTNAME=%s\\nWORKER_DRIVER_VERSION=%s\\n" "$NODE" "$d"\n'
        'fi\n'
    )
    run = bashtest.run_bash(
        STUBS + 'AUDIT_SRUN_FLAGS=()\n' + functions
        + '\nSECURITY_HOST_RECORDS=""\nSECURITY_HOST_LIMIT=32\n'
        + 'SECURITY_VERSION_AUDIT_JSON=\'{"nvidiaDriver":{"status":"pass"}}\'\n'
        + 'SECURITY_ADVISORY_JSON=\'{}\'\n'
        + 'collect_slurm_security_host_fleet\napply_security_host_fleet\n'
        + 'printf "%s\\n" "$SECURITY_VERSION_AUDIT_JSON"\n',
        stubs={
            "sinfo": "printf 'gpu-1|gpu*|gpu:h100:8\\ngpu-2|gpu|gpu:h100:8\\ngpu-1|debug|gpu:h100:8\\ncpu-1|cpu|(null)\\ngpu-3|gpu|gpu:8\\n'",
            "scontrol": "true",
            "srun": srun,
        },
        env={
            "WORKLOAD_DIR": str(workload), "SLURM_JOB_ID": "", "BAD_NODE": bad_node,
            "BUSY_NODE": busy_node, "WORKER_HOSTNAME": "gpu-1",
            "WORKER_CHECK_OUTPUT": SAMPLED,
            "CLUSTERMAX_AUDIT_SECURITY_CONCURRENCY": "1",
        },
    )
    assert run.returncode == 0, run.stderr
    return run, json.loads(run.stdout.strip().splitlines()[-1])


def test_slurm_reads_every_gpu_node_but_not_the_sampled_one_twice(tmp_path):
    run, versions = run_slurm(tmp_path, bad_node="gpu-3")
    driver = versions["nvidiaDriver"]
    assert driver["status"] == "fail"
    assert driver["fleet"]["worstHost"] == "gpu-3"
    assert sorted(h["node"] for h in driver["fleet"]["hosts"]) == ["gpu-1", "gpu-2", "gpu-3"]
    calls = run.calls("srun")
    # The sampled worker is reused, CPU nodes are skipped, and each other GPU
    # node gets one host check and one container check with a GPU and a bound.
    assert sorted(c[c.index("-w") + 1] for c in calls) == ["gpu-2", "gpu-2", "gpu-3", "gpu-3"]
    assert all("--gres=gpu:1" in c and "--immediate=30" in c for c in calls)


def test_slurm_busy_gpu_node_blocks_a_pass(tmp_path):
    _, versions = run_slurm(tmp_path, busy_node="gpu-2")
    driver = versions["nvidiaDriver"]
    assert driver["status"] == "unknown"
    assert driver["fleet"]["unassessedHosts"] == ["gpu-2"]
