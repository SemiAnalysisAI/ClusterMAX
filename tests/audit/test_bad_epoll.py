"""Offline Bad Epoll checks: no cluster contact and no exploit execution."""

import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from cmax import audit_report, security

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"
sys.path.insert(0, str(WORKLOAD))
spec = importlib.util.spec_from_file_location("bad_epoll", WORKLOAD / "bad_epoll.py")
bad_epoll = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bad_epoll)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


def table():
    # Frozen fixtures, deliberately independent of daily minimum refreshes.
    return {"schemaVersion": 1, "components": {
        component: {"packages": {"linuxBadEpoll": {
            "cve": "CVE-2026-46242", "package": package,
            "fixed": fixed, "status": "released",
        }}}
        for component, package, fixed in (
            ("ubuntuNoble", "linux", "6.8.0-137.137"),
            ("ubuntuJammy", "linux-hwe-6.8", "6.8.0-138.138~22.04.1"),
        )
    }}


def facts(abi=137, release="24.04", upload=None):
    version = f"6.8.0-{abi}.{upload or abi}"
    source = "linux"
    if release == "22.04":
        version += "~22.04.1"
        source = "linux-hwe-6.8"
    return dict(
        os_id="ubuntu", release=release, running=f"6.8.0-{abi}-generic",
        signature=f"Ubuntu {version}-generic 6.8.12",
        package=f"ii |{source}|{version}", livepatch="none",
    )


@pytest.fixture(autouse=True)
def minimums(tmp_path, monkeypatch):
    path = tmp_path / "minimums.json"
    path.write_text(json.dumps(table()))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(path))
    bad_epoll.minimum_versions._CACHE = None
    yield path
    bad_epoll.minimum_versions._CACHE = None


@pytest.mark.parametrize("abi,expected", [
    (117, "fail"), (124, "fail"), (136, "fail"), (137, "pass"), (138, "pass"),
])
def test_noble_boundaries(abi, expected):
    assert bad_epoll.evaluate(**facts(abi))["status"] == expected


@pytest.mark.parametrize("abi,expected", [(137, "fail"), (138, "pass"), (139, "pass")])
def test_jammy_hwe_uses_its_own_minimum(abi, expected):
    assert bad_epoll.evaluate(**facts(abi, "22.04"))["status"] == expected


@pytest.mark.parametrize("change", [
    {"os_id": "debian"}, {"release": "26.04"}, {"release": "unknown"},
    {"running": "6.8.0-1062-aws"}, {"running": "6.8.0-1064-azure"},
    {"running": "6.8.0-137-nvidia"}, {"running": "6.8.0-137-custom"},
    {"running": "6.17.0-42-generic"}, {"running": "unknown"},
    {"signature": "unknown"}, {"signature": "Ubuntu 6.8.0-136.136-generic 6.8.12"},
    {"package": "unknown"}, {"package": "rc |linux|6.8.0-137.137"},
    {"package": "ii |custom-linux|6.8.0-137.137"},
    {"package": "ii |linux|6.8.0-137.137+custom"},
    {"livepatch": "active"}, {"livepatch": "unknown"},
])
def test_unverifiable_evidence_never_passes(change):
    assert bad_epoll.evaluate(**(facts() | change))["status"] == "unknown"


def test_signed_distribution_package():
    data = facts()
    data["package"] = data["package"].replace("|linux|", "|linux-signed|")
    assert bad_epoll.evaluate(**data)["status"] == "pass"


@pytest.mark.parametrize("selection", ["h", "r", "p", "u"])
@pytest.mark.parametrize("abi,expected", [(136, "fail"), (138, "pass")])
def test_installed_packages_are_graded_regardless_of_selection(selection, abi, expected):
    data = facts(abi)
    data["package"] = data["package"].replace("ii ", f"{selection}i ", 1)
    assert bad_epoll.evaluate(**data)["status"] == expected


def test_package_error_flag_remains_unverified():
    data = facts()
    data["package"] = data["package"].replace("ii ", "hiR", 1)
    assert bad_epoll.evaluate(**data)["status"] == "unknown"


def test_newer_package_with_same_abi_is_not_running():
    data = facts()
    data["package"] = "ii |linux|6.8.0-137.138"
    assert bad_epoll.evaluate(**data)["status"] == "unknown"


@pytest.mark.parametrize("broken", ["missing", "invalid", "removed", "wrong-cve", "wrong-source"])
def test_bad_minimums_fail_closed(minimums, broken):
    doc = table()
    if broken == "missing":
        minimums.unlink()
    elif broken == "invalid":
        minimums.write_text("{")
    else:
        entry = doc["components"]["ubuntuNoble"]["packages"]["linuxBadEpoll"]
        if broken == "removed":
            doc["components"] = {}
        elif broken == "wrong-cve":
            entry["cve"] = "CVE-other"
        else:
            entry["package"] = "linux-aws"
        minimums.write_text(json.dumps(doc))
    assert bad_epoll.evaluate(**facts())["status"] == "unknown"


def test_minimum_is_read_from_table(minimums):
    doc = table()
    doc["components"]["ubuntuNoble"]["packages"]["linuxBadEpoll"]["fixed"] = "6.8.0-200.200"
    minimums.write_text(json.dumps(doc))
    assert bad_epoll.evaluate(**facts(138))["status"] == "fail"


@pytest.mark.parametrize("state,expected", [("pass", "PASS"), ("fail", "FAIL"), ("unknown", "WARNING")])
def test_full_and_security_report_share_one_result(state, expected):
    record = bad_epoll.evaluate(**facts())
    record["status"] = state
    values = {"audit_data": {"security": {"badEpoll": record}}}
    root = security.find_runtime_root()
    checks = audit_report.evaluate(values, root)
    matches = [check for check in checks if check.key == "security.badEpoll.status"]
    assert len(matches) == 1
    assert matches[0].status.upper() == expected
    assert "CVE-2026-46242" in matches[0].observed
    from cmax.audit_profiles import profile_includes
    assert profile_includes("security", "security.badEpoll.status")
    legacy = next(c for c in security.evaluate_security(values) if c.id == "bad-epoll")
    assert legacy.status == {
        "pass": security.PASS, "fail": security.CRITICAL, "unknown": security.WARNING,
    }[state]


def test_installed_update_does_not_override_running_failure():
    record = bad_epoll.evaluate(**facts(136))
    values = {"security": {
        "badEpoll": record,
        "guestKernel": {"running": "6.8.0-136-generic",
                        "newestInstalled": "6.8.0-137-generic", "newerInstalled": True},
    }}
    checks = audit_report.evaluate(values, security.find_runtime_root())
    result = next(c for c in checks if c.key == "security.badEpoll.status")
    assert result.status == audit_report.FAIL


@pytest.mark.parametrize("collector", ["common", "k8s", "security"])
def test_real_collector_argument_wiring(collector):
    data = facts(136)
    worker = {
        "WORKER_OS_ID": data["os_id"], "WORKER_OS_VERSION_ID": data["release"],
        "WORKER_GUEST_KERNEL_RUNNING": data["running"],
        "WORKER_BAD_EPOLL_SIGNATURE": data["signature"],
        "WORKER_BAD_EPOLL_PACKAGE": data["package"],
        "WORKER_BAD_EPOLL_LIVEPATCH": data["livepatch"],
    }
    if collector == "k8s":
        names = ["HP_BAD_EPOLL_OS", "HP_BAD_EPOLL_RELEASE", "HP_GUEST_KERNEL_RUNNING",
                 "HP_BAD_EPOLL_SIGNATURE", "HP_BAD_EPOLL_PACKAGE", "HP_BAD_EPOLL_LIVEPATCH"]
        worker = dict(zip(names, worker.values()))
        call = bashtest.extract_block(
            WORKLOAD / "cluster-audit-k8s.sh",
            "SECURITY_ADVISORY_JSON=$(build_security_advisory_json \\",
            '--vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")',
        )
        output = 'printf "{%s \\"end\\":null}" "$SECURITY_ADVISORY_JSON"'
    elif collector == "security":
        call = bashtest.extract_block(
            WORKLOAD / "cluster-audit-slurm-security.sh",
            "SECURITY_ADVISORY_JSON=$(printf",
            '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")"',
        ) + ")\n"
        output = 'printf "%s" "$SECURITY_ADVISORY_JSON"'
    else:
        call = bashtest.extract_block(
            WORKLOAD / "audit-common.sh",
            "security_advisory_json=$(build_security_advisory_json \\",
            '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")',
        )
        output = 'printf "{%s \\"end\\":null}" "$security_advisory_json"'
    setup = "\n".join(f"{key}={shlex.quote(value)}" for key, value in worker.items())
    setup += '\njanuscape_exposed_json=false\nHP_JANUSCAPE_EXPOSED_JSON=false\nJANUSCAPE_EXPOSED_JSON=false\n'
    command = f'source "{WORKLOAD}/audit-common.sh"\n{setup}\n{call}\n{output}'
    run = subprocess.run(["bash", "-c", command], text=True, capture_output=True)
    assert run.returncode == 0, run.stderr
    record = json.loads(run.stdout)["badEpoll"]
    assert record["status"] == "fail"
    assert record["running"] == data["running"]


@pytest.mark.parametrize("patch_state,expected", [
    ("empty", "none"), ("0", "none"), ("1", "active"),
    ("unreadable", "unknown"), ("absent", "unknown"),
])
def test_host_probe_queries_exact_running_image(tmp_path, patch_state, expected):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "version_signature").write_text("Ubuntu 6.8.0-136.136-generic 6.8.12\n")
    livepatch = tmp_path / "sys/kernel/livepatch"
    if patch_state != "absent":
        livepatch.mkdir(parents=True)
    if patch_state not in {"empty", "absent"}:
        (livepatch / "test-patch").mkdir()
        if patch_state != "unreadable":
            (livepatch / "test-patch/enabled").write_text(patch_state)
    block = bashtest.extract_block(
        WORKLOAD / "host-check.sh", "# Bad Epoll identity evidence.",
        "# End Bad Epoll identity evidence.",
    )
    run = bashtest.run_bash(
        'WORKER_GUEST_KERNEL_RUNNING=6.8.0-136-generic\n'
        'dpkg-query() { [[ "${@: -1}" == linux-image-6.8.0-136-generic ]] || return 1; '
        'printf "ii |linux|6.8.0-136.136"; }\n' + block,
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    assert run.returncode == 0, run.stderr
    assert "WORKER_BAD_EPOLL_PACKAGE=ii |linux|6.8.0-136.136" in run.stdout
    assert f"WORKER_BAD_EPOLL_LIVEPATCH={expected}" in run.stdout


def test_missing_grader_produces_unknown(tmp_path):
    run = subprocess.run(
        ["bash", "-c",
         f'source "{WORKLOAD}/audit-common.sh"\n'
         f'AUDIT_COMMON_DIR={shlex.quote(str(tmp_path))}\n'
         'result=$(build_security_advisory_json)\n'
         'printf "{%s \\"end\\":null}" "$result"'],
        capture_output=True, text=True,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["badEpoll"]["status"] == "unknown"
