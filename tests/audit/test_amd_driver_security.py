"""Offline AMD host-driver cases. All host readings below are synthetic."""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import bashtest
from test_minimum_refresh import StubFetcher
from test_security_version_audit import security, unreadable_minimum_table
from cmax import minimum_refresh as fr

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"


def evidence(release="31.40"):
    return {
        "packageRelease": release,
        "packageOrigin": f"https://repo.radeon.com/amdgpu/{release}/ubuntu",
        "packageVersion": "synthetic-package-version",
        "packageBoundToModule": True,
        "loadedSrcversion": "SYNTHETIC123",
        "installedSrcversion": "SYNTHETIC123",
        "loadedVersion": "6.19.14",
        "installedVersion": "6.19.14",
    }


@pytest.fixture
def driver_block():
    return fr.amd_driver_minimums(fetch=StubFetcher())


@pytest.fixture
def fixture_policy(driver_block):
    # Pin grading tests to the frozen bulletin, not a future daily table.
    with mock.patch.object(security.minimum_versions, "component", return_value=driver_block):
        yield


def test_driver_parser_and_rocm_remain_independent(driver_block):
    assert driver_block["programs"] == dict.fromkeys(
        ("MI210", "MI250", "MI250X", "MI300A", "MI300X",
         "MI308X", "MI325X", "MI350X", "MI355X"), "31.40")
    assert driver_block["cves"] == ["CVE-2026-43603"]
    assert driver_block["source"]["released"] == "2026-09-08T00:00:00Z"
    assert driver_block["floorAvailability"]["MI355X"]["available"] == "2026-07-15T00:00:00Z"
    stub = StubFetcher()
    rocm = fr.amd_rocm_minimums(fetch=stub)
    assert all("6034" not in call for call in stub.calls)
    assert rocm["source"]["aId"] != "AMD-SB-6034"


@pytest.mark.parametrize("old,new", [
    ("Linux GPU Driver 31.40", "ROCm 31.40"),
    ("Linux GPU Driver 31.40", "Linux GPU Driver TBD"),
    ("CVE-2026-43603", "pending"),
    ("2026-07-15", "TBD"),
    ("AMD Instinct MI", "Radeon RX"),
])
def test_changed_driver_bulletin_fails_closed(old, new):
    stub = StubFetcher()
    url = fr.amd_bulletin_page("amd-sb-6034")
    stub.text_by_url[url] = stub.text_by_url[url].replace(old, new)
    with pytest.raises(fr.MinimumRefreshError):
        fr.amd_driver_minimums(fetch=stub)


def test_new_bulletin_detection_tracks_driver_separately():
    stub = StubFetcher()
    stub.text_by_url[fr.AMD_SECURITY_INDEX] = (
        "<table><tr><td>AMD-SB-6034</td><td>Linux GPU Driver</td></tr>"
        "<tr><td>AMD-SB-9999</td><td>Linux GPU Driver</td></tr></table>"
    )
    found = fr.detect_new_bulletins(fetch=stub, years=[2026])
    assert not any(item.get("id") == "amd-sb-6034" for item in found)
    assert any("9999" in str(item) for item in found)


@pytest.mark.parametrize("release,status", [
    ("31.30", "fail"), ("31.40", "pass"), ("31.40.1", "pass"), ("31.50", "pass"),
])
def test_proven_release_comparison(fixture_policy, release, status):
    result = security.amd_driver_verdict("AMD-Instinct-MI355X", evidence(release))
    assert result.status == status
    assert result.minimum == "31.40"
    assert "CVE-2026-43603" in result.detail


@pytest.mark.parametrize("field,value", [
    ("packageBoundToModule", False),
    ("packageBoundToModule", "true"),
    ("loadedSrcversion", ""),
    ("loadedSrcversion", "OLD"),
    ("loadedVersion", "old-module"),
    ("packageVersion", ""),
    ("packageOrigin", "https://repo.radeon.com.evil.test/amdgpu/31.40/ubuntu"),
    ("packageOrigin", "https://repo.radeon.com/amdgpu/31.30/ubuntu"),
    ("packageRelease", "6.19.14"),
    ("packageRelease", "ROCm 31.40"),
    ("packageRelease", "31.40-rc1"),
])
def test_unproven_or_mismatched_evidence_is_unknown(fixture_policy, field, value):
    sample = evidence()
    sample[field] = value
    assert security.amd_driver_verdict("MI300X", sample).status == "unknown"


@pytest.mark.parametrize("model", ["unknown", "MI100", "MI999X", "Radeon RX 7900"])
def test_unassessed_hardware_cannot_pass(fixture_policy, model):
    assert security.amd_driver_verdict(model, evidence()).status == "unknown"


def test_nvidia_unaffected_and_missing_amd_evidence_unknown(fixture_policy):
    assert security.amd_driver_verdict("H100", gpu_vendor="nvidia").status == "not_applicable"
    assert security.amd_driver_verdict("MI300X").status == "unknown"
    assert security.amd_driver_verdict("MI300X MI999X", evidence()).status == "unknown"
    assert security.amd_driver_verdict("MI300X MI999X", evidence("31.30")).status == "fail"


def test_missing_table_cannot_pass():
    with unreadable_minimum_table():
        assert security.amd_driver_verdict("MI300X", evidence()).status == "unknown"


def test_committed_component_contract():
    block = security.minimum_versions.component("amdDriver")
    for program, floor in block["programs"].items():
        assert security.amd_driver_verdict(program, evidence(floor)).status == "pass"
        parts = list(security.numeric_version(floor, parts=2))
        parts[-1] -= 1
        below = ".".join(map(str, parts))
        assert security.amd_driver_verdict(program, evidence(below)).status == "fail"


def test_collector_builder_preserves_json_and_no_container_driver_fallback():
    sample = evidence()
    kv = "WORKER_AMD_GPU_MODEL=AMD-Instinct-MI300X\nWORKER_AMD_DRIVER_EVIDENCE=" + json.dumps(sample)
    run = bashtest.run_bash(
        f'WORKLOAD_DIR={shlex.quote(str(WORKLOAD))}\n'
        f'source "{WORKLOAD}/audit-common.sh"\n'
        f'build_security_version_audit {shlex.quote(kv)} 99.99 unknown unknown unknown amd unknown standalone\n'
    )
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)["amdDriver"]
    assert result["status"] == "pass"
    assert result["evidence"] == sample
    assert "not fleet-wide" in result["scope"]
    run = bashtest.run_bash(
        f'WORKLOAD_DIR={shlex.quote(str(WORKLOAD))}\n'
        f'source "{WORKLOAD}/audit-common.sh"\n'
        'build_security_version_audit WORKER_AMD_GPU_MODEL=MI300X 99.99 unknown unknown unknown amd unknown standalone\n'
    )
    assert json.loads(run.stdout)["amdDriver"]["status"] == "unknown"
    mixed = kv + "\nWORKER_HOSTNAME=one\nWORKER_HOSTNAME=two"
    run = bashtest.run_bash(
        f'WORKLOAD_DIR={shlex.quote(str(WORKLOAD))}\n'
        f'source "{WORKLOAD}/audit-common.sh"\n'
        f'build_security_version_audit {shlex.quote(mixed)} 99.99 unknown unknown unknown amd unknown standalone\n'
    )
    assert json.loads(run.stdout)["amdDriver"]["status"] == "unknown"


def collect(tmp_path, *, policy=None, installed_src="SYNTHETIC123", dkms=False,
            owner=True, built_src="SYNTHETIC123"):
    root = tmp_path
    sysfs = root / "sys/module/amdgpu"
    sysfs.mkdir(parents=True)
    (sysfs / "version").write_text("6.19.14")
    (sysfs / "srcversion").write_text("SYNTHETIC123")
    module = "/lib/modules/test-kernel/updates/dkms/amdgpu.ko"
    built = root / "var/lib/dkms/amdgpu/test-version/test-kernel/x86_64/module/amdgpu.ko"
    built.parent.mkdir(parents=True)
    built.touch()
    if policy is None:
        policy = """amdgpu-dkms:
  Installed: test-version
  Candidate: newer
  Version table:
     newer 500
        500 https://repo.radeon.com/amdgpu/99.99/ubuntu noble/main amd64 Packages
 *** test-version 500
        500 https://repo.radeon.com/amdgpu/31.40/ubuntu noble/main amd64 Packages
        100 /var/lib/dpkg/status
"""
    owner_response = "amdgpu-dkms: " + ("/usr/src/amdgpu-test-version/dkms.conf" if dkms else module)
    dpkg = (
        f'if [[ "$1" == "-W" ]]; then printf "install ok installed\\ttest-version"; '
        f'elif [[ "$2" == "/usr/src/amdgpu-test-version/dkms.conf" ]]; then echo {shlex.quote(owner_response)}; '
        + ('else exit 1; fi' if dkms or not owner else f'else echo {shlex.quote(owner_response)}; fi')
    )
    if not owner:
        dpkg = "exit 1"
    stubs = {
        "modinfo": (
            'case "$2" in\n'
            'version) echo 6.19.14;;\n'
            f'srcversion) if [[ "$3" == amdgpu ]]; then echo {installed_src}; else echo {built_src}; fi;;\n'
            f'filename) echo {module};;\nesac'
        ),
        "dpkg-query": dpkg,
        "apt-cache": f"printf '%s' {shlex.quote(policy)}",
        "uname": "echo test-kernel",
        "dkms": "echo 'amdgpu/test-version, test-kernel, x86_64: installed'",
    }
    # The generic shell-function helper stops at a Python dict's closing brace.
    source = (WORKLOAD / "host-check.sh").read_text()
    collector = "collect_amd_driver_evidence() {" + source.split(
        "collect_amd_driver_evidence() {", 1
    )[1].split("\nPY\n}", 1)[0] + "\nPY\n}"
    run = bashtest.run_bash(
        collector + "\ncollect_amd_driver_evidence",
        stubs=stubs, env={"CLUSTERMAX_AUDIT_ROOT": str(root)})
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


@pytest.mark.parametrize("dkms", [False, True])
def test_host_collection_binds_installed_version_not_candidate(tmp_path, dkms):
    sample = collect(tmp_path, dkms=dkms)
    assert sample["packageRelease"] == "31.40"
    assert sample["packageBoundToModule"] is True
    assert security.amd_driver_verdict("MI300X", sample).status == "pass"


@pytest.mark.parametrize("kwargs", [
    {"installed_src": "NEW_NOT_LOADED"},
    {"owner": False},
    {"dkms": True, "built_src": "OTHER_BUILD"},
    {"policy": "*** test-version 500\n 500 https://archive.ubuntu.com/ubuntu noble/main amd64 Packages"},
    {"policy": "*** test-version 100\n 100 /var/lib/dpkg/status\n newer 500\n 500 https://repo.radeon.com/amdgpu/31.40/ubuntu noble/main amd64 Packages"},
    {"policy": "*** test-version 500\n 500 https://repo.radeon.com/amdgpu/31.40/ubuntu noble/main amd64 Packages\n 500 https://mirror.invalid/ubuntu noble/main amd64 Packages"},
])
def test_host_collection_never_binds_ambiguous_installations(tmp_path, kwargs):
    sample = collect(tmp_path, **kwargs)
    assert sample["packageBoundToModule"] is False
    assert security.amd_driver_verdict("MI300X", sample).status == "unknown"
