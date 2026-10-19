"""Offline AMD host-driver cases. All host readings below are synthetic."""
from __future__ import annotations

import json
import shlex
import sys
from datetime import date
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


@pytest.mark.parametrize("model", ["MI300X", "MI300X MI999X", "MI300X MI355X"])
def test_serialized_below_minimum_stays_failed_after_grace(fixture_policy, model):
    real_grace = security.minimum_versions.active_grace_period
    with mock.patch.object(
        security.minimum_versions, "active_grace_period",
        side_effect=lambda *a, **kw: real_grace(*a, **kw, today=date(2026, 9, 25)),
    ):
        result = security.evaluate(
            driver="unknown", nct="unknown", runc="unknown", connectx_firmware=[],
            gpu_vendor="amd", amd_model=model, amd_driver_evidence=evidence("31.30"),
        )["amdDriver"]
    assert result["status"] == "fail"
    assert "gracePeriod" not in result


@pytest.mark.parametrize("day,status", [(8, "pass"), (11, "pass"), (12, "fail")])
def test_program_grace_uses_bulletin_date_and_expires(fixture_policy, day, status):
    real_grace = security.minimum_versions.active_grace_period
    with mock.patch.object(
        security.minimum_versions, "active_grace_period",
        side_effect=lambda *a, **kw: real_grace(*a, **kw, today=date(2026, 9, day)),
    ):
        result = security.amd_driver_record("MI300X", evidence("31.30"), gpu_vendor="amd")
    assert result["status"] == status
    if status == "pass":
        assert result["gracePeriod"]["enforcementDate"] == "2026-09-12"


def test_new_fix_for_one_product_cannot_hide_an_enforced_failure(driver_block):
    driver_block["floorAvailability"]["MI355X"]["available"] = "2026-09-25T00:00:00Z"
    real_grace = security.minimum_versions.active_grace_period
    with mock.patch.object(security.minimum_versions, "component", return_value=driver_block):
        with mock.patch.object(
            security.minimum_versions, "active_grace_period",
            side_effect=lambda *a, **kw: real_grace(*a, **kw, today=date(2026, 9, 25)),
        ):
            result = security.amd_driver_record(
                "MI300X MI355X", evidence("31.30"), gpu_vendor="amd")
    assert result["status"] == "fail"


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
            owner=True, built_src="SYNTHETIC123",
            dkms_status="amdgpu/test-version, test-kernel, x86_64: installed"):
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
        "dkms": f"printf '%s\\n' {shlex.quote(dkms_status)}",
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


@pytest.mark.parametrize("suffix", [
    "", " (original_module exists)",
    " (WARNING! Diff between built and installed module!)",
    " (original_module exists) (WARNING! Diff between built and installed module!)",
])
def test_dkms_installed_annotations_keep_fingerprint_binding(tmp_path, suffix):
    sample = collect(
        tmp_path, dkms=True,
        dkms_status="amdgpu/test-version, test-kernel, x86_64: installed" + suffix)
    assert sample["packageBoundToModule"] is True
    assert security.amd_driver_verdict("MI300X", sample).status == "pass"


@pytest.mark.parametrize("kwargs", [
    {"dkms_status": "amdgpu/test-version, other-kernel, x86_64: installed (original_module exists)"},
    {"dkms_status": "amdgpu/test-version, test-kernel, other-arch: installed (original_module exists)"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: built"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: added"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: installed-but-broken"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: not installed"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: installed (original_module exists)",
     "built_src": "OTHER_BUILD"},
    {"dkms_status": "amdgpu/test-version, test-kernel, x86_64: installed (original_module exists)",
     "owner": False},
])
def test_dkms_annotations_do_not_bypass_binding_checks(tmp_path, kwargs):
    sample = collect(tmp_path, dkms=True, **kwargs)
    assert sample["packageBoundToModule"] is False


def detect_model(tmp_path, devices, *, pci_output="", pci_exit=0, cli=None):
    for index, (vendor, device_class, product) in enumerate(devices):
        device = tmp_path / f"sys/bus/pci/devices/0000:{index:02x}:00.0"
        device.mkdir(parents=True)
        (device / "vendor").write_text(vendor)
        (device / "class").write_text(device_class)
        if product is not None:
            (device / "product_name").write_text(product)
    source = (WORKLOAD / "host-check.sh").read_text()
    # Execute the real model emission path with both CLIs genuinely absent.
    block = source.split("detect_amd_gpu_model_without_cli() {", 1)[1]
    block = "detect_amd_gpu_model_without_cli() {" + block.split(
        "# Tool-free fallback:", 1)[0]
    command = (
        'command() { if [[ "$1" == -v && ( "$2" == rocm-smi || "$2" == amd-smi ) ]]; '
        'then return 1; else builtin command "$@"; fi; }\n'
    )
    stubs = {
        "lspci": f"printf '%s\\n' {shlex.quote(pci_output)}; exit {pci_exit}",
    }
    if cli:
        command = ""
        stubs.update({"rocm-smi": cli, "amd-smi": "exit 1"})
    run = bashtest.run_bash(
        command + block, stubs=stubs, env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)})
    assert run.returncode == 0, run.stderr
    models = [line.split("=", 1)[1] for line in run.stdout.splitlines()
              if line.startswith("WORKER_AMD_GPU_MODEL=")]
    assert len(models) == 1
    return models[0]


def test_driver_only_host_model_can_be_graded(tmp_path, fixture_policy):
    model = detect_model(tmp_path, [("0x1002", "0x030200", "AMD Instinct MI355X")])
    assert model == "MI355X"
    assert security.amd_driver_verdict(model, evidence()).status == "pass"
    assert security.amd_driver_verdict(model, evidence("31.30")).status == "fail"


def test_driver_only_model_uses_exact_pci_device_name(tmp_path):
    model = detect_model(
        tmp_path, [("0x1002", "0x120000", None)],
        pci_output='0000:00:00.0 "Processing accelerators" "AMD" "Instinct MI300X"')
    assert model == "MI300X"


@pytest.mark.parametrize("output,exit_code", [
    ("", 0), ("", 1), ("", 127),
    ('0000:01:00.0 "Display controller" "AMD" "Instinct MI300X"', 0),
    ('0000:00:00.0 "Display controller" "AMD" "Device 74a1" "AMD" "Instinct MI300X"', 0),
    ('0000:00:00.0 "Display controller" "AMD" "Aqua Vanjaram"', 0),
    ('0000:00:00.0 "Display controller" "AMD" "MI300X / MI325X"', 0),
    ('0000:00:00.0 "unterminated', 0),
    ('0000:00:00.0 "Display controller" "AMD" "MI300X"\n'
     '0000:01:00.0 "Display controller" "AMD" "MI355X"', 0),
])
def test_missing_or_ambiguous_model_stays_unknown(tmp_path, output, exit_code):
    assert detect_model(
        tmp_path, [("0x1002", "0x030200", None)],
        pci_output=output, pci_exit=exit_code) == "unknown"


def test_model_fallback_ignores_non_amd_and_non_gpu_devices(tmp_path):
    assert detect_model(tmp_path, [
        ("0x10de", "0x030200", "MI300X"),
        ("0x1002", "0x060000", "MI300X"),
    ]) == "unknown"


def test_model_fallback_preserves_mixed_and_unidentified_devices(tmp_path, fixture_policy):
    model = detect_model(tmp_path, [
        ("0x1002", "0x030200", "MI300X"),
        ("0x1002", "0x120000", "MI355X"),
        ("0x1002", "0x030200", None),
    ])
    assert model == "MI300X-MI355X-unknown"
    assert security.amd_driver_verdict(model, evidence()).status == "unknown"
    assert security.amd_driver_verdict(model, evidence("31.30")).status == "fail"


def test_existing_cli_model_still_takes_precedence(tmp_path):
    assert detect_model(
        tmp_path, [("0x1002", "0x030200", "MI300X")],
        cli="echo 'GPU[0] : Card Series: AMD Instinct MI355X'") == "AMD-Instinct-MI355X"


def test_unusable_cli_model_falls_back_to_host(tmp_path):
    assert detect_model(
        tmp_path, [("0x1002", "0x030200", "MI300X")],
        cli="echo 'GPU[0] : Card Series: unknown'") == "MI300X"
