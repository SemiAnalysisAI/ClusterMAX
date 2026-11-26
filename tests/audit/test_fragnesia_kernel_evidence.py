"""Fragnesia grades only the Noble generic 6.8 line; other kernels are unknown."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

WORKLOAD_DIR = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"


def advisory(running: str, os_id: str = "ubuntu", release: str = "24.04",
             host_status: str = "not-applicable") -> dict:
    script = f"""
source "{WORKLOAD_DIR / 'audit-common.sh'}"
build_security_advisory_json --bad-epoll-os {os_id} --bad-epoll-release {release} \\
    --bad-epoll-running {running} --fragnesia-status {host_status} \\
    --fragnesia-compared-abi 124
"""
    run = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return json.loads("{" + run.stdout.strip().rstrip(",") + "}")["fragnesia"]


@pytest.mark.parametrize("running, os_id, release", [
    ("7.0.12-319-ge90ae78b-custom-amd64", "ubuntu", "24.04"),
    ("6.17.0-1021-nvidia-64k", "ubuntu", "24.04"),
    ("5.14.0-427.el9.x86_64", "rhel", "9.4"),
])
def test_kernel_outside_the_noble_generic_line_is_unknown(running, os_id, release):
    frag = advisory(running, os_id, release)
    assert frag["status"] == "unknown"
    assert frag["comparedAbiFloor"] == "unknown"
    assert frag["kernelEvidence"]["running"] == running
    assert "provider patch evidence" in frag["kernelEvidence"]["detail"]


@pytest.mark.parametrize("host_status", ["pass", "fail", "unknown"])
def test_noble_generic_keeps_the_host_check_grade(host_status):
    frag = advisory("6.8.0-130-generic", host_status=host_status)
    assert frag["kernelEvidence"] is None
    assert frag["comparedAbiFloor"] == "124"
    if host_status != "fail":
        assert frag["status"] == host_status


def test_unknown_running_kernel_keeps_the_host_check_grade():
    frag = advisory("unknown", host_status="unknown")
    assert frag["kernelEvidence"] is None


def graded(running: str, version: str, source: str, release: str = "24.04",
           livepatch: str = "none") -> dict:
    flavor = running.split("-", 2)[2]
    script = f"""
source "{WORKLOAD_DIR / 'audit-common.sh'}"
build_security_advisory_json --bad-epoll-os ubuntu --bad-epoll-release {release} \\
    --bad-epoll-running {running} --fragnesia-status not-applicable \\
    --bad-epoll-signature 'Ubuntu {version}-{flavor} 6.0' \\
    --bad-epoll-package 'ii|{source}|{version}' --bad-epoll-livepatch {livepatch}
"""
    run = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return json.loads("{" + run.stdout.strip().rstrip(",") + "}")["fragnesia"]


@pytest.mark.parametrize("running, version, source, release, expected", [
    ("6.17.0-1021-nvidia-64k", "6.17.0-1021.21", "linux-nvidia-6.17", "24.04", "pass"),
    ("6.17.0-1031-nvidia", "6.17.0-1031.31", "linux-signed-nvidia-6.17", "24.04", "pass"),
    ("6.17.0-1020-nvidia", "6.17.0-1020.20", "linux-nvidia-6.17", "24.04", "fail"),
    ("7.0.0-22-generic", "7.0.0-22.22", "linux", "26.04", "pass"),
    ("7.0.0-21-generic", "7.0.0-21.21", "linux", "26.04", "fail"),
    ("6.8.0-124-generic", "6.8.0-124.124", "linux", "24.04", "pass"),
    ("6.8.0-123-generic", "6.8.0-123.123", "linux", "24.04", "fail"),
])
def test_public_package_grading_covers_nvidia_617_and_resolute(
        running, version, source, release, expected):
    frag = graded(running, version, source, release)
    # A grace period in the bulletin can turn fail into pass, as in public.
    if expected == "fail" and frag["gracePeriod"] is not None:
        expected = "pass"
    assert frag["status"] == expected
    assert frag["kernelEvidence"]["status"] in {"pass", "fail"}
    assert frag["ubuntuNoblePackageMinimum"] == frag["kernelEvidence"]["minimum"]


def test_package_for_a_different_kernel_line_stays_unknown():
    frag = graded("6.17.0-1031-nvidia", "6.17.0-1031.31", "linux")
    assert frag["status"] == "unknown"


def test_active_livepatch_stays_unknown():
    frag = graded("7.0.0-22-generic", "7.0.0-22.22", "linux", "26.04", livepatch="enabled")
    assert frag["status"] == "unknown"
