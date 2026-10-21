"""Run the shipped Kubernetes collector against invented sysfs devices."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest


CHECK = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/checks/fabric/nic-topology-check.py"
SPEC = importlib.util.spec_from_file_location("failed_rail_shell", CHECK)
assert SPEC and SPEC.loader
nic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nic)


def run_collector(tmp_path, ports):
    root = tmp_path / "synthetic-infiniband"
    root.mkdir()
    for name, rate, layer, state in ports:
        port = root / name / "ports/1"
        port.mkdir(parents=True)
        for field, value in (("rate", rate), ("link_layer", layer), ("state", state)):
            (port / field).write_text(value + "\n")
        device = tmp_path / "devices" / name
        device.mkdir(parents=True)
        (root / name / "device").symlink_to(device)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for tool in ("mlxconfig", "mlxlink"):
        binary = binaries / tool
        binary.write_text(
            "#!/bin/sh\n"
            'printf "%s %s\\n" "$(basename "$0")" "$*" >> "$TOOL_CALLS"\n'
            'printf "SPLIT_MODE SPLIT_2X(1)\\n"\n'
        )
        binary.chmod(0o755)
    # Never fall through to a real fabric-management tool on developer hosts.
    discover = binaries / "ibnetdiscover"
    discover.write_text("#!/bin/sh\nexit 127\n")
    discover.chmod(0o755)
    script = nic.K8S_COLLECTOR_SH.replace("/sys/class/infiniband", str(root))
    script = script.replace("/sys/class/net", str(tmp_path / "empty-net"))
    calls = tmp_path / "calls"
    result = subprocess.run(
        ["/bin/sh", "-c", script],
        env={
            **os.environ, "CLUSTERMAX_GPU_VENDOR": "amd",
            "PATH": f"{binaries}:{os.environ['PATH']}", "TOOL_CALLS": str(calls),
        },
        capture_output=True, text=True, timeout=10, check=True,
    )
    return result.stdout, calls.read_text().splitlines() if calls.exists() else []


@pytest.mark.parametrize("rate", ["0 Gb/sec", "10 Gb/sec", "2.5 Gb/sec"])
@pytest.mark.parametrize("state", ["1: DOWN", "2: INIT", ""])
def test_low_rate_failed_ib_runs_tools_and_retains_parsed_evidence(tmp_path, rate, state):
    output, calls = run_collector(
        tmp_path, [("synthetic_failed", rate, "InfiniBand", state)],
    )
    assert len(calls) == 2
    raw, _ = nic._parse_k8s_plane(output)
    assert "SPLIT_MODE SPLIT_2X(1)" in raw["synthetic_failed"]["mlxconfig"][0]


def test_active_rails_take_priority_within_the_existing_tool_cap(tmp_path):
    ports = [("aaa_failed", "0 Gb/sec", "InfiniBand", "1: DOWN")]
    ports += [
        (f"synthetic_active_{index}", "200 Gb/sec", "InfiniBand", "4: ACTIVE")
        for index in range(6)
    ]
    output, calls = run_collector(tmp_path, ports)
    assert len(calls) == 12
    assert "@@PLANE@@ aaa_failed" not in output
    assert all("aaa_failed" not in call for call in calls)


@pytest.mark.parametrize("layer", ["Ethernet", "InfiniBand"])
def test_active_low_rate_storage_is_not_a_failed_rail_candidate(tmp_path, layer):
    output, calls = run_collector(
        tmp_path, [("synthetic_storage", "10 Gb/sec", layer, "4: ACTIVE")],
    )
    assert calls == []
    assert "@@PLANE@@" not in output
