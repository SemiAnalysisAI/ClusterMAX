"""Behavioral tests for host-check.sh MOFED / DOCA-OFED detection.

Executes the real detection block with a stubbed rdma-core package query,
instead of pinning source fragments. The guarded incident: DOCA-OFED ships no
ofed_info and no /etc/mlnx-release, so the check reported "MOFED: Not detected"
on a node whose Mellanox stack was fully present (MLNX-built rdma-core, mlx5
driver, ConnectX firmware).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

# ofed_info and /etc/mlnx-release are absent in CI, so the block naturally takes
# the DOCA-OFED branch; the rdma-core version is the only stubbed input.
DETECT_BLOCK = (
    bashtest.extract_function(WORKLOAD / "host-check.sh", "scale_out_checks_enabled")
    + bashtest.extract_block(
        WORKLOAD / "host-check.sh",
        '_mofed_mlx5_path="${CLUSTERMAX_MLX5_VERSION_PATH',
        'echo "WORKER_MLX5_DRIVER_VERSION=',
    )
)


def run_detect(rdma_core_version: str, env: dict[str, str] | None = None) -> dict[str, str]:
    # Point the sysfs / DOCA-dir seams at absent paths by default so the test is
    # not sensitive to the host it runs on; individual tests override as needed.
    base_env = {
        "CLUSTERMAX_MLX5_VERSION_PATH": "/nonexistent/mlx5/version",
        "CLUSTERMAX_OPT_MELLANOX_DIR": "/nonexistent/opt/mellanox",
    }
    base_env.update(env or {})
    stubs = {"dpkg-query": f'echo "{rdma_core_version}"'}
    run = bashtest.run_bash(DETECT_BLOCK, stubs=stubs, env=base_env)
    assert run.returncode == 0, run.stderr
    out: dict[str, str] = {}
    for line in run.stdout.splitlines():
        if line.startswith("WORKER_") and "=" in line:
            key, val = line.split("=", 1)
            out[key] = val
    return out


def test_doca_ofed_rdma_core_is_detected() -> None:
    out = run_detect("2507mlnx58-1.2507097")
    assert out["WORKER_MOFED_FLAVOR"] == "doca-ofed"
    assert "DOCA-OFED rdma-core 2507mlnx58-1.2507097" == out["WORKER_MOFED_VERSION"]


def test_plain_rdma_core_without_mellanox_is_not_claimed_as_mofed() -> None:
    # A non-MLNX rdma-core (no "mlnx" tag) with no /opt/mellanox is not MOFED.
    out = run_detect("50.0-2ubuntu1")
    assert out["WORKER_MOFED_FLAVOR"] == "none"
    assert out["WORKER_MOFED_VERSION"] == "none"


def test_doca_ofed_via_opt_mellanox_and_driver_version(tmp_path) -> None:
    # No MLNX rdma-core tag, but /opt/mellanox exists and the mlx5 driver
    # version is readable: still DOCA-OFED, reported with the driver version.
    mlx5 = tmp_path / "version"
    mlx5.write_text("25.07-0.9.7\n")
    opt = tmp_path / "mellanox"
    opt.mkdir()
    out = run_detect(
        "50.0-2ubuntu1",
        env={
            "CLUSTERMAX_MLX5_VERSION_PATH": str(mlx5),
            "CLUSTERMAX_OPT_MELLANOX_DIR": str(opt),
        },
    )
    assert out["WORKER_MOFED_FLAVOR"] == "doca-ofed"
    assert out["WORKER_MLX5_DRIVER_VERSION"] == "25.07-0.9.7"
    assert "DOCA-OFED mlx5_core 25.07-0.9.7" == out["WORKER_MOFED_VERSION"]
