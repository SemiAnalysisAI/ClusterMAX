from __future__ import annotations

from pathlib import Path

import pytest

import bashtest


ROOT = Path(__file__).resolve().parents[2]
SLURM = ROOT / "cmax/scripts/1-audit/cluster-audit-slurm.sh"
NHC_SCRIPT = (
    bashtest.extract_block(
        SLURM,
        "# NHC (Node Health Check)",
        "# Monitoring stack detection",
    )
    + '\nprintf "%s|%s|%s|%s\\n" "$NHC_INSTALLED" "$NHC_PATH" '
    '"$NHC_CONF_LINES" "$NHC_CHECK_SCOPE"\n'
)
STUBS = dict.fromkeys(("print_section", "print_info", "print_detail", "nhc"), "")


@pytest.mark.parametrize(
    ("worker_ok", "installed", "path", "checks", "host", "expected"),
    [
        ("true", "false", "none", 0, "gpu-1", "false|none|0|worker"),
        ("true", "true", "/usr/sbin/nhc", 12, "gpu-2", "true|/usr/sbin/nhc|12|worker"),
        ("false", "false", "none", 0, "none", "|head-fallback"),
    ],
    ids=("worker-absent", "worker-configured", "head-fallback"),
)
def test_nhc_scope(worker_ok: str, installed: str, path: str, checks: int, host: str, expected: str) -> None:
    setup = (
        f"WORKER_CHECK_OK={worker_ok}\nWORKER_NHC_INSTALLED={installed}\n"
        f"WORKER_NHC_PATH={path}\nWORKER_NHC_CONF_CHECKS={checks}\nWORKER_HOSTNAME={host}\n"
    )
    run = bashtest.run_bash(setup + NHC_SCRIPT, stubs=STUBS)

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip().endswith(expected)
