"""The Slurm collector must tell the user when no allocation is present."""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-slurm.sh"
)


def _hint_block() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r'^if \[\[ -z "\$\{SLURM_JOB_ID:-\}" \]\]; then\n    # Many worker checks.*?^fi\n',
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "allocation hint block is missing"
    return match.group(0)


def _run(env_job_id: str | None) -> str:
    script = (
        'print_warn() { printf "WARN %s\\n" "$1"; }\n'
        'print_detail() { printf "DETAIL %s\\n" "$1"; }\n' + _hint_block()
    )
    env = {key: value for key, value in os.environ.items() if key != "SLURM_JOB_ID"}
    if env_job_id is not None:
        env["SLURM_JOB_ID"] = env_job_id
    return subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, text=True, check=True
    ).stdout


class SlurmAllocationHintTests(unittest.TestCase):
    def test_hint_without_allocation(self) -> None:
        output = _run(None)
        self.assertIn("WARN SLURM_JOB_ID is not set", output)
        self.assertIn("salloc", output)

    def test_no_hint_inside_allocation(self) -> None:
        self.assertEqual(_run("42"), "")


if __name__ == "__main__":
    unittest.main()
