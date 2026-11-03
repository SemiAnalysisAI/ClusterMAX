"""Unit tests for the bashtest harness itself."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


@pytest.mark.skipif(not Path("/proc/self/environ").exists(), reason="needs /proc")
@pytest.mark.parametrize("launcher", ["setsid", "timeout 30"])
def test_processes_that_leave_the_process_group_are_stopped_before_cleanup(
    launcher, tmp_path
) -> None:
    # A follower started with setsid, or a command under timeout (which takes
    # its own process group), outlives the snippet unless the harness stops
    # it. Left running, it keeps appending to the call log while the temp
    # directory is removed, which fails cleanup with "Directory not empty".
    started = tmp_path / "started"
    run = bashtest.run_bash(
        f"{launcher} bash -c 'while :; do probe; done' >/dev/null 2>&1 &\n"
        'until [[ -e "$PROBE_STARTED" ]]; do :; done',
        stubs={"probe": ': > "$PROBE_STARTED"'},
        env={"PROBE_STARTED": str(started)},
    )
    assert run.returncode == 0
    assert run.calls("probe")
    marker = f"PROBE_STARTED={started}".encode()
    survivors = []
    for entry in Path("/proc").iterdir():
        try:
            if entry.name.isdigit() and marker in (entry / "environ").read_bytes().split(b"\0"):
                survivors.append(entry.name)
        except OSError:
            continue
    assert survivors == []
