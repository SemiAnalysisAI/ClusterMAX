"""Behavioral tests for the slurm collector's topology unit counter.

Executes the real counting block from cluster-audit-slurm.sh against sample
scontrol / topology.conf output, instead of pinning source fragments. The
guarded incident: the counter summed only SwitchName (topology/tree) and the
yaml list items, so a valid topology/block config (which uses BlockName) counted
0 units and false-warned "No switches or blocks in topology".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

COUNT_BLOCK = bashtest.extract_block(
    WORKLOAD / "cluster-audit-slurm.sh",
    "_topo_count() {",
    'print_info "Configured topology units',
)

# topology/block: `scontrol show topology` on this GB300 cluster.
BLOCK_OUTPUT = (
    "BlockName=computenvlinstancegroup-e00k8tjbm2mxdxbza8 BlockIndex=0 "
    "Nodes=worker-rack0-[0-17] BlockSize=16\n"
    "BlockName=computenvlinstancegroup-e00sjc41t7jgwx6hsm BlockIndex=1 "
    "Nodes=worker-rack1-[0-17] BlockSize=16\n"
)
# topology/tree: classic SwitchName lines.
TREE_OUTPUT = (
    "SwitchName=spine Switches=leaf[0-1]\n"
    "SwitchName=leaf0 Nodes=node[0-1]\n"
    "SwitchName=leaf1 Nodes=node[2-3]\n"
)


def count_units(topo_output: str) -> int:
    run = bashtest.run_bash(
        f'TOPO_OUTPUT={bashtest_quote(topo_output)}\n{COUNT_BLOCK}\nprintf %s "$TOPO_UNITS"'
    )
    assert run.returncode == 0, run.stderr
    return int(run.stdout.strip())


def bashtest_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def test_counts_block_topology_units() -> None:
    # The regression: two BlockName entries must count as 2, not 0.
    assert count_units(BLOCK_OUTPUT) == 2


def test_counts_tree_topology_units() -> None:
    assert count_units(TREE_OUTPUT) == 3


def test_empty_topology_counts_zero() -> None:
    assert count_units("") == 0
