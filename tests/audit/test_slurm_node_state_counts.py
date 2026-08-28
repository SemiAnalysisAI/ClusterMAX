#!/usr/bin/env python3
"""Unit tests for Slurm node-state counting in the cluster audit.

Slurm joins a node base state and its flags with "+", for example
"IDLE+CLOUD+POWERED_DOWN". The audit used a substring test on "DOWN|DRAIN",
so the POWERED_DOWN power-save flag matched the down/drained pattern. On an
Azure cloud cluster that scales to zero, the audit printed
"Down/Drained: 84" while `sinfo` showed all 84 nodes as "idle~".
"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


COMMON_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "audit-common.sh"
)


def run_helper(function: str, value: str) -> dict:
    command = f'source "$1"; {function} "$2"'
    result = subprocess.run(
        ["bash", "-c", command, "bash", str(COMMON_PATH), value],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout.strip())


def node(name: str, state: str) -> dict:
    return {"name": name, "state": state, "cpus": 8, "memory": 1024, "gpus": 0}


class SlurmNodeStateCountTests(unittest.TestCase):
    def test_powered_down_cloud_nodes_are_idle_not_down(self) -> None:
        """Reproduce the Azure ccw cluster: 84 idle~ nodes, 0 real failures."""
        nodes = (
            [node(f"ccw-gpu-{i}", "IDLE+CLOUD+POWERED_DOWN") for i in range(19, 37)]
            + [node(f"ccw-gpu-{i}", "ALLOCATED+CLOUD") for i in range(1, 5)]
            + [node(f"ccw-gpu-{i}", "IDLE+CLOUD") for i in range(5, 19)]
            + [node(f"ccw-hpc-{i}", "IDLE+CLOUD+POWERED_DOWN") for i in range(1, 17)]
            + [node(f"ccw-htc-{i}", "IDLE+CLOUD+POWERED_DOWN") for i in range(1, 51)]
        )

        counts = run_helper("count_slurm_node_states", json.dumps(nodes))

        self.assertEqual(counts["total"], 102)
        self.assertEqual(counts["idle"], 98)
        self.assertEqual(counts["allocated"], 4)
        self.assertEqual(counts["downDrained"], 0)
        self.assertEqual(counts["poweredDown"], 84)

    def test_power_transition_flags_are_not_down(self) -> None:
        nodes = [
            node("a", "IDLE+CLOUD+POWERING_DOWN"),
            node("b", "IDLE+CLOUD+POWER_DOWN"),
            node("c", "IDLE+CLOUD+POWERING_UP"),
        ]

        counts = run_helper("count_slurm_node_states", json.dumps(nodes))

        self.assertEqual(counts["downDrained"], 0)
        self.assertEqual(counts["idle"], 3)

    def test_real_down_and_drained_nodes_still_count(self) -> None:
        nodes = [
            node("a", "DOWN"),
            node("b", "DOWN+NOT_RESPONDING"),
            node("c", "IDLE+DRAIN"),
            node("d", "ALLOCATED+DRAIN"),
            node("e", "DOWN+DRAIN"),
            node("f", "IDLE+CLOUD+POWERED_DOWN"),
            node("g", "IDLE"),
        ]

        counts = run_helper("count_slurm_node_states", json.dumps(nodes))

        self.assertEqual(counts["downDrained"], 5)
        self.assertEqual(counts["poweredDown"], 1)

    def test_drained_nodes_are_excluded_from_idle_and_allocated(self) -> None:
        """A node must appear in exactly one of the three summary counts."""
        nodes = [
            node("a", "IDLE+DRAIN"),
            node("b", "ALLOCATED+DRAIN"),
            node("c", "IDLE"),
            node("d", "ALLOCATED"),
        ]

        counts = run_helper("count_slurm_node_states", json.dumps(nodes))

        self.assertEqual(counts["idle"], 1)
        self.assertEqual(counts["allocated"], 1)
        self.assertEqual(counts["downDrained"], 2)
        self.assertEqual(
            counts["idle"] + counts["allocated"] + counts["downDrained"],
            counts["total"],
        )

    def test_mixed_state_is_neither_idle_nor_down(self) -> None:
        counts = run_helper(
            "count_slurm_node_states", json.dumps([node("a", "MIXED+CLOUD")])
        )

        self.assertEqual(counts["idle"], 0)
        self.assertEqual(counts["allocated"], 0)
        self.assertEqual(counts["downDrained"], 0)

    def test_empty_node_list_returns_zeros(self) -> None:
        counts = run_helper("count_slurm_node_states", "[]")

        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["downDrained"], 0)


class SnodesStateCountTests(unittest.TestCase):
    def test_sinfo_power_save_suffix_counts_as_idle(self) -> None:
        """Real `sinfo` output from the Azure ccw cluster login node."""
        rows = "\n".join(
            [
                "PARTITION AVAIL  TIMELIMIT  NODES  STATE NODELIST",
                "dynamic      up   infinite      0    n/a",
                "gpu          up   infinite     18   idle~ ccw-gpu-[19-36]",
                "gpu          up   infinite      4   alloc ccw-gpu-[1-4]",
                "gpu          up   infinite     14    idle ccw-gpu-[5-18]",
                "hpc*         up   infinite     16   idle~ ccw-hpc-[1-16]",
                "htc          up   infinite     50   idle~ ccw-htc-[1-50]",
            ]
        )

        counts = run_helper("count_snodes_states", rows)

        self.assertEqual(counts["total"], 102)
        self.assertEqual(counts["idle"], 98)
        self.assertEqual(counts["allocated"], 4)
        self.assertEqual(counts["downDrained"], 0)

    def test_sinfo_down_and_drain_states_count(self) -> None:
        rows = "\n".join(
            [
                "PARTITION AVAIL  TIMELIMIT  NODES  STATE NODELIST",
                "gpu          up   infinite      2    down gpu-[1-2]",
                "gpu          up   infinite      3   drain gpu-[3-5]",
                "gpu          up   infinite      1    drng gpu-6",
                "gpu          up   infinite      4   idle~ gpu-[7-10]",
                "gpu          up   infinite      1   down* gpu-11",
            ]
        )

        counts = run_helper("count_snodes_states", rows)

        self.assertEqual(counts["downDrained"], 7)
        self.assertEqual(counts["idle"], 4)
        self.assertEqual(counts["total"], 11)

    def test_zero_node_partition_rows_do_not_break_counting(self) -> None:
        rows = "\n".join(
            [
                "PARTITION AVAIL  TIMELIMIT  NODES  STATE NODELIST",
                "dynamic      up   infinite      0    n/a",
            ]
        )

        counts = run_helper("count_snodes_states", rows)

        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["idle"], 0)
        self.assertEqual(counts["downDrained"], 0)


if __name__ == "__main__":
    unittest.main()
