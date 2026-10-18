"""Behavioral tests for the k8s collector's live check-node selection.

Synthetic fixtures cover unreachable workers that advertise more free GPUs
than Ready workers. Live probes must select a Ready worker in the primary
GPU profile while retaining every worker in the inventory.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit"
AUDIT_DIR = Path(__file__).resolve().parent
SCRIPT = SCRIPT_DIR / "cluster-audit-k8s.sh"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest


def selection_snippet() -> str:
    return "\n".join(
        [
            bashtest.extract_block(
                SCRIPT,
                'GPU_NODE_NAMES=$(echo "$NODES_JSON"',
                "K8S_AUDIT_CHECK_NODE_TRIES=3",
            ),
            'printf "INVENTORY=%s\\n" "$(printf %s "$GPU_NODE_NAMES" | paste -sd, -)"',
            'printf "CHECK=%s\\n" "$(printf %s "$GPU_CHECK_NODE_NAMES" | paste -sd, -)"',
            'printf "FIRST=%s\\n" "$FIRST_GPU_NODE"',
            'printf "FREE=%s\\n" "$(printf %s "$GPU_FREE_NODE_NAMES" | paste -sd, -)"',
        ]
    )


def gpu_node(
    name: str,
    *,
    ready: str,
    allocatable: str,
    capacity: str = "8",
    labels: dict[str, str] | None = None,
    unschedulable: bool = False,
    unreachable: bool = False,
) -> dict:
    spec: dict = {}
    if unschedulable:
        spec["unschedulable"] = True
    if unreachable:
        spec["taints"] = [
            {"key": "node.kubernetes.io/unreachable", "effect": "NoSchedule"}
        ]
    return {
        "metadata": {"name": name, "labels": labels or {}},
        "spec": spec,
        "status": {
            "capacity": {"nvidia.com/gpu": capacity},
            "allocatable": {"nvidia.com/gpu": allocatable},
            "conditions": [{"type": "Ready", "status": ready}],
        },
    }


def run_selection(
    nodes: list[dict], primary_names: list[str] | None = None,
    primary_model: str = "NVIDIA-H100-80GB-HBM3",
) -> bashtest.BashRun:
    return bashtest.run_bash(
        selection_snippet(),
        env={
            "NODES_JSON": json.dumps({"items": nodes}),
            "GPU_ALLOC_BY_NODE": "{}",
            "PRIMARY_GPU_NODE_NAMES_JSON": json.dumps(
                primary_names
                if primary_names is not None
                else [node["metadata"]["name"] for node in nodes]
            ),
            "PRIMARY_GPU_PROFILE_JSON": json.dumps(
                {
                    "model": primary_model,
                    "perNode": 8,
                    "nodeCount": len(nodes),
                    "totalCpus": 0,
                    "totalMemoryGB": 0,
                }
            ),
            "GPU_RESOURCE_KEY": "nvidia.com/gpu",
            "GPU_VENDOR": "nvidia",
        },
    )


def outputs(run: bashtest.BashRun) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for line in run.stdout.splitlines():
        key, _, value = line.partition("=")
        parsed[key] = [item for item in value.split(",") if item]
    return parsed


def test_ready_worker_is_selected_ahead_of_unreachable_free_gpu_nodes() -> None:
    run = run_selection(
        [
            gpu_node("p2-a", ready="Unknown", allocatable="8", unreachable=True),
            gpu_node("p2-b", ready="Unknown", allocatable="8", unreachable=True),
            gpu_node("p2-c", ready="False", allocatable="8", unreachable=True),
            gpu_node(
                "p1-ready",
                ready="True",
                allocatable="0",
                capacity="0",
                labels={
                    "nvidia.com/gpu.count": "8",
                    "nvidia.com/gpu.product": "NVIDIA-H100-80GB-HBM3",
                },
            ),
        ],
        primary_names=["p2-a", "p2-b", "p2-c"],
    )

    assert run.returncode == 0, run.stderr
    result = outputs(run)
    assert set(result["INVENTORY"]) == {"p2-a", "p2-b", "p2-c"}
    assert result["CHECK"] == ["p1-ready"]
    assert result["FIRST"] == ["p1-ready"]


def test_cordoned_or_unreachable_tainted_ready_nodes_are_not_check_targets() -> None:
    run = run_selection(
        [
            gpu_node(
                "ready-cordoned",
                ready="True",
                allocatable="8",
                unschedulable=True,
            ),
            gpu_node(
                "ready-unreachable-taint",
                ready="True",
                allocatable="8",
                unreachable=True,
            ),
            gpu_node("ready-open", ready="True", allocatable="0"),
        ]
    )

    assert run.returncode == 0, run.stderr
    assert outputs(run)["CHECK"] == ["ready-open"]
    assert outputs(run)["FREE"] == []


def test_gpu_consuming_probes_require_both_ready_and_free_capacity() -> None:
    run = run_selection([
        gpu_node("down-free", ready="False", allocatable="8"),
        gpu_node("ready-free", ready="True", allocatable="1"),
        gpu_node("ready-busy", ready="True", allocatable="0"),
    ])
    assert run.returncode == 0, run.stderr
    assert outputs(run)["FREE"] == ["ready-free"]


def test_secondary_pool_cannot_supply_primary_profile_facts() -> None:
    run = run_selection(
        [
            gpu_node("primary-down", ready="False", allocatable="8"),
            gpu_node(
                "secondary-ready", ready="True", allocatable="1", capacity="1",
                labels={"nvidia.com/gpu.product": "NVIDIA-A10G"},
            ),
        ],
        primary_names=["primary-down"],
    )
    assert run.returncode == 0, run.stderr
    assert outputs(run)["CHECK"] == []
    assert outputs(run)["FIRST"] == []


def test_label_fallback_requires_primary_model_and_density() -> None:
    candidates = [
        ("wrong-model", "NVIDIA-A10G", "8"),
        ("wrong-density", "NVIDIA-H100-80GB-HBM3", "1"),
        ("unknown-density", "NVIDIA-H100-80GB-HBM3", "unknown"),
        ("matching-labels", "NVIDIA-H100-80GB-HBM3", "8"),
    ]
    run = run_selection(
        [
            gpu_node("primary-down", ready="False", allocatable="8"),
            *[
                gpu_node(
                    name, ready="True", allocatable="0", capacity="0",
                    labels={"nvidia.com/gpu.product": model, "nvidia.com/gpu.count": density},
                )
                for name, model, density in candidates
            ],
        ],
        primary_names=["primary-down"],
    )
    assert run.returncode == 0, run.stderr
    assert outputs(run)["CHECK"] == ["matching-labels"]


def test_unknown_primary_model_does_not_allow_an_unrelated_fallback() -> None:
    run = run_selection(
        [
            gpu_node("primary-down", ready="False", allocatable="8"),
            gpu_node("secondary-ready", ready="True", allocatable="8"),
        ],
        primary_names=["primary-down"],
        primary_model="unknown",
    )
    assert run.returncode == 0, run.stderr
    assert outputs(run)["CHECK"] == []
