#!/usr/bin/env python3
"""Shared k8s node fan-out scaffolding for the audit checks.

The three audit checks (vboost, hbm_memory_exposure, nic-topology) each run a
small worker on every GPU node and collect one JSON object per node. The
genuinely-identical pieces of that live here:

  * parse_json_lines - one JSON object per line of worker stdout.
  * k8s_gpu_nodes     - the GPU nodes from ``kubectl get nodes -o json``.
  * fan_out_k8s       - apply a per-node callable concurrently over the (capped)
                        node list, collecting records + errors with the shared
                        cap message.

What stays in each check, because it genuinely differs and is already validated:
the slurm ``srun`` fan-out, the local/standalone collector, namespace + node
discovery wording, the max-nodes parse, the JSON aggregation/summary, and the
per-node MECHANISM itself - driver-pod exec (NIC, VIRTIO-Net, vBoost) vs a
fresh privileged pod with host mounts (platform and HBM). That mechanism is the
``per_node`` callable handed to fan_out_k8s. There is deliberately no harness
switch and no kubectl/subprocess call in this module; it is pure, so the checks'
validated I/O paths are untouched.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

# (node) -> (record | None, error | None). ``node`` is whatever k8s_gpu_nodes
# produced; the caller's closure decides how to reach and check it.
PerNode = Callable[[Any], "tuple[Optional[dict[str, Any]], Optional[str]]"]
MAX_K8S_FANOUT_WORKERS = 8


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_json_lines(stdout: str, *, require_host: bool = False) -> list[dict[str, Any]]:
    """Pull one JSON object per line that starts with ``{``.

    With ``require_host=True``, only objects carrying a ``host`` key are kept (the
    per-node worker contract for vboost and nic-topology).
    """
    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        if require_host and "host" not in value:
            continue
        records.append(value)
    return records


def k8s_gpu_nodes(nodes_json: dict[str, Any]) -> list[dict[str, Any]]:
    """GPU nodes from ``kubectl get nodes -o json``.

    Returns a rich dict per node (``{name, gpu_count, gpu_model, gpu_memory_mb}``);
    callers that only need the name read ``["name"]`` and ignore the rest.
    """
    gpu_nodes: list[dict[str, Any]] = []
    for item in nodes_json.get("items", []):
        capacity = item.get("status", {}).get("capacity", {})
        labels = item.get("metadata", {}).get("labels", {})
        gpu_count = _as_int(capacity.get("nvidia.com/gpu"))
        if gpu_count <= 0:
            # NVIDIA GPU DRA clusters do not publish a scalar capacity. GFD
            # still publishes the node-local device count used by the audit.
            gpu_count = _as_int(labels.get("nvidia.com/gpu.count"))
        if gpu_count <= 0:
            continue
        gpu_nodes.append(
            {
                "name": item.get("metadata", {}).get("name", ""),
                "gpu_count": gpu_count,
                "gpu_model": labels.get("nvidia.com/gpu.product", ""),
                "gpu_memory_mb": _as_int(labels.get("nvidia.com/gpu.memory")),
            }
        )
    return [node for node in gpu_nodes if node["name"]]


def fan_out_k8s(
    per_node: PerNode,
    *,
    nodes: list[Any],
    max_nodes: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply ``per_node`` over ``nodes[:max_nodes]``, collecting records + errors.

    Appends the shared cap message when ``max_nodes < len(nodes)``. Node
    discovery, namespace resolution, the max-nodes parse, and the empty-list
    guards stay with the caller (their wording differs per check).
    """
    selected = nodes[:max_nodes]
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if selected:
        # Every node operation is independent and Kubernetes already schedules
        # the host-check pods onto distinct nodes. Keep the pool bounded for
        # large fleets, and consume executor.map in input order so aggregation
        # and diagnostics remain deterministic.
        workers = min(len(selected), MAX_K8S_FANOUT_WORKERS)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for record, error in executor.map(per_node, selected):
                if record is not None:
                    records.append(record)
                if error:
                    errors.append(error)
    if max_nodes < len(nodes):
        errors.append(
            f"checked {max_nodes} of {len(nodes)} GPU nodes due to CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"
        )
    return records, errors
