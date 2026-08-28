#!/usr/bin/env python3
"""Select the primary GPU profile from a Kubernetes NodeList.

Kubernetes clusters often contain several accelerator pools. The flat audit
summary represents the profile that contributes the most installed GPUs while
the full profile list preserves the heterogeneous inventory.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

WORKLOAD_DIR = str(Path(__file__).resolve().parent)
if WORKLOAD_DIR not in sys.path:
    sys.path.insert(0, WORKLOAD_DIR)

from kubernetes_quantities import kubernetes_memory_gib


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _cpu_cores(value: Any) -> float:
    text = str(value or "0").strip()
    if text.endswith("m"):
        return _number(text[:-1]) / 1000
    return _number(text)


def _model(labels: dict[str, Any], vendor: str) -> str:
    if vendor == "amd":
        return str(labels.get("amd.com/gpu.product-name") or "unknown")

    product = labels.get("nvidia.com/gpu.product")
    if product:
        return str(product)
    doks_model = str(labels.get("doks.digitalocean.com/gpu-model") or "").strip()
    doks_brand = str(labels.get("doks.digitalocean.com/gpu-brand") or "").strip()
    if doks_model or doks_brand:
        return f"{doks_brand} {doks_model}".strip().upper()
    gke_model = labels.get("cloud.google.com/gke-accelerator")
    if gke_model:
        return str(gke_model)
    return "unknown"


def _gpu_memory(labels: dict[str, Any], vendor: str) -> str:
    key = "amd.com/gpu.vram" if vendor == "amd" else "nvidia.com/gpu.memory"
    return str(labels.get(key) or "unknown")


def select_gpu_profiles(
    node_list: dict[str, Any],
    *,
    resource_key: str,
    vendor: str,
) -> dict[str, Any]:
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for node in node_list.get("items", []):
        if not isinstance(node, dict):
            continue
        status = node.get("status") if isinstance(node.get("status"), dict) else {}
        capacity = status.get("capacity") if isinstance(status.get("capacity"), dict) else {}
        per_node = int(_number(capacity.get(resource_key)))
        if per_node <= 0:
            continue
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
        grouped[(_model(labels, vendor), per_node)].append(
            {
                "name": str(metadata.get("name") or ""),
                "cpu": _cpu_cores(capacity.get("cpu")),
                "memoryGiB": kubernetes_memory_gib(capacity.get("memory")),
                "gpuMemoryMB": _gpu_memory(labels, vendor),
            }
        )

    profiles: list[dict[str, Any]] = []
    for (model, per_node), nodes in grouped.items():
        memory_values = sorted(
            {node["gpuMemoryMB"] for node in nodes if node["gpuMemoryMB"] != "unknown"}
        )
        profiles.append(
            {
                "model": model,
                "perNode": per_node,
                "nodeCount": len(nodes),
                "totalGpus": per_node * len(nodes),
                "totalCpus": math.floor(sum(node["cpu"] for node in nodes)),
                "totalMemoryGB": math.floor(sum(node["memoryGiB"] for node in nodes)),
                "memoryMB": memory_values[0] if memory_values else "unknown",
                "nodeNames": sorted(node["name"] for node in nodes if node["name"]),
            }
        )

    profiles.sort(
        key=lambda profile: (
            -profile["totalGpus"],
            -profile["nodeCount"],
            -profile["perNode"],
            profile["model"],
        )
    )
    return {"primary": profiles[0] if profiles else None, "profiles": profiles}


def resolve_primary_profile(
    inventory: dict[str, Any],
    *,
    model: str,
    memory_mb: str,
) -> dict[str, Any]:
    """Fill missing primary profile facts from a check on that profile."""
    resolved = copy.deepcopy(inventory)
    primary = resolved.get("primary")
    if not isinstance(primary, dict):
        return resolved

    primary_nodes = primary.get("nodeNames")
    primary_per_node = primary.get("perNode")
    primary_model = str(primary.get("model") or "unknown").lower()
    primary_memory = str(primary.get("memoryMB") or "unknown").lower()
    resolved_model = str(model or "").strip()
    resolved_memory = str(memory_mb or "").strip()
    if primary_model == "unknown" and resolved_model.lower() not in {
        "",
        "unknown",
        "nvidia gpu",
        "no-nvidia-smi",
        "no-amd-smi",
    }:
        primary["model"] = resolved_model
    if primary_memory == "unknown" and resolved_memory.lower() not in {
        "",
        "0",
        "unknown",
    }:
        primary["memoryMB"] = resolved_memory

    profiles = resolved.get("profiles")
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            same_nodes = profile.get("nodeNames") == primary_nodes
            same_density = profile.get("perNode") == primary_per_node
            if same_nodes and same_density:
                profile.update({"model": primary.get("model"), "memoryMB": primary.get("memoryMB")})
                break
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-key")
    parser.add_argument("--vendor", choices=("nvidia", "amd"))
    parser.add_argument("--resolved-model")
    parser.add_argument("--resolved-memory-mb")
    args = parser.parse_args()
    input_data = json.load(sys.stdin)
    if not isinstance(input_data, dict):
        raise ValueError("input must be a JSON object")
    if args.resolved_model is not None or args.resolved_memory_mb is not None:
        result = resolve_primary_profile(
            input_data,
            model=args.resolved_model or "",
            memory_mb=args.resolved_memory_mb or "",
        )
    else:
        if not args.resource_key or not args.vendor:
            parser.error("--resource-key and --vendor are required for NodeList inventory")
        result = select_gpu_profiles(
            input_data,
            resource_key=args.resource_key,
            vendor=args.vendor,
        )
    json.dump(
        result,
        sys.stdout,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
