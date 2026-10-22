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
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Mapping, Optional

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


def k8s_gpu_nodes(nodes_json: dict[str, Any], *, gpu_vendor: str | None = None) -> list[dict[str, Any]]:
    """GPU nodes from ``kubectl get nodes -o json``.

    Returns a rich dict per node
    (``{name, gpu_count, gpu_vendor, gpu_model, gpu_memory_mb}``); callers that
    only need the name read ``["name"]`` and ignore the rest.
    """
    gpu_nodes: list[dict[str, Any]] = []
    for item in nodes_json.get("items", []):
        capacity = item.get("status", {}).get("capacity", {})
        labels = item.get("metadata", {}).get("labels", {})
        gpu_count = _as_int(capacity.get("nvidia.com/gpu"))
        vendor = "nvidia"
        if gpu_count <= 0:
            # NVIDIA GPU DRA clusters do not publish a scalar capacity. GFD
            # still publishes the node-local device count used by the audit.
            gpu_count = _as_int(labels.get("nvidia.com/gpu.count"))
        if gpu_count <= 0:
            gpu_count = _as_int(capacity.get("amd.com/gpu"))
            vendor = "amd"
        if gpu_count <= 0:
            continue
        if gpu_vendor is not None and vendor != gpu_vendor:
            continue
        if vendor == "amd":
            gpu_model = labels.get("amd.com/gpu.product-name") or labels.get(
                "beta.amd.com/gpu.product-name", ""
            )
            gpu_memory_mb = _memory_mb(
                labels.get("amd.com/gpu.vram")
                or labels.get("beta.amd.com/gpu.vram")
            )
        else:
            gpu_model = labels.get("nvidia.com/gpu.product", "")
            gpu_memory_mb = _memory_mb(labels.get("nvidia.com/gpu.memory"))
        gpu_nodes.append(
            {
                "name": item.get("metadata", {}).get("name", ""),
                "gpu_count": gpu_count,
                "gpu_vendor": vendor,
                "gpu_model": gpu_model,
                "gpu_memory_mb": gpu_memory_mb,
            }
        )
    return [node for node in gpu_nodes if node["name"]]


def k8s_nodes_json(
    run_kubectl: Callable[[list[str]], Any],
) -> tuple[dict[str, Any] | None, str]:
    """Return ``kubectl get nodes -o json`` as a dict, or ``(None, error)``.

    ``run_kubectl`` takes kubectl arguments and returns a CompletedProcess.
    """
    try:
        proc = run_kubectl(["get", "nodes", "-o", "json"])
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"kubectl get nodes failed: {exc}"
    if proc.returncode != 0:
        return None, f"kubectl get nodes failed: {(proc.stderr or '').strip()}"
    try:
        return json.loads(proc.stdout), ""
    except (TypeError, json.JSONDecodeError) as exc:
        return None, f"kubectl get nodes returned invalid JSON: {exc}"


def k8s_max_host_checks(env: Mapping[str, str], total: int) -> int:
    """Nodes to check: CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS when positive, else all."""
    limit = _as_int(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"), default=0)
    return limit if limit > 0 else total


def fan_out_k8s(
    per_node: PerNode,
    *,
    nodes: list[Any],
    max_nodes: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply ``per_node`` over ``nodes[:max_nodes]``, collecting records + errors.

    Appends the shared cap message when ``max_nodes < len(nodes)``. Namespace
    resolution and the empty-list guards stay with the caller (their wording
    differs per check).
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


# Per-node GRES in ``scontrol show job -d``: "GRES=gpu:h100:8(IDX:0-7)" or
# "GRES=gpu:8(IDX:0-7)". Other GRES entries on the same line are ignored.
_NODE_GPU_GRES_RE = re.compile(r"(?:^|[=,])gpu(?::[A-Za-z0-9_.-]+)?:([0-9]+)(?:\(|,|$)")


def slurm_gpus_per_node(
    env: Mapping[str, str] = os.environ,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int | None:
    """Return the GPUs every node of the current job holds, or None.

    A job step only sees GPUs it requests. A step launched without ``--gres``
    inside an allocation that holds every GPU, for example ``salloc
    --exclusive``, sees no GPU at all, so nvidia-smi reports "No devices were
    found". Checks that read GPUs must request the job's GPUs. With different
    counts per node, the smallest one is used, so the step can start on every
    node.
    """
    job_id = str(env.get("SLURM_JOB_ID") or "").strip()
    if not job_id:
        return None
    try:
        proc = runner(
            ["scontrol", "show", "job", "-d", job_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not isinstance(proc.stdout, str):
        return None
    counts: list[int] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("Nodes="):
            continue
        gres = re.search(r"\bGRES=(\S+)", line)
        if not gres:
            return None  # a node without GPU GRES: requesting GPUs would fail
        total = sum(int(m.group(1)) for m in _NODE_GPU_GRES_RE.finditer(gres.group(1)))
        if total <= 0:
            return None
        counts.append(total)
    return min(counts) if counts else None


def slurm_python_command(
    *,
    node_count: str,
    worker_args: list[str],
    gpus_per_node: int | None = None,
) -> list[str]:
    """Build an srun command that does not require a shared checkout.

    Slurm broadcasts standard input to each task. The caller supplies the
    source through standard input, so no controller path reaches a compute node.
    Checks that read GPUs pass ``gpus_per_node`` (see slurm_gpus_per_node) so
    the step can see them.
    """
    gres = [f"--gres=gpu:{gpus_per_node}"] if gpus_per_node and gpus_per_node > 0 else []
    return [
        "srun",
        "--overlap",
        "--input=all",
        "-N",
        node_count,
        "--ntasks-per-node=1",
        *gres,
        "python3",
        "-",
        *worker_args,
    ]


def _memory_mb(value: Any) -> int:
    """Normalize integer MiB labels and AMD labels such as ``288G``."""
    text = str(value or "").strip().upper()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]I?B?|)", text)
    if not match:
        return 0
    amount = float(match.group(1))
    unit = match.group(2).rstrip("B").rstrip("I")
    factors = {
        "": 1,
        "K": 1 / 1024,
        "M": 1,
        "G": 1024,
        "T": 1024 * 1024,
    }
    return int(amount * factors[unit])
