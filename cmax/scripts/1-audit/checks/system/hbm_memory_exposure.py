#!/usr/bin/env python3
"""Report coherent GPU HBM exposure and Kubernetes CPU Manager policy.

The check passively inspects NUMA topology, ``/proc/meminfo``, the NVIDIA
``CoherentGPUMemoryMode`` driver param, and the kubelet
``cpu_manager_state`` policy on Kubernetes. It omits the Kubernetes check on
Slurm and standalone targets. It does not allocate memory or perturb the node.
Use a separate destructive memory test for the active DRAM-to-HBM spill repro.

Kubernetes harness environment variables:

* ``CLUSTERMAX_AUDIT_K8S_NAMESPACE`` (default ``default``)
* ``CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE`` (default
  ``python:3.12-alpine``) - must be reachable from GPU nodes; override
  for air-gapped clusters.
* ``CLUSTERMAX_AUDIT_K8S_HOST_CHECK_PULL_POLICY`` (default
  ``IfNotPresent``)
* ``CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS`` (default: all GPU nodes)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


GIB_KB = 1024 * 1024
# Lower bound for what counts as an HBM-sized memory-only NUMA node. 64 GiB
# catches every coherent NVIDIA platform shipping today (GH200 96 GiB, GB200
# 192 GiB per GPU, GB300 288 GiB per GPU, H100 SXM 80 GiB if ever exposed
# coherently). Bump if a smaller-HBM coherent SKU appears.
HBM_MIN_KB = 64 * GIB_KB
NO_K8S_GPU_NODES = "no Kubernetes nodes advertise nvidia.com/gpu capacity"
COHERENT_GPU_MARKERS = (
    "GH200",
    "GB200",
    "GB300",
    "GRACE HOPPER",
    "GRACE BLACKWELL",
)

_FANOUT = None


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily.

    Lazy (not a top-level import) because the worker arm runs this file via
    ``python3 -`` on stdin, where ``__file__`` does not point at the real check
    path. That arm never calls into _fanout, so the import only ever runs from
    the real on-disk file (run_checks.py / srun).
    """
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout
        _FANOUT = _fanout
    return _FANOUT


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def under_root(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_memtotal_kb(text: str) -> int:
    for line in text.splitlines():
        if "MemTotal:" not in line:
            continue
        match = re.search(r"MemTotal:\s*([0-9]+)", line)
        return int(match.group(1)) if match else 0
    return 0


def parse_cpu_list(cpulist: str) -> list[int]:
    cpus: list[int] = []
    for part in (cpulist or "").strip().split(","):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            if start.isdigit() and end.isdigit():
                cpus.extend(range(int(start), int(end) + 1))
            continue
        if part.isdigit():
            cpus.append(int(part))
    return cpus


def parse_range_list(value: str) -> list[int]:
    return parse_cpu_list(value)


def parse_nvidia_params(text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        params[key.strip()] = value.strip().strip('"')
    return params


def parse_gpu_information(root: Path) -> list[dict[str, Any]]:
    gpu_root = under_root(root, "/proc/driver/nvidia/gpus")
    if not gpu_root.is_dir():
        return []

    gpus: list[dict[str, Any]] = []
    for info_path in sorted(gpu_root.glob("*/information")):
        info = read_text(info_path)
        gpu: dict[str, Any] = {"source": str(info_path)}
        for line in info.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized = key.strip().lower().replace(" ", "_")
            gpu[normalized] = value.strip()
        if gpu:
            gpus.append(gpu)
    return gpus


def run_command(command: list[str], *, timeout: int = 30, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def query_nvidia_smi() -> list[dict[str, Any]]:
    try:
        proc = run_command(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,uuid,pci.bus_id,driver_version",
                "--format=csv,noheader,nounits",
            ],
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if proc.returncode != 0:
        return []

    gpus: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            continue
        gpus.append(
            {
                "model": parts[0],
                "memory_mb": as_int(parts[1]),
                "uuid": parts[2],
                "pci_bus_id": parts[3],
                "driver_version": parts[4],
                "source": "nvidia-smi",
            }
        )
    return gpus


def discover_nodes(root: Path) -> list[int]:
    node_root = under_root(root, "/sys/devices/system/node")
    online = read_text(node_root / "online").strip()
    if online:
        nodes = parse_range_list(online)
        if nodes:
            return nodes

    discovered: list[int] = []
    for path in node_root.glob("node[0-9]*"):
        suffix = path.name.removeprefix("node")
        if suffix.isdigit():
            discovered.append(int(suffix))
    return sorted(discovered)


def collect_numa_nodes(root: Path) -> list[dict[str, Any]]:
    node_root = under_root(root, "/sys/devices/system/node")
    nodes: list[dict[str, Any]] = []
    for node_id in discover_nodes(root):
        path = node_root / f"node{node_id}"
        mem_total_kb = parse_memtotal_kb(read_text(path / "meminfo"))
        cpulist = read_text(path / "cpulist").strip()
        cpus = parse_cpu_list(cpulist)
        nodes.append(
            {
                "id": node_id,
                "mem_total_kb": mem_total_kb,
                "mem_total_gb": round(mem_total_kb / GIB_KB, 1) if mem_total_kb else 0,
                "cpulist": cpulist,
                "cpu_count": len(cpus),
                "has_cpus": bool(cpus),
                "memory_only": mem_total_kb > 0 and not cpus,
            }
        )
    return nodes


def coherent_gpu_candidate(gpu_models: list[str]) -> bool:
    haystack = " ".join(model.upper() for model in gpu_models if model)
    return any(marker in haystack for marker in COHERENT_GPU_MARKERS)


def classify_hbm_like_nodes(
    numa_nodes: list[dict[str, Any]],
    *,
    coherent_candidate: bool,
) -> list[dict[str, Any]]:
    """Return HBM-sized memory-only nodes on a coherent GPU platform."""
    if not coherent_candidate:
        return []
    return [
        node
        for node in numa_nodes
        if node.get("memory_only") and as_int(node.get("mem_total_kb")) >= HBM_MIN_KB
    ]


def parse_kubelet_cpu_manager(root: Path) -> dict[str, Any]:
    state_path = under_root(root, "/var/lib/kubelet/cpu_manager_state")
    text = read_text(state_path)
    if not text:
        return {
            "checked": False,
            "path": str(state_path),
            "policy_name": "unknown",
            "status": "unknown",
            "message": "cpu_manager_state not found or unreadable",
        }

    try:
        state = json.loads(text)
    except json.JSONDecodeError as exc:
        return {
            "checked": True,
            "path": str(state_path),
            "policy_name": "unknown",
            "status": "warning",
            "message": f"cpu_manager_state is not valid JSON: {exc}",
        }

    policy_name = str(state.get("policyName") or "unknown")
    status = "pass" if policy_name == "static" else "warning"
    return {
        "checked": True,
        "path": str(state_path),
        "policy_name": policy_name,
        "status": status,
        "message": f"kubelet CPU manager policy is {policy_name}",
    }


def summarize_host(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize HBM exposure for one coherent GPU host."""
    failures: list[str] = []
    warnings: list[str] = []

    gpu_count = as_int(report.get("gpu_count"))
    if gpu_count == 0:
        return {
            "status": "not_applicable",
            "failures": [],
            "warnings": [],
            "message": "no NVIDIA GPUs detected",
        }

    hbm_nodes = report.get("hbm_like_memory_only_nodes") or []
    coherent_candidate = bool(report.get("coherent_gpu_candidate"))
    if not coherent_candidate:
        gpu_models = report.get("gpu_models") or []
        hbm_scale_nodes = [
            node
            for node in report.get("memory_only_numa_nodes") or []
            if as_int(node.get("mem_total_kb")) >= HBM_MIN_KB
        ]
        if not gpu_models and hbm_scale_nodes:
            return {
                "status": "warning",
                "failures": [],
                "warnings": [
                    "HBM-scale memory-only NUMA nodes are present, but GPU model evidence "
                    "does not confirm a coherent platform"
                ],
                "message": (
                    f"{len(hbm_scale_nodes)} HBM-scale memory-only NUMA node(s) require "
                    "coherent GPU model evidence"
                ),
            }
        return {
            "status": "not_applicable",
            "failures": [],
            "warnings": [],
            "message": "GPU platform is not a coherent NVIDIA GPU platform",
        }

    harness = str(report.get("harness") or "")
    cdmm_mode = str(report.get("nvidia", {}).get("coherent_gpu_memory_mode") or "unknown")

    if hbm_nodes:
        total_gb = round(sum(as_int(node.get("mem_total_kb")) for node in hbm_nodes) / GIB_KB, 1)
        failures.append(
            f"{len(hbm_nodes)} memory-only NUMA node(s) expose {total_gb} GB that looks like GPU HBM"
        )

    if coherent_candidate and cdmm_mode != "driver":
        msg = f"coherent GPU platform is not in CDMM driver mode (CoherentGPUMemoryMode={cdmm_mode})"
        if harness == "k8s":
            failures.append(msg)
        else:
            warnings.append(msg)

    if report.get("memory_only_numa_nodes") and not hbm_nodes:
        warnings.append("host has memory-only NUMA node(s), but they were not classified as GPU HBM")

    status = "pass"
    if failures:
        status = "fail"
    elif warnings:
        status = "warning"

    message = "HBM is not exposed as ordinary system memory"
    if failures:
        message = failures[0]
    elif warnings:
        message = warnings[0]

    return {"status": status, "failures": failures, "warnings": warnings, "message": message}


def summarize_cpu_manager_host(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize kubelet CPU Manager policy as a separate advisory."""
    if as_int(report.get("gpu_count")) == 0:
        return {
            "status": "not_applicable",
            "failures": [],
            "warnings": [],
            "message": "no NVIDIA GPUs detected",
        }
    if str(report.get("harness") or "") != "k8s":
        return {
            "status": "not_applicable",
            "failures": [],
            "warnings": [],
            "message": "kubelet CPU Manager applies only to Kubernetes",
        }

    manager = report.get("kubelet_cpu_manager")
    manager = manager if isinstance(manager, dict) else {}
    policy_name = str(manager.get("policy_name") or "unknown")
    if policy_name == "static":
        return {
            "status": "pass",
            "failures": [],
            "warnings": [],
            "message": "kubelet CPU Manager policy is static",
        }

    if not manager.get("checked"):
        message = "kubelet CPU Manager policy could not be read"
    else:
        message = (
            f"kubelet CPU Manager policy is {policy_name}; "
            "static is recommended for CPU isolation on GPU nodes"
        )
    return {
        "status": "warning",
        "failures": [],
        "warnings": [message],
        "message": message,
    }


def collect_host(
    *,
    root: Path,
    harness: str,
    gpu_model_hint: str = "",
    gpu_memory_mb_hint: int = 0,
    gpu_count_hint: int = 0,
) -> dict[str, Any]:
    hostname = os.environ.get("NODE_NAME") or read_text(under_root(root, "/proc/sys/kernel/hostname")).strip()
    if not hostname:
        hostname = socket.gethostname()

    smi_gpus = query_nvidia_smi() if root == Path("/") else []
    proc_gpus = parse_gpu_information(root)
    gpu_models = [str(gpu.get("model") or gpu.get("model_name") or "") for gpu in smi_gpus + proc_gpus]
    if gpu_model_hint:
        gpu_models.append(gpu_model_hint)
    gpu_models = sorted({model for model in gpu_models if model})

    gpu_memories = [as_int(gpu.get("memory_mb")) for gpu in smi_gpus if as_int(gpu.get("memory_mb")) > 0]
    if gpu_memory_mb_hint > 0:
        gpu_memories.append(gpu_memory_mb_hint)
    gpu_memory_mb = max(gpu_memories) if gpu_memories else 0

    gpu_count = len(smi_gpus) or len(proc_gpus) or gpu_count_hint
    coherent_candidate = coherent_gpu_candidate(gpu_models)
    numa_nodes = collect_numa_nodes(root)
    memory_only_nodes = [node for node in numa_nodes if node.get("memory_only")]
    hbm_like_nodes = classify_hbm_like_nodes(
        numa_nodes,
        coherent_candidate=coherent_candidate,
    )

    meminfo_total_kb = parse_memtotal_kb(read_text(under_root(root, "/proc/meminfo")))
    cpu_numa_mem_kb = sum(as_int(node.get("mem_total_kb")) for node in numa_nodes if node.get("has_cpus"))
    memory_only_mem_kb = sum(as_int(node.get("mem_total_kb")) for node in memory_only_nodes)
    hbm_like_mem_kb = sum(as_int(node.get("mem_total_kb")) for node in hbm_like_nodes)
    node_mem_total_kb = sum(as_int(node.get("mem_total_kb")) for node in numa_nodes)

    params = parse_nvidia_params(read_text(under_root(root, "/proc/driver/nvidia/params")))
    cdmm_mode_value = params.get("CoherentGPUMemoryMode")
    cdmm_mode = "unknown" if cdmm_mode_value is None else (cdmm_mode_value or "unset")

    report: dict[str, Any] = {
        "host": hostname,
        "harness": harness,
        "gpu_count": gpu_count,
        "gpu_models": gpu_models,
        "gpu_memory_mb": gpu_memory_mb,
        "coherent_gpu_candidate": coherent_candidate,
        "proc_meminfo": {
            "mem_total_kb": meminfo_total_kb,
            "mem_total_gb": round(meminfo_total_kb / GIB_KB, 1) if meminfo_total_kb else 0,
        },
        "numa": {
            "nodes": numa_nodes,
            "cpu_node_memory_kb": cpu_numa_mem_kb,
            "memory_only_node_memory_kb": memory_only_mem_kb,
            "hbm_like_memory_kb": hbm_like_mem_kb,
            "node_memory_total_kb": node_mem_total_kb,
            "meminfo_matches_node_total": (
                node_mem_total_kb > 0
                and abs(meminfo_total_kb - node_mem_total_kb) <= max(int(node_mem_total_kb * 0.02), GIB_KB)
            ),
            "meminfo_includes_hbm_like_memory": (
                hbm_like_mem_kb > 0 and meminfo_total_kb >= cpu_numa_mem_kb + int(hbm_like_mem_kb * 0.8)
            ),
        },
        "memory_only_numa_nodes": memory_only_nodes,
        "hbm_like_memory_only_nodes": hbm_like_nodes,
        "nvidia": {
            "coherent_gpu_memory_mode": cdmm_mode,
            "params_read": bool(params),
        },
    }

    report["summary"] = summarize_host(report)
    if harness == "k8s":
        report["kubelet_cpu_manager"] = parse_kubelet_cpu_manager(root)
        report["kubelet_cpu_manager_policy"] = summarize_cpu_manager_host(report)
    return report


def aggregate_reports(
    reports: list[dict[str, Any]],
    errors: list[str],
    *,
    summary_key: str = "summary",
    pass_message: str = "HBM exposure check passed",
    not_applicable_message: str = "no coherent NVIDIA GPU hosts were checked",
) -> dict[str, Any]:
    statuses = [str(report.get(summary_key, {}).get("status") or "unknown") for report in reports]
    if any(status == "fail" for status in statuses):
        status = "fail"
    elif any(status == "warning" for status in statuses):
        status = "warning"
    elif errors:
        status = "warning"
    elif any(status == "pass" for status in statuses):
        status = "pass"
    elif any(status == "not_applicable" for status in statuses):
        status = "not_applicable"
    else:
        status = "unknown"

    failures = [
        f"{report.get('host', 'unknown')}: {failure}"
        for report in reports
        for failure in report.get(summary_key, {}).get("failures", [])
    ]
    warnings = [
        f"{report.get('host', 'unknown')}: {warning}"
        for report in reports
        for warning in report.get(summary_key, {}).get("warnings", [])
    ]
    warnings.extend(errors)

    message = pass_message
    if failures:
        message = failures[0]
    elif warnings:
        message = warnings[0]
    elif status == "not_applicable":
        message = not_applicable_message

    return {
        "schema_version": 1,
        "status": status,
        "message": message,
        "failures": failures,
        "warnings": warnings,
        "hosts_checked": len(reports),
        "hosts": {str(report.get("host") or f"host-{idx}"): report for idx, report in enumerate(reports)},
    }


def aggregate_cpu_manager_reports(
    reports: list[dict[str, Any]], errors: list[str]
) -> dict[str, Any]:
    if not reports:
        no_gpu_hosts = NO_K8S_GPU_NODES in errors
        return {
            "schema_version": 1,
            "status": "not_applicable" if no_gpu_hosts else "unknown",
            "message": (
                "no Kubernetes GPU hosts were checked"
                if no_gpu_hosts
                else "kubelet CPU Manager policy could not be checked on any Kubernetes GPU host"
            ),
            "failures": [],
            "warnings": [],
            "hosts_checked": 0,
            "hosts": {},
        }
    return aggregate_reports(
        reports,
        [],
        summary_key="kubelet_cpu_manager_policy",
        pass_message="kubelet CPU Manager policy check passed",
        not_applicable_message="no Kubernetes GPU hosts were checked",
    )


def run_slurm_check(harness: str) -> tuple[list[dict[str, Any]], list[str]]:
    if not os.environ.get("SLURM_JOB_ID"):
        report = collect_host(root=Path("/"), harness=harness)
        report["check_scope"] = "local"
        return [report], ["SLURM_JOB_ID is not set; HBM check only checked the local host"]

    node_count = os.environ.get("SLURM_NNODES") or "1"
    command = [
        "srun",
        "--overlap",
        "-N",
        node_count,
        "--ntasks-per-node=1",
        sys.executable,
        str(Path(__file__).resolve()),
        "--collect-host",
        "--harness",
        harness,
    ]
    try:
        proc = run_command(command, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report = collect_host(root=Path("/"), harness=harness)
        report["check_scope"] = "local"
        return [report], [f"srun host check failed; local host only: {exc}"]

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    if proc.returncode != 0:
        errors.append(f"srun host check exited {proc.returncode}; parsing any completed host output")

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"ignored non-JSON srun output line: {exc}")
            continue
        if isinstance(value, dict):
            reports.append(value)

    # srun emits informational stderr (site banners, cgroup notices) on healthy
    # clusters, and aggregate_reports downgrades pass to warning whenever errors
    # is non-empty. Record stderr only as failure evidence - a non-zero exit or
    # a fan-out that produced no host JSON - matching the sibling nic-topology
    # and vboost checks.
    if proc.stderr and (proc.returncode != 0 or not reports):
        errors.append(proc.stderr.strip())

    if not reports:
        report = collect_host(root=Path("/"), harness=harness)
        report["check_scope"] = "local"
        reports.append(report)
        errors.append("srun host check returned no host JSON; local host only")
    return reports, errors


def kubectl(command: list[str], *, timeout: int = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_command(["kubectl", *command], timeout=timeout, input_text=input_text)


def _k8s_check_env(node: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"name": "NODE_NAME", "value": node["name"]},
        {"name": "GPU_MODEL", "value": str(node.get("gpu_model") or "")},
        {"name": "GPU_MEMORY_MB", "value": str(node.get("gpu_memory_mb") or 0)},
        {"name": "GPU_COUNT", "value": str(node.get("gpu_count") or 0)},
    ]


def pod_manifest(namespace: str, node: dict[str, Any], image: str, pod_name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "clustermax-hbm-audit"},
        },
        "spec": {
            "restartPolicy": "Never",
            "nodeName": node["name"],
            "hostPID": True,
            "tolerations": [{"operator": "Exists"}],
            "containers": [
                {
                    "name": "check",
                    "image": image,
                    "imagePullPolicy": os.environ.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_PULL_POLICY", "IfNotPresent"),
                    "command": ["sh", "-c", "sleep 600"],
                    "env": _k8s_check_env(node),
                    "securityContext": {"privileged": True, "runAsUser": 0},
                    "volumeMounts": [
                        {"name": "host-proc", "mountPath": "/host/proc", "readOnly": True},
                        {"name": "host-sys", "mountPath": "/host/sys", "readOnly": True},
                        {"name": "host-kubelet", "mountPath": "/host/var/lib/kubelet", "readOnly": True},
                    ],
                }
            ],
            "volumes": [
                {"name": "host-proc", "hostPath": {"path": "/proc"}},
                {"name": "host-sys", "hostPath": {"path": "/sys"}},
                {"name": "host-kubelet", "hostPath": {"path": "/var/lib/kubelet"}},
            ],
        },
    }


def run_k8s_host_check(namespace: str, node: dict[str, Any], image: str) -> tuple[dict[str, Any] | None, str | None]:
    suffix = uuid.uuid4().hex[:8]
    pod_name = f"clustermax-hbm-{suffix}"
    manifest = json.dumps(pod_manifest(namespace, node, image, pod_name))
    try:
        apply_proc = kubectl(["apply", "-f", "-"], timeout=45, input_text=manifest)
        if apply_proc.returncode != 0:
            return None, f"{node['name']}: failed to create host check pod: {apply_proc.stderr.strip()}"

        wait_proc = kubectl(
            ["wait", f"pod/{pod_name}", "-n", namespace, "--for=condition=Ready", "--timeout=90s"],
            timeout=100,
        )
        if wait_proc.returncode != 0:
            return None, f"{node['name']}: host check pod did not become Ready: {wait_proc.stderr.strip()}"

        exec_proc = kubectl(
            ["exec", "-i", "-n", namespace, pod_name, "--", "python3", "-", "--collect-host", "--root", "/host", "--harness", "k8s"],
            timeout=60,
            input_text=Path(__file__).read_text(),
        )
        if exec_proc.returncode != 0:
            return None, f"{node['name']}: host check exec failed: {exec_proc.stderr.strip()}"
        for line in exec_proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                return value, None
        return None, f"{node['name']}: host check returned no JSON"
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return None, f"{node['name']}: host check failed: {exc}"
    finally:
        try:
            kubectl(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=false"], timeout=20)
        except Exception:
            pass


def _hbm_per_node(namespace: str, image: str):
    """Per-node strategy: a fresh privileged pod with host mounts on each node."""
    return lambda node: run_k8s_host_check(namespace, node, image)


def run_k8s_check() -> tuple[list[dict[str, Any]], list[str]]:
    try:
        nodes_proc = kubectl(["get", "nodes", "-o", "json"], timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"kubectl get nodes failed: {exc}"]
    if nodes_proc.returncode != 0:
        return [], [f"kubectl get nodes failed: {nodes_proc.stderr.strip()}"]

    try:
        nodes_json = json.loads(nodes_proc.stdout)
    except json.JSONDecodeError as exc:
        return [], [f"kubectl get nodes returned invalid JSON: {exc}"]

    nodes = load_fanout().k8s_gpu_nodes(nodes_json)
    if not nodes:
        return [], [NO_K8S_GPU_NODES]

    namespace = os.environ.get("CLUSTERMAX_AUDIT_K8S_NAMESPACE", "default")
    image = os.environ.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE", "python:3.12-alpine")
    max_nodes = as_int(os.environ.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"), default=len(nodes))
    return load_fanout().fan_out_k8s(_hbm_per_node(namespace, image), nodes=nodes, max_nodes=max_nodes)


def run_default_check(harness: str) -> dict[str, Any]:
    errors: list[str] = []
    if harness == "slurm":
        reports, errors = run_slurm_check(harness)
    elif harness == "k8s":
        reports, errors = run_k8s_check()
    else:
        reports = [collect_host(root=Path("/"), harness=harness)]
    result = {
        "hbm_memory_exposure": aggregate_reports(reports, errors),
    }
    if harness == "k8s":
        result["kubelet_cpu_manager_policy"] = aggregate_cpu_manager_reports(
            reports, errors
        )
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-host", action="store_true", help="emit one host report instead of aggregate check JSON")
    parser.add_argument("--root", default="/", help="host root path for proc/sys/kubelet reads")
    parser.add_argument("--harness", default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone"))
    args = parser.parse_args(argv)

    if args.collect_host:
        report = collect_host(
            root=Path(args.root),
            harness=args.harness,
            gpu_model_hint=os.environ.get("GPU_MODEL", ""),
            gpu_memory_mb_hint=as_int(os.environ.get("GPU_MEMORY_MB")),
            gpu_count_hint=as_int(os.environ.get("GPU_COUNT")),
        )
        print(json.dumps(report, sort_keys=True))
        return 0

    print(json.dumps(run_default_check(args.harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
