#!/usr/bin/env python3
"""Check whether the current provider allows changing NVIDIA vboost."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional


TARGET_VBOOST = 2
COMMAND_TIMEOUT_S = 20
SLURM_TIMEOUT_S = 90
KUBECTL_TIMEOUT_S = 60
MAX_OUTPUT_CHARS = 4000

_VBOOST_UNSUPPORTED_GPU_RE = re.compile(r"\bg?b300\b", re.IGNORECASE)

# Namespaces the NVIDIA GPU Operator installs into, in the same order the k8s
# collector and the nic-topology check scan them.
GPU_OPERATOR_NAMESPACES = (
    "gpu-operator",
    "gpu-operator-resources",
    "nvidia-gpu-operator",
    "nvidia",
    "gpu",
)

Runner = Callable[..., subprocess.CompletedProcess[str]]
Which = Callable[[str], Optional[str]]

_FANOUT = None


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily.

    Lazy (not a top-level import) because the worker arm runs this file on
    compute nodes via ``srun python3 <path> --worker`` and never calls into
    _fanout, so only the orchestrator arm (run_checks.py) pays for the import
    and the sys.path mutation.
    """
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout
        _FANOUT = _fanout
    return _FANOUT


def clipped(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    value = value.strip()
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS] + "...<truncated>"


def display_command(command: list[str]) -> str:
    return " ".join(Path(part).name if part.endswith("/nvidia-smi") else part for part in command)


def is_vboost_unsupported_model(model: str) -> bool:
    return bool(_VBOOST_UNSUPPORTED_GPU_RE.search(model))


def vboost_command(which: Which = shutil.which, euid: Callable[[], int] = os.geteuid) -> tuple[list[str] | None, str]:
    nvidia_smi = which("nvidia-smi")
    if not nvidia_smi:
        return None, "nvidia_smi_missing"
    if euid() == 0:
        return [nvidia_smi, "boost-slider", "--vboost", str(TARGET_VBOOST)], "root"
    sudo = which("sudo")
    if sudo:
        return [sudo, "-n", nvidia_smi, "boost-slider", "--vboost", str(TARGET_VBOOST)], "sudo"
    return [nvidia_smi, "boost-slider", "--vboost", str(TARGET_VBOOST)], "direct"


def local_vboost_result(
    *,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
    euid: Callable[[], int] = os.geteuid,
    hostname: Callable[[], str] = socket.gethostname,
) -> dict[str, Any]:
    command, method = vboost_command(which=which, euid=euid)
    if command is None:
        return {
            "host": hostname(),
            "allowed": False,
            "status": "nvidia_smi_missing",
            "method": method,
            "command": "sudo -n nvidia-smi boost-slider --vboost 2",
            "exit_code": None,
            "stdout": "",
            "stderr": "nvidia-smi not found on PATH",
        }

    try:
        proc = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=COMMAND_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "host": hostname(),
            "allowed": False,
            "status": "timeout",
            "method": method,
            "command": display_command(command),
            "exit_code": None,
            "stdout": clipped(exc.stdout),
            "stderr": clipped(exc.stderr),
        }
    except OSError as exc:
        # nvidia-smi was found on PATH but cannot be executed (e.g. a stub or
        # wrong-arch binary on a non-GPU login node: "Exec format error").
        # Observed on GCore's Soperator login when `bench audit` is run outside
        # an salloc, where vboost falls back to the local host. Report it as a
        # check failure instead of crashing the whole audit.
        return {
            "host": hostname(),
            "allowed": False,
            "status": "nvidia_smi_error",
            "method": method,
            "command": display_command(command),
            "exit_code": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
        }

    allowed = proc.returncode == 0
    return {
        "host": hostname(),
        "allowed": allowed,
        "status": "allowed" if allowed else "denied",
        "method": method,
        "command": display_command(command),
        "exit_code": proc.returncode,
        "stdout": clipped(proc.stdout),
        "stderr": clipped(proc.stderr),
    }


def slurm_vboost_results(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if not env.get("SLURM_JOB_ID") or not which("srun"):
        return [], None

    node_count = env.get("SLURM_NNODES") or "1"
    command = [
        "srun",
        "--overlap",
        "-N",
        node_count,
        "--ntasks-per-node=1",
        "python3",
        str(Path(__file__).resolve()),
        "--worker",
    ]
    try:
        proc = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SLURM_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        return [], {
            "status": "slurm_timeout",
            "command": display_command(command),
            "stdout": clipped(exc.stdout),
            "stderr": clipped(exc.stderr),
        }

    results = load_fanout().parse_json_lines(proc.stdout, require_host=True)
    if proc.returncode != 0 and not results:
        return [], {
            "status": "slurm_failed",
            "command": display_command(command),
            "exit_code": proc.returncode,
            "stdout": clipped(proc.stdout),
            "stderr": clipped(proc.stderr),
        }
    return results, None


def kubectl(
    args: list[str],
    *,
    runner: Runner = subprocess.run,
    timeout: int = KUBECTL_TIMEOUT_S,
) -> subprocess.CompletedProcess[str]:
    return runner(
        ["kubectl", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def k8s_gpu_namespace(*, env: dict[str, str], runner: Runner) -> str | None:
    override = env.get("CLUSTERMAX_GPU_OPERATOR_NAMESPACE")
    if override:
        return override
    for ns in GPU_OPERATOR_NAMESPACES:
        try:
            proc = kubectl(["get", "namespace", ns], runner=runner, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return ns
    return None


def k8s_driver_pod(namespace: str, node: str, *, runner: Runner) -> str | None:
    try:
        proc = kubectl(
            ["get", "pods", "-n", namespace, "--field-selector", f"spec.nodeName={node}", "-o", "json"],
            runner=runner,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        pods = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    candidates: list[tuple[int, str]] = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        phase = item.get("status", {}).get("phase", "")
        if phase != "Running":
            continue
        if "nvidia-driver" in name:
            candidates.append((0, name))
        elif name.startswith("gpu-feature-discovery-"):
            candidates.append((1, name))
        elif name.startswith("nvidia-dcgm-exporter-"):
            candidates.append((2, name))
    return min(candidates)[1] if candidates else None


def k8s_vboost_node(namespace: str, node: str, *, runner: Runner) -> tuple[dict[str, Any] | None, str | None]:
    """Try to set vboost from inside the node's nvidia-driver daemonset pod.

    The driver pod runs privileged with nvidia-smi on PATH, so this exercises
    the same hardware/driver control path the slurm and standalone arms reach
    via sudo, but on an actual GPU node instead of the operator workstation.
    """
    pod = k8s_driver_pod(namespace, node, runner=runner)
    if not pod:
        return None, f"{node}: no running nvidia-smi-capable GPU Operator pod to test vboost"
    command = ["nvidia-smi", "boost-slider", "--vboost", str(TARGET_VBOOST)]
    try:
        proc = kubectl(
            ["exec", "-n", namespace, pod, "--", *command],
            runner=runner,
            timeout=COMMAND_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "host": node,
            "allowed": False,
            "status": "timeout",
            "method": "k8s-driver-pod",
            "command": " ".join(command),
            "exit_code": None,
            "stdout": clipped(exc.stdout),
            "stderr": clipped(exc.stderr),
        }, None
    except OSError as exc:
        return None, f"{node}: vboost exec failed: {exc}"
    allowed = proc.returncode == 0
    return {
        "host": node,
        "allowed": allowed,
        "status": "allowed" if allowed else "denied",
        "method": "k8s-driver-pod",
        "command": " ".join(command),
        "exit_code": proc.returncode,
        "stdout": clipped(proc.stdout),
        "stderr": clipped(proc.stderr),
    }, None


def k8s_vboost_results(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        nodes_proc = kubectl(["get", "nodes", "-o", "json"], runner=runner, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"kubectl get nodes failed: {exc}"]
    if nodes_proc.returncode != 0:
        return [], [f"kubectl get nodes failed: {nodes_proc.stderr.strip()}"]
    try:
        nodes_json = json.loads(nodes_proc.stdout)
    except json.JSONDecodeError as exc:
        return [], [f"kubectl get nodes returned invalid JSON: {exc}"]

    fanout = load_fanout()
    nodes = fanout.k8s_gpu_nodes(nodes_json)
    if not nodes:
        return [], ["no Kubernetes nodes advertise nvidia.com/gpu capacity"]

    namespace = k8s_gpu_namespace(env=env, runner=runner)
    if not namespace:
        return [], ["no NVIDIA GPU Operator namespace found; cannot reach a driver pod to test vboost"]

    try:
        max_nodes = int(str(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS")))
    except (TypeError, ValueError):
        max_nodes = len(nodes)

    return fanout.fan_out_k8s(
        lambda node: k8s_vboost_node(namespace, node["name"], runner=runner),
        nodes=nodes,
        max_nodes=max_nodes,
    )


def aggregate_status(nodes: list[dict[str, Any]]) -> str:
    if not nodes:
        return "not_checked"
    allowed = sum(1 for node in nodes if node.get("allowed") is True)
    if allowed == len(nodes):
        return "allowed"
    if allowed == 0:
        # Every per-node result is a check failure (nvidia-smi absent, a stub /
        # wrong-arch binary that raised OSError, or a timeout): the control was
        # never exercised, so this is missing data, not a provider denial.
        statuses = {str(node.get("status") or "") for node in nodes}
        if statuses and statuses <= {"nvidia_smi_missing", "nvidia_smi_error", "timeout"}:
            return "unavailable"
        return "denied"
    return "partial"


def build_check_payload(
    *,
    harness: str,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
) -> dict[str, Any]:
    gpu_model = env.get("CLUSTERMAX_AUDIT_GPU_MODEL", "")
    if is_vboost_unsupported_model(gpu_model):
        return {
            "gpu_controls": {
                "vboost": {
                    "target": TARGET_VBOOST,
                    "checked": False,
                    "allowed": False,
                    "status": "not_applicable",
                    "mode": harness or "local",
                    "checked_nodes": 0,
                    "allowed_nodes": 0,
                    "nodes": [],
                    "reason": f"{gpu_model} does not implement the vboost slider",
                }
            }
        }

    errors: list[dict[str, Any]] = []
    mode = "local"
    nodes: list[dict[str, Any]]

    if harness == "slurm":
        nodes, error = slurm_vboost_results(env=env, runner=runner, which=which)
        if nodes:
            mode = "slurm"
        else:
            if error:
                errors.append(error)
            nodes = [local_vboost_result(runner=runner, which=which)]
    elif harness == "k8s":
        k8s_nodes, k8s_errors = k8s_vboost_results(env=env, runner=runner)
        for message in k8s_errors:
            errors.append({"status": "k8s", "message": message})
        if k8s_nodes:
            mode = "k8s"
            nodes = k8s_nodes
        else:
            nodes = [local_vboost_result(runner=runner, which=which)]
    else:
        nodes = [local_vboost_result(runner=runner, which=which)]

    allowed_nodes = sum(1 for node in nodes if node.get("allowed") is True)
    status = aggregate_status(nodes)
    vboost: dict[str, Any] = {
        "target": TARGET_VBOOST,
        "checked": bool(nodes),
        "allowed": bool(nodes) and allowed_nodes == len(nodes),
        "status": status,
        "mode": mode,
        "checked_nodes": len(nodes),
        "allowed_nodes": allowed_nodes,
        "nodes": nodes,
    }
    if errors:
        vboost["errors"] = errors
    return {"gpu_controls": {"vboost": vboost}}


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--worker":
        print(json.dumps(local_vboost_result(), sort_keys=True))
        return 0

    harness = os.environ.get("CLUSTERMAX_AUDIT_HARNESS") or os.environ.get("CLUSTERMAX_HARNESS") or ""
    print(json.dumps(build_check_payload(harness=harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
