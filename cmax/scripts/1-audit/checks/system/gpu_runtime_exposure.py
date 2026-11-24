#!/usr/bin/env python3
"""Read GPU runtime exposure facts on each GPU node. No active probes.

The check reads local state only. It sends no request to a service and runs
no exploit code. It collects these facts:

* MIG mode and MIG instance count per GPU, for the MIG timing side channel
  reports (Stealthium "Behind Bars" and "Reading the Work").
* ECC mode on GDDR GPUs, for GPUBreach (GDDR6 Rowhammer).
* CDI specifications that call nvidia-cdi-hook, and the exec monitoring that
  covers that hook (NVIDIA Container Toolkit compromise detection).
* Ray dashboard listeners on port 8265, the dashboard auth mode and the Ray
  version (ShadowRay 2.0, CVE-2023-48022).
* AIStore node processes or images (CVE-2026-65162 and later bulletins).

Each topic gets a status of pass, warning, fail, not_applicable or unknown.
The security CLI grades the AIStore version against the minimum table.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


KEY = "gpu_runtime_exposure"
COMMAND_TIMEOUT_S = 20
SLURM_TIMEOUT_S = 120
KUBECTL_TIMEOUT_S = 60
RAY_DASHBOARD_PORT = 8265
# Ray 2.52.0 added token authentication. It is off unless RAY_AUTH_MODE=token.
RAY_TOKEN_AUTH_RELEASE = (2, 52, 0)
CDI_SPEC_DIRS = ("/etc/cdi", "/var/run/cdi")
AUDIT_RULE_PATHS = ("/etc/audit/audit.rules", "/etc/audit/rules.d")
# Runtime monitors that can record process execution by executable path.
EXEC_MONITORS = ("falco", "tetragon", "tracee", "auditd")
# Loader variables that the Stealthium post names as compromise signs when a
# hook starts with them.
LOADER_VARIABLES = ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")
# GPUs with GDDR memory. HBM GPUs keep ECC on, so GPUBreach does not apply.
_GDDR_GPU_RE = re.compile(
    r"\b(?:A2|A10G?|A16|A40|L4|L20|L40S?|T4|RTX|Quadro|GeForce|TITAN)\b",
    re.IGNORECASE,
)
# The "Behind Bars" study reports no leak on Ampere MIG (A100, A30).
_AMPERE_MIG_RE = re.compile(r"\b(?:A100|A30)\b", re.IGNORECASE)
_MIG_DEVICE_RE = re.compile(r"^\s*MIG\s+\S+\s+Device\s+\d+:", re.IGNORECASE)
_GPU_LINE_RE = re.compile(r"^GPU\s+(\d+):")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

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
    """Import checks/_fanout.py. The worker reads this file through stdin."""
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout
        _FANOUT = _fanout
    return _FANOUT


def _run(command: list[str], runner: Runner, timeout: int = COMMAND_TIMEOUT_S) -> tuple[int | None, str]:
    try:
        proc = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return proc.returncode, proc.stdout or ""


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


# ---------------------------------------------------------------- GPU facts


def parse_gpu_query(text: str) -> list[dict[str, Any]]:
    """Parse `nvidia-smi --query-gpu=index,name,mig.mode.current,ecc.mode.current`."""
    gpus: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        gpus.append(
            {
                "index": int(parts[0]),
                "name": parts[1],
                "mig_mode": parts[2],
                "ecc_mode": parts[3],
                "mig_instances": 0,
            }
        )
    return gpus


def count_mig_instances(listing: str) -> dict[int, int]:
    """Count MIG devices under each GPU in `nvidia-smi -L` output."""
    counts: dict[int, int] = {}
    current: int | None = None
    for line in listing.splitlines():
        gpu = _GPU_LINE_RE.match(line.strip())
        if gpu:
            current = int(gpu.group(1))
            counts.setdefault(current, 0)
            continue
        if current is not None and _MIG_DEVICE_RE.match(line):
            counts[current] += 1
    return counts


def local_gpu_facts(runner: Runner, which: Which) -> dict[str, Any]:
    nvidia_smi = which("nvidia-smi")
    if not nvidia_smi:
        return {"status": "nvidia_smi_missing", "gpus": []}
    code, out = _run(
        [
            nvidia_smi,
            "--query-gpu=index,name,mig.mode.current,ecc.mode.current",
            "--format=csv,noheader",
        ],
        runner,
    )
    if code != 0:
        return {"status": "nvidia_smi_error", "gpus": []}
    gpus = parse_gpu_query(out)
    _, listing = _run([nvidia_smi, "-L"], runner)
    counts = count_mig_instances(listing)
    for gpu in gpus:
        gpu["mig_instances"] = counts.get(gpu["index"], 0)
    return {"status": "ok", "gpus": gpus}


# ------------------------------------------------------------ CDI hook facts


def _iter_files(paths: Iterable[str], suffixes: tuple[str, ...]) -> Iterable[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
        elif path.is_dir():
            try:
                children = sorted(path.iterdir())
            except OSError:
                continue
            for child in children:
                if child.is_file() and child.name.endswith(suffixes):
                    yield child


def cdi_hooks_in_spec(text: str) -> list[dict[str, Any]]:
    """Return the nvidia-cdi-hook entries in one CDI spec (JSON or YAML)."""
    hooks: list[dict[str, Any]] = []
    try:
        payload = json.loads(text)
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        stack: list[Any] = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                path = node.get("path")
                if isinstance(path, str) and path.endswith("nvidia-cdi-hook"):
                    env = [str(item) for item in node.get("env") or [] if isinstance(item, str)]
                    hooks.append(
                        {
                            "path": path,
                            "hook": str(node.get("hookName") or ""),
                            "loader_env": sorted(
                                {item.split("=", 1)[0] for item in env}
                                & set(LOADER_VARIABLES)
                            ),
                        }
                    )
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return hooks
    # YAML spec: read path lines without a YAML dependency on the worker.
    for line in text.splitlines():
        match = re.match(r"^\s*-?\s*path:\s*['\"]?(\S*nvidia-cdi-hook)['\"]?\s*$", line)
        if match:
            hooks.append({"path": match.group(1), "hook": "", "loader_env": []})
    loader = sorted(
        name for name in LOADER_VARIABLES if re.search(rf"\b{name}=", text)
    )
    for hook in hooks:
        hook["loader_env"] = loader
    return hooks


def local_cdi_facts(proc_root: str = "/proc") -> dict[str, Any]:
    specs: list[dict[str, Any]] = []
    unreadable: list[str] = []
    for path in _iter_files(CDI_SPEC_DIRS, (".json", ".yaml", ".yml")):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            unreadable.append(str(path))
            continue
        hooks = cdi_hooks_in_spec(text)
        if hooks:
            specs.append({"file": str(path), "hooks": hooks})
    audit_rules: bool | None = False
    for path in _iter_files(AUDIT_RULE_PATHS, (".rules",)):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            audit_rules = None if audit_rules is False else audit_rules
            continue
        if "nvidia-cdi-hook" in text or re.search(r"-S\s+execve\b", text):
            audit_rules = True
            break
    return {
        "specs": specs,
        "unreadable": unreadable,
        "audit_rules_cover_hook": audit_rules,
        "monitors": sorted(running_processes(EXEC_MONITORS, proc_root)),
    }


# -------------------------------------------------------- process and sockets


def _read(path: Path) -> str:
    try:
        return path.read_bytes().decode(errors="replace")
    except OSError:
        return ""


def iter_processes(proc_root: str = "/proc") -> Iterable[tuple[str, str, list[str]]]:
    """Yield (pid, executable name, argv) for each readable process."""
    root = Path(proc_root)
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.name.isdigit():
            continue
        argv = [part for part in _read(entry / "cmdline").split("\0") if part]
        name = _read(entry / "comm").strip()
        try:
            exe = os.readlink(entry / "exe")
            name = Path(exe).name or name
        except OSError:
            pass
        yield entry.name, name, argv


def running_processes(names: Iterable[str], proc_root: str = "/proc") -> set[str]:
    wanted = set(names)
    found: set[str] = set()
    for _pid, name, argv in iter_processes(proc_root):
        if name in wanted:
            found.add(name)
        elif argv and Path(argv[0]).name in wanted:
            found.add(Path(argv[0]).name)
    return found


def listening_addresses(port: int, proc_root: str = "/proc") -> list[str]:
    """Return the local addresses that listen on TCP `port`."""
    addresses: list[str] = []
    for name, family in (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6)):
        text = _read(Path(proc_root) / "net" / name)
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":  # 0A is LISTEN
                continue
            address, _, hex_port = fields[1].partition(":")
            if int(hex_port, 16) != port:
                continue
            raw = bytes.fromhex(address)
            if family == socket.AF_INET:
                raw = raw[::-1]
            else:
                raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
            addresses.append(socket.inet_ntop(family, raw))
    return sorted(set(addresses))


def is_loopback(address: str) -> bool:
    return address.startswith("127.") or address in {"::1", "::ffff:127.0.0.1"}


def ray_version_from_argv(argv: list[str]) -> str:
    """Read the Ray version from the dist-info next to the dashboard module."""
    for part in argv:
        marker = "/site-packages/ray/"
        if marker not in part and "/dist-packages/ray/" not in part:
            continue
        marker = marker if marker in part else "/dist-packages/ray/"
        site = Path(part.split(marker, 1)[0] + marker.rsplit("/ray/", 1)[0])
        try:
            for child in site.iterdir():
                match = re.fullmatch(r"ray-(\d+\.\d+\.\d+[^-]*)\.dist-info", child.name)
                if match:
                    return match.group(1)
        except OSError:
            continue
    return "unknown"


def local_ray_facts(proc_root: str = "/proc") -> dict[str, Any]:
    dashboards: list[dict[str, Any]] = []
    for pid, _name, argv in iter_processes(proc_root):
        if not any(part.endswith("ray/dashboard/dashboard.py") for part in argv):
            continue
        environ = _read(Path(proc_root) / pid / "environ")
        auth = "unreadable"
        if environ:
            auth = "disabled"
            for item in environ.split("\0"):
                if item.startswith("RAY_AUTH_MODE="):
                    auth = item.split("=", 1)[1] or "disabled"
        dashboards.append({"version": ray_version_from_argv(argv), "auth_mode": auth})
    return {
        "dashboards": dashboards,
        "listen": listening_addresses(RAY_DASHBOARD_PORT, proc_root),
    }


def local_aistore_facts(proc_root: str = "/proc") -> dict[str, Any]:
    return {"processes": len([1 for _p, name, _a in iter_processes(proc_root) if name == "aisnode"])}


def local_result(
    *,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
    hostname: Callable[[], str] = socket.gethostname,
    proc_root: str = "/proc",
) -> dict[str, Any]:
    return {
        "host": hostname(),
        "gpu": local_gpu_facts(runner, which),
        "cdi": local_cdi_facts(proc_root),
        "ray": local_ray_facts(proc_root),
        "aistore": local_aistore_facts(proc_root),
    }


# ------------------------------------------------------------- Kubernetes


def kubectl_json(args: list[str], runner: Runner) -> tuple[Any, str]:
    try:
        proc = runner(
            ["kubectl", *args, "-o", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=KUBECTL_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"kubectl {' '.join(args)} failed: {exc}"
    if proc.returncode != 0:
        return None, f"kubectl {' '.join(args)} failed: {(proc.stderr or '').strip()[:300]}"
    try:
        return json.loads(proc.stdout), ""
    except (TypeError, ValueError) as exc:
        return None, f"kubectl {' '.join(args)} returned invalid JSON: {exc}"


def image_tag(image: str) -> str:
    reference = image.split("@", 1)[0]
    name, separator, tag = reference.rpartition(":")
    return tag if separator and "/" not in tag else ""


def k8s_facts(payloads: dict[str, Any]) -> dict[str, Any]:
    """Summarize Kubernetes API objects. `payloads` holds kubectl JSON lists."""
    nodes = []
    for item in (payloads.get("nodes") or {}).get("items", []):
        labels = item.get("metadata", {}).get("labels", {}) or {}
        capacity = item.get("status", {}).get("capacity", {}) or {}
        mig = sum(
            int(value) for key, value in capacity.items()
            if key.startswith("nvidia.com/mig-") and str(value).isdigit()
        )
        if not labels.get("nvidia.com/gpu.product") and not mig:
            continue
        nodes.append(
            {
                "host": item.get("metadata", {}).get("name", ""),
                "gpu_model": labels.get("nvidia.com/gpu.product", ""),
                "mig_instances": mig,
                "mig_strategy": labels.get("nvidia.com/mig.strategy", ""),
            }
        )
    cdi_enabled = None
    for policy in (payloads.get("clusterpolicies") or {}).get("items", []):
        enabled = ((policy.get("spec") or {}).get("cdi") or {}).get("enabled")
        cdi_enabled = bool(enabled) or bool(cdi_enabled)
    monitors: set[str] = set()
    ray: list[dict[str, Any]] = []
    aistore: list[dict[str, Any]] = []
    for pod in (payloads.get("pods") or {}).get("items", []):
        meta = pod.get("metadata", {}) or {}
        if (pod.get("status") or {}).get("phase") in ("Succeeded", "Failed"):
            continue
        labels = meta.get("labels", {}) or {}
        for container in (pod.get("spec") or {}).get("containers", []) or []:
            image = str(container.get("image") or "")
            lowered = image.lower()
            for monitor in EXEC_MONITORS:
                if f"/{monitor}" in lowered or lowered.startswith(monitor):
                    monitors.add(monitor)
            if "aistorage/aisnode" in lowered:
                aistore.append(
                    {"namespace": meta.get("namespace", ""), "pod": meta.get("name", ""),
                     "version": image_tag(image).lstrip("v").split("-", 1)[0] or "unknown"}
                )
            if labels.get("ray.io/node-type") == "head" or (
                "rayproject/ray" in lowered and "ray.io/node-type" not in labels
            ):
                auth = "disabled"
                for env in container.get("env") or []:
                    if env.get("name") == "RAY_AUTH_MODE":
                        auth = str(env.get("value") or "set-from-reference")
                tag = image_tag(image)
                ray.append(
                    {"namespace": meta.get("namespace", ""), "pod": meta.get("name", ""),
                     "version": tag.split("-", 1)[0] if parse_version(tag) else "unknown",
                     "auth_mode": auth}
                )
    exposed: list[str] = []
    for service in (payloads.get("services") or {}).get("items", []):
        spec = service.get("spec") or {}
        if spec.get("type") not in ("NodePort", "LoadBalancer"):
            continue
        for port in spec.get("ports") or []:
            if RAY_DASHBOARD_PORT in (port.get("port"), port.get("targetPort")):
                meta = service.get("metadata", {}) or {}
                exposed.append(f"{meta.get('namespace', '')}/{meta.get('name', '')} ({spec['type']})")
    return {
        "nodes": nodes,
        "cdi_enabled": cdi_enabled,
        "monitors": sorted(monitors),
        "ray": ray,
        "ray_exposed_services": exposed,
        "aistore": aistore,
    }


def k8s_gpu_query(namespace: str, node: str, runner: Runner) -> tuple[dict[str, Any] | None, str | None]:
    """Run the read-only nvidia-smi query in the node's GPU Operator pod."""
    pods, error = kubectl_json(
        ["get", "pods", "-n", namespace, "--field-selector", f"spec.nodeName={node}"], runner
    )
    if pods is None:
        return None, f"{node}: {error}"
    names = sorted(
        item["metadata"]["name"] for item in pods.get("items", [])
        if (item.get("status") or {}).get("phase") == "Running"
        and str(item.get("metadata", {}).get("name", "")).startswith(
            ("nvidia-driver", "nvidia-device-plugin", "gpu-feature-discovery", "nvidia-dcgm-exporter")
        )
    )
    if not names:
        return None, f"{node}: no running GPU Operator pod with nvidia-smi"
    code, out = _run(
        ["kubectl", "exec", "-n", namespace, names[0], "--", "nvidia-smi",
         "--query-gpu=index,name,mig.mode.current,ecc.mode.current", "--format=csv,noheader"],
        runner,
    )
    if code != 0:
        return None, f"{node}: nvidia-smi query failed in {names[0]}"
    gpus = parse_gpu_query(out)
    _, listing = _run(["kubectl", "exec", "-n", namespace, names[0], "--", "nvidia-smi", "-L"], runner)
    counts = count_mig_instances(listing)
    for gpu in gpus:
        gpu["mig_instances"] = counts.get(gpu["index"], 0)
    return {"host": node, "gpu": {"status": "ok", "gpus": gpus}}, None


def k8s_results(env: dict[str, str], runner: Runner) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    errors: list[str] = []
    payloads: dict[str, Any] = {}
    for name, args in (
        ("nodes", ["get", "nodes"]),
        ("pods", ["get", "pods", "-A"]),
        ("services", ["get", "services", "-A"]),
        ("clusterpolicies", ["get", "clusterpolicies.nvidia.com"]),
    ):
        payload, error = kubectl_json(args, runner)
        if payload is None and name != "clusterpolicies":
            errors.append(error)
        payloads[name] = payload or {}
    summary = k8s_facts(payloads)
    hosts: list[dict[str, Any]] = []
    nodes = [node for node in summary["nodes"] if node["host"]]
    namespace = env.get("CLUSTERMAX_GPU_OPERATOR_NAMESPACE") or next(
        (
            ns for ns in GPU_OPERATOR_NAMESPACES
            if any(
                (pod.get("metadata") or {}).get("namespace") == ns
                for pod in (payloads.get("pods") or {}).get("items", [])
            )
        ),
        None,
    )
    if nodes and namespace:
        fanout = load_fanout()
        max_nodes = fanout.k8s_max_host_checks(env, len(nodes))
        records, fan_errors = fanout.fan_out_k8s(
            lambda node: k8s_gpu_query(namespace, node["host"], runner),
            nodes=nodes,
            max_nodes=max_nodes,
        )
        hosts.extend(records)
        errors.extend(fan_errors)
    elif nodes:
        errors.append("no NVIDIA GPU Operator namespace found; GPU MIG and ECC modes come from node labels only")
    return hosts, summary, errors


def slurm_results(env: dict[str, str], runner: Runner, which: Which) -> tuple[list[dict[str, Any]], list[str]]:
    if not env.get("SLURM_JOB_ID") or not which("srun"):
        return [], ["no Slurm allocation; no compute node was read"]
    fanout = load_fanout()
    node_count = env.get("SLURM_NNODES") or "1"
    command = fanout.slurm_python_command(
        node_count=node_count,
        worker_args=["--worker"],
        gpus_per_node=fanout.slurm_gpus_per_node(env, runner),
    )
    try:
        proc = runner(
            command,
            input=Path(__file__).read_text(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SLURM_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], [f"srun failed: {exc}"]
    results = fanout.parse_json_lines(proc.stdout, require_host=True)
    errors = []
    if proc.returncode != 0:
        errors.append(f"srun exited {proc.returncode} after {len(results)} worker result(s)")
    if node_count.isdigit() and len(results) < int(node_count):
        errors.append(f"only {len(results)} of {node_count} allocated node(s) reported")
    return results, errors


# ---------------------------------------------------------------- grading


def _verdict(status: str, message: str, **evidence: Any) -> dict[str, Any]:
    return {"status": status, "message": message, **evidence}


def grade_mig(gpus: list[dict[str, Any]], k8s_nodes: list[dict[str, Any]], complete: bool) -> dict[str, Any]:
    shared = []
    ampere = []
    for gpu in gpus:
        if str(gpu.get("mig_mode", "")).lower() != "enabled" or gpu.get("mig_instances", 0) < 2:
            continue
        entry = f"{gpu.get('host', '')} GPU {gpu.get('index')} {gpu.get('name', '')}: {gpu['mig_instances']} MIG instances"
        (ampere if _AMPERE_MIG_RE.search(str(gpu.get("name", ""))) else shared).append(entry)
    for node in k8s_nodes:
        if node.get("mig_instances", 0) >= 2:
            entry = f"{node['host']} {node.get('gpu_model', '')}: {node['mig_instances']} MIG devices advertised"
            (ampere if _AMPERE_MIG_RE.search(str(node.get("gpu_model", ""))) else shared).append(entry)
    if shared:
        return _verdict(
            "warning",
            "MIG partitions more than one instance on a GPU. If different tenants get instances "
            "of one GPU, a tenant can infer the work of a co-located tenant through cross-partition "
            "timing side channels. MIG does not isolate shared timing resources.",
            partitions=sorted(shared),
        )
    if ampere:
        return _verdict(
            "pass",
            "MIG is shared only on Ampere GPUs, for which the published study found no leak.",
            partitions=sorted(ampere),
        )
    if not gpus and not k8s_nodes:
        return _verdict("unknown", "No GPU was read, so MIG sharing is not known.")
    if not complete:
        return _verdict("unknown", "Some GPU nodes were not read, so MIG sharing is not known for them.")
    return _verdict("not_applicable", "No GPU has more than one MIG instance.")


def grade_ecc(gpus: list[dict[str, Any]], complete: bool) -> dict[str, Any]:
    gddr = [gpu for gpu in gpus if _GDDR_GPU_RE.search(str(gpu.get("name", "")))]
    if not gpus:
        return _verdict("unknown", "No GPU ECC mode was read.")
    disabled = sorted(
        f"{gpu.get('host', '')} GPU {gpu.get('index')} {gpu.get('name', '')}: ECC {gpu.get('ecc_mode', '')}"
        for gpu in gddr
        if str(gpu.get("ecc_mode", "")).lower() != "enabled"
    )
    if disabled:
        return _verdict(
            "warning",
            "A GDDR GPU runs without ECC. GPUBreach uses GDDR6 Rowhammer bit flips in GPU page "
            "table entries to reach a root shell on the host, and NVIDIA recommends "
            "System-Level ECC as the mitigation.",
            gpus=disabled,
        )
    if gddr:
        return _verdict("pass", "ECC is enabled on every GDDR GPU that was read.")
    if not complete:
        return _verdict("unknown", "Some GPU nodes were not read.")
    return _verdict("not_applicable", "No GDDR GPU was found. HBM GPUs keep ECC on.")


def grade_cdi(hosts: list[dict[str, Any]], k8s: dict[str, Any] | None) -> dict[str, Any]:
    with_hooks = []
    unmonitored = []
    loader = []
    unreadable = []
    for host in hosts:
        cdi = host.get("cdi") or {}
        if cdi.get("unreadable"):
            unreadable.append(host.get("host", ""))
        if not cdi.get("specs"):
            continue
        with_hooks.append(host.get("host", ""))
        for spec in cdi["specs"]:
            for hook in spec.get("hooks", []):
                if hook.get("loader_env"):
                    loader.append(f"{host.get('host', '')} {spec['file']}: {', '.join(hook['loader_env'])}")
        monitors = set(cdi.get("monitors") or ())
        if k8s:
            monitors.update(k8s.get("monitors") or ())
        covered = bool(monitors - {"auditd"}) or (
            "auditd" in monitors and cdi.get("audit_rules_cover_hook") is True
        )
        if not covered:
            unmonitored.append(host.get("host", ""))
    if loader:
        return _verdict(
            "fail",
            "A CDI hook entry for nvidia-cdi-hook sets a loader variable. The Stealthium report names "
            "LD_PRELOAD, LD_AUDIT and LD_LIBRARY_PATH on this hook as signs of compromise.",
            hooks=sorted(loader),
        )
    if unmonitored:
        return _verdict(
            "warning",
            "CDI specifications run nvidia-cdi-hook as root at container creation, and no exec "
            "monitor (Falco, Tetragon, Tracee, or an auditd execve rule) was found on these hosts.",
            hosts=sorted(unmonitored),
        )
    if with_hooks:
        return _verdict("pass", "An exec monitor runs on every host with nvidia-cdi-hook CDI hooks.", hosts=sorted(with_hooks))
    if k8s and k8s.get("cdi_enabled"):
        if k8s.get("monitors"):
            return _verdict("pass", "GPU Operator CDI is enabled and an exec monitor runs in the cluster.")
        return _verdict(
            "warning",
            "GPU Operator CDI is enabled, so nvidia-cdi-hook runs as root at container creation, and "
            "no Falco, Tetragon or Tracee pod was found.",
        )
    if unreadable:
        return _verdict("unknown", "Some CDI specifications could not be read.", hosts=sorted(set(unreadable)))
    if not hosts and not k8s:
        return _verdict("unknown", "No host was read.")
    return _verdict("not_applicable", "No CDI specification calls nvidia-cdi-hook.")


def grade_ray(hosts: list[dict[str, Any]], k8s: dict[str, Any] | None) -> dict[str, Any]:
    exposed = []
    local_only = []
    versions = set()
    for host in hosts:
        ray = host.get("ray") or {}
        dashboards = ray.get("dashboards") or []
        listen = ray.get("listen") or []
        for dashboard in dashboards:
            versions.add(dashboard.get("version", "unknown"))
        if not listen:
            continue
        public = [address for address in listen if not is_loopback(address)]
        modes = {str(item.get("auth_mode", "unreadable")).lower() for item in dashboards} or {"unreadable"}
        entry = f"{host.get('host', '')} listens on {', '.join(listen)}:{RAY_DASHBOARD_PORT}; RAY_AUTH_MODE={'/'.join(sorted(modes))}"
        if public and modes != {"token"}:
            exposed.append(entry)
        else:
            local_only.append(entry)
    if k8s:
        heads = k8s.get("ray") or []
        for head in heads:
            versions.add(head.get("version", "unknown"))
        services = k8s.get("ray_exposed_services") or []
        if services and any(head.get("auth_mode") != "token" for head in heads or [{}]):
            exposed.extend(f"Service {service} exposes port {RAY_DASHBOARD_PORT}" for service in services)
        elif heads:
            local_only.extend(f"{head['namespace']}/{head['pod']} RAY_AUTH_MODE={head['auth_mode']}" for head in heads)
    old = sorted(
        version for version in versions
        if parse_version(version) and parse_version(version) < RAY_TOKEN_AUTH_RELEASE
    )
    if exposed:
        return _verdict(
            "fail",
            "A Ray dashboard and Jobs API on port 8265 is reachable beyond loopback without token "
            "authentication. Anyone who reaches the port can submit a job and run code on the "
            "cluster (ShadowRay 2.0, CVE-2023-48022).",
            endpoints=sorted(exposed),
            versions=sorted(versions),
        )
    if local_only:
        status = "warning" if old else "pass"
        message = (
            "The Ray dashboard listens on loopback only or requires a token."
            if not old
            else "The Ray dashboard is not exposed, but Ray is older than 2.52.0 and cannot enforce token authentication."
        )
        return _verdict(status, message, endpoints=sorted(local_only), versions=sorted(versions))
    if not hosts and not k8s:
        return _verdict("unknown", "No host was read.")
    return _verdict("not_applicable", "No Ray dashboard was found.")


def aistore_minimum() -> tuple[str, str]:
    """Read the AIStore minimum and bulletin from the installed minimum table."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        import minimum_versions

        block = minimum_versions.component("aistore")
    except Exception:  # noqa: BLE001 - a missing table leaves the grade unknown
        return "", ""
    minimum = block.get("minimum")
    advisory = block.get("advisory")
    return (
        minimum if isinstance(minimum, str) else "",
        advisory if isinstance(advisory, str) else "",
    )


def _aistore_key(version: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", version.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _aistore_status(version: str, minimum: str) -> str:
    found, floor = _aistore_key(version), _aistore_key(minimum) if minimum else None
    if found is None or floor is None:
        return "unknown"
    return "fail" if found < floor else "pass"


def grade_aistore(hosts: list[dict[str, Any]], k8s: dict[str, Any] | None) -> dict[str, Any]:
    deployments = []
    for host in hosts:
        if (host.get("aistore") or {}).get("processes"):
            deployments.append({"where": host.get("host", ""), "version": "unknown"})
    for item in (k8s or {}).get("aistore") or []:
        deployments.append({"where": f"{item['namespace']}/{item['pod']}", "version": item["version"]})
    if deployments:
        minimum, advisory = aistore_minimum()
        for item in deployments:
            item["status"] = _aistore_status(item["version"], minimum)
        statuses = {item["status"] for item in deployments}
        version_status = (
            "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
        )
        return _verdict(
            "present",
            f"AIStore runs in {len(deployments)} place(s).",
            deployments=deployments,
            minimum=minimum or None,
            advisory=advisory or None,
            versionStatus=version_status,
        )
    if not hosts and not k8s:
        return _verdict("unknown", "No host was read.")
    return _verdict("not_applicable", "No AIStore node was found.")


def build_payload(
    *,
    harness: str,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
) -> dict[str, Any]:
    errors: list[str] = []
    k8s: dict[str, Any] | None = None
    if harness == "slurm":
        hosts, errors = slurm_results(env, runner, which)
    elif harness == "k8s":
        hosts, k8s, errors = k8s_results(env, runner)
    else:
        hosts = [local_result(runner=runner, which=which)]
    gpus = []
    for host in hosts:
        for gpu in (host.get("gpu") or {}).get("gpus") or []:
            gpus.append({**gpu, "host": host.get("host", "")})
    complete = not errors
    k8s_nodes = [] if gpus else list((k8s or {}).get("nodes") or [])
    no_nvidia = bool(hosts) and not k8s_nodes and all(
        (host.get("gpu") or {}).get("status") == "nvidia_smi_missing" for host in hosts
    )
    if no_nvidia:
        absent = _verdict("not_applicable", "nvidia-smi is not installed on the audited hosts.")
        mig, ecc = absent, dict(absent)
    else:
        mig, ecc = grade_mig(gpus, k8s_nodes, complete), grade_ecc(gpus, complete)
    topics = {
        "mig": mig,
        "ecc": ecc,
        "cdiHooks": grade_cdi(hosts, k8s),
        "ray": grade_ray(hosts, k8s),
        "aistore": grade_aistore(hosts, k8s),
    }
    order = {"fail": 0, "warning": 1, "unknown": 2, "present": 3, "pass": 4, "not_applicable": 5}
    worst = min((item["status"] for item in topics.values()), key=lambda s: order.get(s, 2))
    worst = {"present": "pass"}.get(worst, worst)
    flagged = [name for name, item in topics.items() if item["status"] in {"fail", "warning"}]
    message = (
        "findings: " + ", ".join(flagged) if flagged
        else f"read {len(hosts)} host(s); no exposure found"
    )
    payload: dict[str, Any] = {
        "status": worst,
        "message": message,
        "mode": harness or "standalone",
        "checked_hosts": len(hosts),
        **topics,
    }
    if errors:
        payload["errors"] = errors
    return {KEY: payload}


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--worker":
        print(json.dumps(local_result(), sort_keys=True))
        return 0
    harness = os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "")
    print(json.dumps(build_payload(harness=harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
