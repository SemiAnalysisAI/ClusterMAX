#!/usr/bin/env python3
"""NIC topology check + classifier.

Emits one check object to stdout:

    {"nic_topology": {"worker-0": [{"name": "mlx5_0", "role": "fabric", ...}], ...}}

Self-dispatches by harness (``CLUSTERMAX_AUDIT_HARNESS`` / ``CLUSTERMAX_HARNESS``):

* ``slurm``      - srun one ``--collect-host`` worker per node, aggregate the
  per-node JSON lines.
* ``k8s``        - for each GPU node, exec a POSIX-sh collector inside that
  node's nvidia-driver daemonset pod (it has ``nvidia-smi`` and host IB sysfs but
  NO python3), then parse + classify its raw output on the orchestrator.
  Mirrors the per-node daemonset exec the k8s collector already uses for its
  host/storage checks.
* otherwise      - run the worker on the local host (standalone).

Worker mode (``--collect-host``) emits ONE line of JSON for the current host:

    {"host": "worker-0", "nics": [{"name": "mlx5_0", "role": "fabric", ...}, ...],
     "topo_collected": true}

Classifies each /sys/class/infiniband HCA as fabric / storage / frontend using
nvidia-smi topo -m output + per-port rate + link layer. Non-RDMA ethernet NICs
go straight to frontend.

When the ``nvidia-smi topo -m`` collection fails or times out on a host, the
check never crashes the audit: classification proceeds without GPU affinity
(RDMA HCAs then fall back to the storage / frontend heuristics). The
degradation is recorded instead of silent: the host record carries
``topo_collected: false`` plus a short ``topo_error`` reason ("timeout", an
exception class, or "no output (exit N)"), the aggregated payload gains a
sibling ``nic_topology_status`` key listing only the degraded hosts, and one
WARNING line goes to stderr. ``nic_topology`` itself keeps its
host -> NIC-list shape unchanged.

Heuristics:
  fabric   : RDMA HCA with PIX, PXB, or PHB affinity to >=1 GPU. These are the
             NICs NCCL_IB_HCA should point at.
  storage  : RDMA HCA with no close-GPU affinity (NODE / SYS) but high
             link rate (>= 100 Gb/s). Usually wired to a separate storage
             fabric (Weka, VAST, Lustre, etc).
  frontend : non-RDMA NIC, or RDMA NIC running Ethernet at < 100 Gb/s.
             Internet / control-plane / SSH / package install.

Superchip (GB200/GB300 NVL) affinity fallback: on Grace superchips the GPU
hangs off NVLink-C2C rather than PCIe, so ``nvidia-smi topo -m`` reports every
NIC as NODE/SYS and the close-affinity rule can never fire -- whole NVL72
fleets came back with zero ``fabric`` NICs (every scale-out HCA binned
``storage``). When the first pass produces no fabric HCA at all,
``fabric_affinity_fallback()`` recovers the scale-out set from rail naming
(``mlx5_rail0``, ``rdma_vf_rail2``, ...) or, failing that, from the >=2 ACTIVE
InfiniBand HCAs tied at the top IB rate >= 200 Gb/s (the planarized 4x800G XDR
presentation). Bond devices never promote, and the promotion reason records
that the GPU-affinity signal was unavailable.

Kubernetes harness environment variables:

* ``CLUSTERMAX_GPU_OPERATOR_NAMESPACE`` - GPU operator namespace override (default:
  autodetected from gpu-operator / gpu-operator-resources / nvidia-gpu-operator /
  gpu).
* ``CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS`` - cap the number of GPU nodes checked
  (default: all GPU nodes).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

Runner = Callable[..., subprocess.CompletedProcess]

# Namespaces the NVIDIA GPU Operator installs into, in the same order the k8s
# collector checks them.
GPU_OPERATOR_NAMESPACES = (
    "gpu-operator",
    "gpu-operator-resources",
    "nvidia-gpu-operator",
    "nvidia",
    "gpu",
)
SLURM_TIMEOUT_S = 120
KUBECTL_TIMEOUT_S = 60

_FANOUT = None


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily.

    Lazy (not a top-level import) because the worker arm runs this file on
    compute nodes via ``srun sys.executable <path> --collect-host`` and never
    calls into _fanout, so only the orchestrator arm (run_checks.py) pays for
    the import and the sys.path mutation.
    """
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout
        _FANOUT = _fanout
    return _FANOUT


def collect_topo(*, runner: Runner = subprocess.run) -> tuple[str, str | None]:
    """``nvidia-smi topo -m`` stdout plus a short failure reason (None on success).

    Never raises: the check must not crash the audit when nvidia-smi hangs or
    errors on a worker. The reason string ("timeout", the exception class, or
    "no output (exit N)") is recorded per host so an empty topo degrades
    classification visibly instead of silently.
    """
    try:
        proc = runner(
            ["nvidia-smi", "topo", "-m"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except Exception as exc:
        return "", type(exc).__name__
    if not proc.stdout.strip():
        return "", f"no output (exit {proc.returncode})"
    return proc.stdout, None


def parse_rate(s: str) -> float:
    m = re.match(r"(\d+(?:\.\d+)?)\s*Gb", s)
    return float(m.group(1)) if m else 0.0


def parse_topo(topo: str) -> tuple[dict, dict]:
    # nvidia-smi topo -m header: GPU0 GPU1 ... NIC0 NIC1 ... CPU Affinity ...
    # For each NIC row, look at GPU columns. PIX, PXB, or PHB anywhere =
    # "close". HGX systems can attach their compute HCAs to the same PCIe host
    # bridge as a GPU without an intervening PCIe switch, which nvidia-smi
    # reports as PHB.
    # Some recent nvidia-smi builds underline the header even when kubectl exec
    # is non-interactive. Strip CSI formatting before looking for GPU0; without
    # this the first GPU data row is mistaken for the header and most NICs lose
    # their GPU affinity.
    topo = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", topo)
    nic_gpu_affinity: dict = {}
    header = None
    header_idx = -1
    if topo:
        lines = [l.rstrip() for l in topo.splitlines()]
        for i, l in enumerate(lines):
            toks = l.split()
            if toks and toks[0].startswith("GPU0"):
                header = toks
                header_idx = i
                break
        if header:
            for l in lines[header_idx + 1:]:
                toks = l.split()
                if not toks:
                    continue
                row = toks[0]
                if not (row.startswith("NIC") or row.startswith("mlx") or
                        row.startswith("ibp") or row.startswith("roce")):
                    continue
                cells = toks[1:1 + len(header)]
                aff = "far"
                for h, c in zip(header, cells):
                    if h.startswith("GPU") and c in ("PIX", "PXB", "PHB"):
                        aff = "close"
                        break
                nic_gpu_affinity[row] = aff

    # nvidia-smi topo -m's "NIC Legend:" maps NIC0 -> sysfs name (mlx5_0 etc).
    nic_label_to_name: dict = {}
    m = re.search(r"NIC Legend:\s*(.*)", topo, re.DOTALL)
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r"\s*(NIC\d+):\s*(\S+)", line)
            if mm:
                nic_label_to_name[mm.group(1)] = mm.group(2)
    return nic_gpu_affinity, nic_label_to_name


def fabric_affinity_fallback(hcas: list, assigned: dict) -> dict:
    """Names of RDMA HCAs to promote to fabric when GPU affinity is degenerate.

    ``assigned`` maps HCA name -> first-pass role. Empty result when the first
    pass already found any fabric HCA (HGX systems, where PIX/PXB/PHB works).
    Otherwise -- Grace superchips (GPU on C2C, every NIC NODE/SYS) or hosts
    where ``nvidia-smi topo -m`` failed -- recover the scale-out set:

    * rail naming: ACTIVE rail-named HCAs at >= 100 Gb/s are the
      provider-labelled scale-out rails (Firmus ``mlx5_rail0..3``, OCI
      ``rdma_vf_rail0..3``). DOWN rail PFs behind active VFs stay unpromoted.
    * planarized IB: else the >= 2 ACTIVE InfiniBand HCAs tied at the top IB
      rate >= 200 Gb/s (the 4x800G XDR presentation on GB300 NVL72). A single
      IB HCA never promotes: it is as likely a storage NIC.

    Bond devices (``mlx5_bond_*``) never promote. Returns {name: reason}.
    """
    if any(role == "fabric" for role in assigned.values()):
        return {}

    def eligible(name: str, rate: float, state: str) -> bool:
        return "bond" not in name and state == "ACTIVE" and rate >= 100

    rails = [
        name for name, rate, layer, state in hcas
        if "rail" in name and eligible(name, rate, state)
    ]
    if rails:
        return {
            name: "rail-named RDMA HCA; no GPU-affinity signal on this platform"
            for name in rails
        }

    ib = [
        (name, rate) for name, rate, layer, state in hcas
        if layer == "InfiniBand" and rate >= 200 and eligible(name, rate, state)
    ]
    if not ib:
        return {}
    top = max(rate for _, rate in ib)
    group = [name for name, rate in ib if rate == top]
    if len(group) < 2:
        return {}
    return {
        name: (
            f"InfiniBand at top fabric rate ({int(top)} Gb/s); "
            "no GPU-affinity signal on this platform"
        )
        for name in group
    }


def classify_nics(topo: str, hcas: list, netdevs: list) -> list:
    """Build the per-NIC role list from raw inputs.

    ``hcas`` is a list of ``(name, rate_gbps_float, link_layer, state)`` and
    ``netdevs`` a list of ``(name, speed_mbps_int)`` for non-RDMA frontend NICs.
    Pure: the slurm/standalone path collects these from local sysfs, the k8s
    path collects them with a shell snippet inside the driver pod. Same classes.
    """
    nic_gpu_affinity, nic_label_to_name = parse_topo(topo)

    def classify(name: str, rate: float, layer: str):
        if layer != "InfiniBand" and rate < 100:
            return "frontend", "low-rate non-IB"
        label = next((lbl for lbl, n in nic_label_to_name.items() if n == name), None)
        aff = nic_gpu_affinity.get(label) if label else nic_gpu_affinity.get(name)
        if aff == "close":
            return "fabric", "PIX, PXB, or PHB to >=1 GPU"
        if rate >= 100 and layer in ("InfiniBand", "Ethernet"):
            return "storage", "high-rate RDMA, no close-GPU affinity"
        return "frontend", "fallback"

    first_pass = {}
    for name, rate, layer, state in hcas:
        first_pass[name] = classify(name, rate, layer)

    promoted = fabric_affinity_fallback(
        hcas, {name: role for name, (role, _) in first_pass.items()}
    )

    nics = []
    for name, rate, layer, state in hcas:
        role, reason = first_pass[name]
        if name in promoted:
            role, reason = "fabric", promoted[name]
        nics.append({
            "name": name,
            "role": role,
            "rate_gbps": int(rate),
            "layer": layer,
            "state": state,
            "reason": reason,
        })

    # Non-RDMA netdevs - frontend by definition.
    for name, speed_mbps in netdevs:
        nics.append({
            "name": name,
            "role": "frontend",
            "rate_gbps": speed_mbps // 1000 if speed_mbps > 0 else 0,
            "layer": "ethernet",
            "state": "?",
            "reason": "no infiniband sysfs link",
        })
    return nics


def _collect_hcas_local() -> list:
    """Per-HCA rate / link layer / state from local sysfs."""
    hcas = []
    for path in sorted(glob.glob("/sys/class/infiniband/*")):
        name = os.path.basename(path)
        if name.startswith("bond"):
            continue
        try:
            rate = parse_rate(open(path + "/ports/1/rate").read())
        except OSError:
            rate = 0.0
        try:
            layer = open(path + "/ports/1/link_layer").read().strip()
        except OSError:
            layer = "?"
        try:
            state = open(path + "/ports/1/state").read().split(":")[1].split()[0]
        except (OSError, IndexError):
            state = "?"
        hcas.append((name, rate, layer, state))
    return hcas


def _collect_netdevs_local() -> list:
    """Non-RDMA frontend netdevs (name, speed_mbps) from local sysfs."""
    netdevs = []
    for path in sorted(glob.glob("/sys/class/net/*")):
        n = os.path.basename(path)
        if n == "lo" or n.startswith(("veth", "docker", "cni", "cali")):
            continue
        if os.path.exists("/sys/class/net/" + n + "/device/infiniband"):
            continue
        if not os.path.exists("/sys/class/net/" + n + "/device"):
            continue
        try:
            speed_mbps = open("/sys/class/net/" + n + "/speed").read().strip()
            speed_mbps = int(speed_mbps) if speed_mbps.lstrip("-").isdigit() else 0
        except (OSError, ValueError):
            speed_mbps = 0
        netdevs.append((n, speed_mbps))
    return netdevs


def gather(*, runner: Runner = subprocess.run) -> dict:
    topo, topo_error = collect_topo(runner=runner)
    nics = classify_nics(topo, _collect_hcas_local(), _collect_netdevs_local())
    host = os.environ.get("NODE_NAME") or socket.gethostname()
    record: dict[str, Any] = {"host": host, "nics": nics, "topo_collected": topo_error is None}
    if topo_error is not None:
        record["topo_error"] = topo_error
    return record


# ---------------------------------------------------------------------------
# Fan-out orchestration (slurm / k8s / local), aggregated into nic_topology.
# ---------------------------------------------------------------------------


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    nic_topology: dict[str, Any] = {}
    for record in records:
        host = str(record.get("host") or "")
        if not host:
            continue
        nic_topology[host] = record.get("nics", [])
    return nic_topology


def topo_status(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Hosts whose ``nvidia-smi topo -m`` collection failed, keyed by host.

    Only degraded hosts appear (a record without the ``topo_collected`` key is
    treated as collected), so the ``nic_topology_status`` payload key is absent
    when every checked host produced topo output. Kept as a sibling of
    ``nic_topology`` because that mapping's host -> NIC-list shape is consumed
    as-is by merge_audit.py.
    """
    status: dict[str, Any] = {}
    for record in records:
        host = str(record.get("host") or "")
        if not host or record.get("topo_collected") is not False:
            continue
        entry: dict[str, Any] = {"topo_collected": False}
        topo_error = record.get("topo_error")
        if topo_error:
            entry["topo_error"] = str(topo_error)
        status[host] = entry
    return status


def slurm_records(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not env.get("SLURM_JOB_ID"):
        return [gather()], ["SLURM_JOB_ID is not set; NIC topology only checked the local host"]

    node_count = env.get("SLURM_NNODES") or "1"
    command = [
        "srun",
        "--overlap",
        "-N",
        node_count,
        "--ntasks-per-node=1",
        sys.executable,
        str(Path(__file__).resolve()),
        "--collect-host",
    ]
    try:
        proc = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=SLURM_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [gather()], [f"srun NIC check failed; local host only: {exc}"]

    records = load_fanout().parse_json_lines(proc.stdout, require_host=True)
    errors: list[str] = []
    if proc.returncode != 0 and not records:
        errors.append(f"srun NIC check exited {proc.returncode}: {proc.stderr.strip()}")
        return [gather()], errors
    if not records:
        return [gather()], ["srun NIC check returned no host JSON; local host only"]
    return records, errors


def kubectl(
    args: list[str],
    *,
    runner: Runner = subprocess.run,
    timeout: int = KUBECTL_TIMEOUT_S,
) -> subprocess.CompletedProcess:
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
    try:
        proc = kubectl(["get", "namespaces", "-o", "json"], runner=runner, timeout=30)
        namespaces = json.loads(proc.stdout) if proc.returncode == 0 else {"items": []}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        namespaces = {"items": []}
    matches = sorted(
        item.get("metadata", {}).get("name", "")
        for item in namespaces.get("items", [])
        if re.search(r"gpu-operator|nvidia-gpu", item.get("metadata", {}).get("name", ""), re.I)
    )
    if matches:
        return matches[0]
    return None


def k8s_driver_pod(namespace: str, node: str, *, runner: Runner) -> dict[str, Any] | None:
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
    candidates: list[tuple[int, str, str | None, bool]] = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        phase = item.get("status", {}).get("phase", "")
        if phase != "Running":
            continue
        volumes = {
            volume.get("name")
            for volume in item.get("spec", {}).get("volumes", [])
            if volume.get("hostPath", {}).get("path") == "/"
        }
        if "nvidia-driver" in name:
            candidates.append((0, name, None, False))
        elif "nvidia-device-plugin" in name:
            for container in item.get("spec", {}).get("containers", []):
                host_root = any(
                    mount.get("name") in volumes and mount.get("mountPath") == "/host"
                    for mount in container.get("volumeMounts", [])
                )
                if host_root and container.get("securityContext", {}).get("privileged") is True:
                    candidates.append((1, name, container.get("name"), True))
        elif name.startswith("gpu-feature-discovery-"):
            candidates.append((2, name, None, False))
        elif name.startswith("nvidia-dcgm-exporter-"):
            candidates.append((3, name, None, False))
    if not candidates:
        return None
    _, name, container, host_root = min(candidates)
    return {"name": name, "container": container, "hostRoot": host_root}


# Shell collector run inside the driver pod. The nvidia-driver daemonset image
# carries nvidia-smi and host IB/net sysfs but NOT python3, so the worker cannot
# run there as python. This POSIX-sh snippet emits the same raw inputs
# classify_nics() needs (topo text + per-HCA rate/layer/state + frontend
# netdevs), tab-delimited, and the orchestrator (which has python3) parses and
# classifies them. Mirrors the local sysfs reads in _collect_*_local().
K8S_COLLECTOR_SH = r'''
echo @@TOPO_BEGIN@@
nvidia-smi topo -m 2>/dev/null
echo @@TOPO_END@@
for d in /sys/class/infiniband/*; do
  [ -e "$d" ] || continue
  n=$(basename "$d")
  case "$n" in bond*) continue;; esac
  r=$(cat "$d/ports/1/rate" 2>/dev/null)
  l=$(cat "$d/ports/1/link_layer" 2>/dev/null)
  s=$(cat "$d/ports/1/state" 2>/dev/null)
  printf '@@HCA@@\t%s\t%s\t%s\t%s\n' "$n" "$r" "$l" "$s"
done
for p in /sys/class/net/*; do
  n=$(basename "$p")
  case "$n" in lo|veth*|docker*|cni*|cali*) continue;; esac
  [ -e "$p/device" ] || continue
  [ -e "$p/device/infiniband" ] && continue
  sp=$(cat "$p/speed" 2>/dev/null)
  printf '@@NET@@\t%s\t%s\n' "$n" "$sp"
done
'''


def _parse_k8s_collector(text: str) -> tuple[str, list, list]:
    """Parse K8S_COLLECTOR_SH output into (topo_text, hcas, netdevs)."""
    topo_lines: list[str] = []
    in_topo = False
    hcas: list = []
    netdevs: list = []
    for line in text.splitlines():
        if line == "@@TOPO_BEGIN@@":
            in_topo = True
            continue
        if line == "@@TOPO_END@@":
            in_topo = False
            continue
        if in_topo:
            topo_lines.append(line)
            continue
        if line.startswith("@@HCA@@\t"):
            parts = line.split("\t")
            if len(parts) >= 5:
                name = parts[1]
                rate = parse_rate(parts[2])
                layer = parts[3].strip() or "?"
                state_raw = parts[4]
                state = state_raw.split(":")[1].split()[0] if ":" in state_raw else (state_raw.strip() or "?")
                hcas.append((name, rate, layer, state))
        elif line.startswith("@@NET@@\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                sp = parts[2].strip()
                speed = int(sp) if sp.lstrip("-").isdigit() else 0
                netdevs.append((parts[1], speed))
    return "\n".join(topo_lines), hcas, netdevs


def run_k8s_node_check(namespace: str, node: str, *, runner: Runner) -> tuple[dict[str, Any] | None, str | None]:
    access = k8s_driver_pod(namespace, node, runner=runner)
    if not access:
        return None, f"{node}: no running nvidia-smi-capable GPU Operator pod for NIC classification"
    exec_args = ["exec", "-i", "-n", namespace, access["name"]]
    if access["container"]:
        exec_args.extend(["-c", access["container"]])
    exec_args.extend(["--", "sh", "-c", K8S_COLLECTOR_SH])
    if access["hostRoot"]:
        exec_args[-4:] = ["--", "chroot", "/host", "sh", "-c", K8S_COLLECTOR_SH]
    try:
        proc = kubectl(
            exec_args,
            runner=runner,
            timeout=KUBECTL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{node}: NIC check exec failed: {exc}"
    if proc.returncode != 0:
        return None, f"{node}: NIC check exec failed: {proc.stderr.strip()}"
    topo, hcas, netdevs = _parse_k8s_collector(proc.stdout)
    if not hcas and not netdevs:
        return None, f"{node}: NIC check returned no devices"
    record: dict[str, Any] = {
        "host": node,
        "nics": classify_nics(topo, hcas, netdevs),
        "topo_collected": bool(topo.strip()),
    }
    if not topo.strip():
        record["topo_error"] = "no output"
    return record, None


def _nic_per_node(namespace: str, *, runner: Runner):
    """Per-node strategy: exec the worker inside the node's nvidia-driver pod."""
    return lambda node: run_k8s_node_check(namespace, node["name"], runner=runner)


def k8s_records(
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

    nodes = load_fanout().k8s_gpu_nodes(nodes_json)
    if not nodes:
        return [], ["no Kubernetes nodes advertise nvidia.com/gpu capacity"]

    namespace = k8s_gpu_namespace(env=env, runner=runner)
    if not namespace:
        return [], ["no NVIDIA GPU Operator namespace found; cannot reach a driver pod for NIC classification"]

    try:
        max_nodes = int(str(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS")))
    except (TypeError, ValueError):
        max_nodes = len(nodes)

    return load_fanout().fan_out_k8s(_nic_per_node(namespace, runner=runner), nodes=nodes, max_nodes=max_nodes)


def build_check_payload(
    *,
    harness: str,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    if harness == "slurm":
        records, errors = slurm_records(env=env, runner=runner)
    elif harness == "k8s":
        records, errors = k8s_records(env=env, runner=runner)
    else:
        records, errors = [gather()], []

    status = topo_status(records)
    if status:
        detail = ", ".join(
            f"{host} ({status[host].get('topo_error', 'unknown')})" for host in sorted(status)
        )
        errors.append(
            f"nvidia-smi topo -m failed on {len(status)} host(s); "
            f"their RDMA NICs were classified without GPU affinity: {detail}"
        )
    for error in errors:
        print(f"  WARNING: nic_topology: {error}", file=sys.stderr)
    payload: dict[str, Any] = {"nic_topology": aggregate(records)}
    if status:
        payload["nic_topology_status"] = status
    return payload


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="NIC topology check")
    parser.add_argument("--collect-host", action="store_true", help="emit one host record instead of the aggregate check object")
    parser.add_argument("--harness", default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS") or os.environ.get("CLUSTERMAX_HARNESS") or "")
    args = parser.parse_args(argv)

    if args.collect_host:
        print(json.dumps(gather(), sort_keys=True))
        return 0

    print(json.dumps(build_check_payload(harness=args.harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
