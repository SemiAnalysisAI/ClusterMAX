#!/usr/bin/env python3
"""NIC topology check + classifier.

Emits one check object to stdout:

    {"nic_topology": {"worker-0": [{"name": "mlx5_0", "role": "fabric", ...}], ...},
     "nic_plane_evidence": {"worker-0": [{"ibdev": "mlx5_0", ...}], ...}}

``nic_plane_evidence`` (present when the host has fabric-role HCAs) carries
read-only plane evidence:
per fabric HCA, best-effort mlxconfig / mlxlink / ibnetdiscover / lldptool
attempts plus the port's width+speed attrs, every derived value tri-state
(ok / not determined + the exact denial reason). See the "Plane evidence"
section below.

Self-dispatches by harness (``CLUSTERMAX_AUDIT_HARNESS`` / ``CLUSTERMAX_HARNESS``):

* ``slurm``      - srun one ``--collect-host`` worker per node, aggregate the
  per-node JSON lines.
* ``k8s``        - for each GPU node, exec a POSIX-sh collector inside a
  privileged NVIDIA or AMD GPU Operator system pod. The pod exposes host RDMA
  sysfs and can omit python3. Parse and classify its raw output on the operator.
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
import time
from pathlib import Path
from typing import Any, Callable

Runner = Callable[..., subprocess.CompletedProcess]

# Namespaces the NVIDIA and AMD GPU Operators install into, in check order.
GPU_OPERATOR_NAMESPACES = (
    "gpu-operator",
    "gpu-operator-resources",
    "nvidia-gpu-operator",
    "nvidia",
    "amd-gpu-operator",
    "kube-amd-gpu",
    "gpu",
)
SLURM_TIMEOUT_S = 120
KUBECTL_TIMEOUT_S = 60

_FANOUT = None


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily.

    The worker reads this file through ``python3 -`` and does not call this
    function. The controller imports the helper before it starts the worker.
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
      scale-out candidates. DOWN rail PFs behind active VFs stay unpromoted.
    * planarized IB: else the >= 2 ACTIVE InfiniBand HCAs tied at the top IB
      rate >= 200 Gb/s. A single
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


# ---------------------------------------------------------------------------
# Read-only fabric plane evidence.
#
# An 800G XDR port reports 4 lanes x 200G in ibv-level attrs whether the cage
# is cabled 2x400G (dual-plane) or 4x200G (quad-plane), so the plane split is
# invisible to the classification above. The tools that CAN pin it --
# mlxconfig (port split / planarized mode), mlxlink (per-lane state, module
# identity), ibnetdiscover / lldptool (the neighbor on the other end of each
# lane) -- usually need privileges a tenancy withholds. Per the methodology,
# every derived value here is tri-state: ok / not determined (with the exact
# denial reason). "Not determined" is not a failure; the tenant-vs-privileged
# visibility delta is itself a recorded finding.
# ---------------------------------------------------------------------------

PLANE_TOOL_TIMEOUT_S = 10
PLANE_BUDGET_S = 45.0
PLANE_MATCH_CAP = 8
K8S_PLANE_EXEC_TIMEOUT_S = 180

# mlxconfig fields worth keeping: link type, port split / planarized mode,
# SR-IOV layout. Everything else in the ~200-key dump is noise here.
_MLXCONFIG_KEEP = re.compile(r"LINK_TYPE|SPLIT|PLANE|SRIOV_EN|NUM_OF_VFS|NUM_OF_PF", re.I)
# The subset that actually answers the plane question.
_PLANE_FIELD = re.compile(r"SPLIT|PLANE", re.I)
_MLXLINK_KEEP = (
    "Speed",
    "Width",
    "State",
    "Vendor Name",
    "Vendor Part Number",
    "Vendor Serial Number",
    "Identifier",
)
_LLDP_KEEP = ("System Name TLV", "Port Description TLV", "Port ID TLV")


def run_evidence_tool(
    command: list[str],
    *,
    runner: Runner = subprocess.run,
    timeout: float = PLANE_TOOL_TIMEOUT_S,
) -> tuple[str, str | None]:
    """Best-effort evidence command: (stdout, None) or ("", short reason).

    Never raises. Reasons are stable strings the report can group on:
    "tool not installed", "timeout", "insufficient privilege (...)",
    "exit N: first stderr line".
    """
    try:
        proc = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return "", "tool not installed"
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except Exception as exc:  # noqa: BLE001 - check must not crash the audit
        return "", type(exc).__name__
    if proc.returncode != 0:
        first = ""
        for stream in (proc.stderr, proc.stdout):
            lines = (stream or "").strip().splitlines()
            if lines:
                first = lines[0].strip()[:120]
                break
        return "", _failure_reason(proc.returncode, first)
    if not proc.stdout.strip():
        return "", f"no output (exit {proc.returncode})"
    return proc.stdout, None


def _failure_reason(returncode: int, first_line: str) -> str:
    """Stable failure-reason string for a nonzero evidence-tool exit.

    Shared by the local runner path and the k8s block parser so both record
    identical reasons. Exit 124 is `timeout(1)`'s kill status in the k8s
    shell collector.
    """
    if returncode == 124:
        return "timeout"
    low = first_line.lower()
    if (
        "permission" in low
        or "operation not permitted" in low
        or "/dev/mst" in low
        or "failed to open" in low
        or "umad" in low
    ):
        return f"insufficient privilege ({first_line})" if first_line else "insufficient privilege"
    return f"exit {returncode}: {first_line}" if first_line else f"exit {returncode}"


def parse_port_attrs(rate_raw: str) -> dict:
    """sysfs ports/1/rate ('800 Gb/sec (4X XDR)') -> rate/width/speed attrs."""
    m = re.match(r"\s*(\d+(?:\.\d+)?)\s*Gb/sec(?:\s*\((\d+X)\s+([A-Z0-9]+)\))?", rate_raw or "")
    if not m:
        return {"raw": (rate_raw or "").strip()}
    attrs: dict[str, Any] = {"rate_gbps": int(float(m.group(1)))}
    if m.group(2):
        attrs["width"] = m.group(2)
    if m.group(3):
        attrs["speed"] = m.group(3)
    return attrs


def parse_mlxconfig(text: str) -> dict:
    """Keep LINK_TYPE / split / plane / SR-IOV keys from `mlxconfig -d X query`."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Z][A-Z0-9_]+)\s+(\S.*?)\s*$", line)
        if m and _MLXCONFIG_KEEP.search(m.group(1)):
            fields[m.group(1)] = m.group(2)
    return fields


def parse_mlxlink(text: str) -> dict:
    """Keep port + module identity keys from `mlxlink -d X -m` (colon pairs)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key in _MLXLINK_KEEP and value and key not in fields:
            fields[key] = value[:120]
    return fields


def parse_lldp(text: str) -> dict:
    """Neighbor identity TLVs from `lldptool get-tlv -n -i <netdev>`."""
    fields: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        name = line.strip()
        if name in _LLDP_KEEP and i + 1 < len(lines):
            value = lines[i + 1].strip()
            if value and name not in fields:
                fields[name] = value[:120]
    return fields


def parse_ibnetdiscover(text: str, node_guid: str, host: str) -> dict:
    """Per-plane neighbor summary from `ibnetdiscover -C <dev> -p`.

    Matches lines carrying our node GUID (sysfs '0011:2233:...' form,
    colons stripped) or, failing that, our hostname in the node description.
    Also counts distinct `SW`-typed lines as the plane's visible switch count.
    """
    guid_hex = (node_guid or "").replace(":", "").lower().lstrip("0")
    guid_matches: list[str] = []
    host_matches: list[str] = []
    host_pattern = re.compile(r"(?<![a-z0-9_.-])" + re.escape(host.lower()) + r"(?![a-z0-9_.-])") if host else None
    switches = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("SW"):
            switches += 1
        low = stripped.lower()
        guids = {value.lstrip("0") for value in re.findall(r"\b0x([0-9a-f]+)\b", low)}
        if guid_hex and guid_hex in guids and len(guid_matches) < PLANE_MATCH_CAP:
            guid_matches.append(stripped[:200])
        if host_pattern and host_pattern.search(low) and len(host_matches) < PLANE_MATCH_CAP:
            host_matches.append(stripped[:200])
    matched = guid_matches or host_matches
    return {"switch_count": switches, "matched": matched}


def _tri(raw: str, reason: str | None, parse: Callable[[str], dict], key: str = "fields") -> dict:
    if reason is not None:
        return {"status": "not determined", "reason": reason}
    return {"status": "ok", key: parse(raw)}


def evidence_from_raw(
    dev: str,
    layer: str,
    rate_raw: str,
    raws: dict[str, tuple[str, str | None]],
    *,
    node_guid: str = "",
    host: str = "",
) -> dict:
    """Assemble one HCA's tri-state evidence record from raw tool outputs.

    ``raws`` maps tool name (mlxconfig / mlxlink / ibnetdiscover / lldp) to
    (stdout, failure-reason). Shared by the local collector and the k8s
    orchestrator so both paths emit identical shapes.
    """
    record: dict[str, Any] = {"ibdev": dev, "port": parse_port_attrs(rate_raw)}
    record["mlxconfig"] = _tri(*raws.get("mlxconfig", ("", "not attempted")), parse_mlxconfig)
    record["mlxlink"] = _tri(*raws.get("mlxlink", ("", "not attempted")), parse_mlxlink)

    if layer == "InfiniBand":
        raw, reason = raws.get("ibnetdiscover", ("", "not attempted"))
        if reason is None:
            neighbor: dict[str, Any] = {"status": "ok", "method": "ibnetdiscover"}
            neighbor.update(parse_ibnetdiscover(raw, node_guid, host))
        else:
            neighbor = {"status": "not determined", "method": "ibnetdiscover", "reason": reason}
    else:
        raw, reason = raws.get("lldp", ("", "not attempted"))
        if reason is None:
            neighbor = {"status": "ok", "method": "lldp", "fields": parse_lldp(raw)}
        else:
            neighbor = {"status": "not determined", "method": "lldp", "reason": reason}
    record["neighbor"] = neighbor

    # Derived plane presentation: only mlxconfig split/plane keys answer it
    # from the node alone. Anything else stays honestly not-determined.
    mlxc = record["mlxconfig"]
    plane_fields = (
        {k: v for k, v in mlxc.get("fields", {}).items() if _PLANE_FIELD.search(k)}
        if mlxc["status"] == "ok"
        else {}
    )
    if plane_fields:
        record["presentation"] = {"status": "ok", "fields": plane_fields}
    else:
        why = (
            "mlxconfig visible but exposes no split/plane key"
            if mlxc["status"] == "ok"
            else f"mlxconfig {mlxc.get('reason', 'unavailable')}"
        )
        record["presentation"] = {
            "status": "not determined",
            "reason": f"{why}; needs Tier A (mlxconfig/mlxlink) or Tier B (SM view) access",
        }
    return record


def _read_sysfs(path: str) -> str:
    try:
        return open(path).read().strip()
    except OSError:
        return ""


def plane_candidate(nic: dict[str, Any]) -> bool:
    """Include down IB ports whose fabric role can be recovered from peers."""
    return nic.get("role") == "fabric" or (
        nic.get("layer") == "InfiniBand"
        and isinstance(nic.get("state"), str)
        and nic["state"] != "ACTIVE"
    )


def collect_plane_evidence(
    nics: list,
    *,
    runner: Runner = subprocess.run,
    sysfs_root: str = "/sys/class/infiniband",
    budget_s: float = PLANE_BUDGET_S,
    time_fn: Callable[[], float] = time.monotonic,
) -> list:
    """Tier A/B evidence for fabric HCAs and down-IB reconciliation candidates.

    Bounded: per-tool timeout plus an overall budget so a hung /dev/mst can
    never starve the srun window that also carries the role classification.
    HCAs skipped by the budget are recorded as not-determined, not dropped.
    """
    started = time_fn()
    out: list[dict[str, Any]] = []
    host = os.environ.get("NODE_NAME") or socket.gethostname()
    for nic in sorted(nics, key=lambda item: item.get("role") != "fabric"):
        if not plane_candidate(nic):
            continue
        dev = nic["name"]
        rate_raw = _read_sysfs(f"{sysfs_root}/{dev}/ports/1/rate")
        if time_fn() - started > budget_s:
            record = evidence_from_raw(
                dev,
                nic.get("layer", "?"),
                rate_raw,
                {tool: ("", "budget exhausted") for tool in ("mlxconfig", "mlxlink", "ibnetdiscover", "lldp")},
            )
            out.append(record)
            continue
        node_guid = _read_sysfs(f"{sysfs_root}/{dev}/node_guid")
        netdevs = sorted(glob.glob(f"{sysfs_root}/{dev}/device/net/*"))
        netdev = os.path.basename(netdevs[0]) if netdevs else ""
        raws: dict[str, tuple[str, str | None]] = {
            "mlxconfig": run_evidence_tool(["mlxconfig", "-d", dev, "query"], runner=runner),
            "mlxlink": run_evidence_tool(["mlxlink", "-d", dev, "-m"], runner=runner),
        }
        if nic.get("layer") == "InfiniBand":
            raws["ibnetdiscover"] = run_evidence_tool(
                ["ibnetdiscover", "-C", dev, "-p"], runner=runner
            )
        elif netdev:
            raws["lldp"] = run_evidence_tool(
                ["lldptool", "get-tlv", "-n", "-i", netdev], runner=runner
            )
        else:
            raws["lldp"] = ("", "no netdev exposed for this HCA")
        out.append(
            evidence_from_raw(
                dev, nic.get("layer", "?"), rate_raw, raws, node_guid=node_guid, host=host
            )
        )
    return out


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
    record["nvlinkExposed"] = bool(re.search(r"\bNV[0-9]+\b", topo)) if topo_error is None else None
    if topo_error is not None:
        record["topo_error"] = topo_error
    evidence = collect_plane_evidence(nics, runner=runner)
    if evidence:
        record["plane_evidence"] = evidence
    return record


# ---------------------------------------------------------------------------
# Fan-out orchestration (slurm / k8s / local), aggregated into nic_topology.
# ---------------------------------------------------------------------------


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    # A down InfiniBand port reports a fallback rate, and a pod may not see
    # that HCA in nvidia-smi topology. Preserve its fabric purpose when two
    # healthy GPU workers classify the same named port as active fabric.
    active_fabric_peers: dict[str, set[str]] = {}
    for record in records:
        host = str(record.get("host") or "")
        if not host:
            continue
        for nic in record.get("nics", []):
            if (nic.get("layer") == "InfiniBand" and nic.get("state") == "ACTIVE"
                    and nic.get("role") == "fabric"):
                active_fabric_peers.setdefault(nic["name"], set()).add(host)

    nic_topology: dict[str, Any] = {}
    for record in records:
        host = str(record.get("host") or "")
        if not host:
            continue
        nics = []
        for nic in record.get("nics", []):
            corrected = dict(nic)
            peers = active_fabric_peers.get(nic.get("name", ""), set()) - {host}
            if (nic.get("layer") == "InfiniBand" and nic.get("state") != "ACTIVE"
                    and nic.get("role") != "fabric" and len(peers) >= 2):
                corrected["role"] = "fabric"
                corrected["reason"] = (
                    f"down InfiniBand port; same HCA is active fabric on "
                    f"{len(peers)} peer GPU workers"
                )
            nics.append(corrected)
        nic_topology[host] = nics
    return nic_topology


def plane_evidence_by_host(
    records: list[dict[str, Any]], topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sibling ``nic_plane_evidence`` payload: host -> per-fabric-HCA evidence.

    Kept out of ``nic_topology`` so that mapping's host -> NIC-list shape
    stays exactly what merge_audit.py and the dashboard already consume.
    """
    topology = aggregate(records) if topology is None else topology
    out: dict[str, Any] = {}
    for record in records:
        host = str(record.get("host") or "")
        if not host:
            continue
        collected = {
            entry["ibdev"]: entry for entry in record.get("plane_evidence", [])
            if isinstance(entry, dict) and entry.get("ibdev")
        }
        evidence = []
        for nic in topology.get(host, []):
            if nic.get("role") != "fabric":
                continue
            dev = nic["name"]
            if dev in collected:
                evidence.append(collected[dev])
            else:
                # Older workers may not have probed a port before peer-based
                # role recovery. Keep that missing evidence explicit.
                reason = "not collected before fabric role aggregation"
                evidence.append(evidence_from_raw(
                    dev, nic.get("layer", "?"), "",
                    {tool: ("", reason) for tool in ("mlxconfig", "mlxlink", "ibnetdiscover", "lldp")},
                    host=host,
                ))
        if evidence:
            out[host] = evidence
    return out


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
        if (not host or record.get("topo_collected") is not False
                or record.get("topo_applicable") is False):
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
        return [], ["SLURM_JOB_ID is not set; no compute node was checked for NIC topology"]

    node_count = env.get("SLURM_NNODES") or "1"
    command = load_fanout().slurm_python_command(
        node_count=node_count, worker_args=["--collect-host"]
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"srun NIC check failed; no compute node was checked: {exc}"]

    records = load_fanout().parse_json_lines(proc.stdout, require_host=True)
    errors: list[str] = []
    if proc.returncode != 0 and not records:
        errors.append(f"srun NIC check exited {proc.returncode}: {proc.stderr.strip()}")
        return [], errors
    if not records:
        return [], ["srun NIC check returned no host JSON; no compute node was checked"]
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


def k8s_gpu_namespaces(*, env: dict[str, str], runner: Runner) -> list[str]:
    override = env.get("CLUSTERMAX_GPU_OPERATOR_NAMESPACE")
    if override:
        return [override]
    try:
        proc = kubectl(["get", "namespaces", "-o", "json"], runner=runner, timeout=20)
        data = json.loads(proc.stdout) if proc.returncode == 0 else None
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ValueError("namespace inventory unavailable")
        names = {
            name
            for item in items
            if isinstance(item, dict) and isinstance(item.get("metadata"), dict)
            and isinstance(name := item["metadata"].get("name"), str)
            and (name in GPU_OPERATOR_NAMESPACES
                 or re.search(r"gpu-operator|nvidia-gpu", name, re.IGNORECASE))
        }
        priority = {name: index for index, name in enumerate(GPU_OPERATOR_NAMESPACES[:-1])}
        if names:
            return sorted(names, key=lambda name: (
                priority.get(name, len(priority) + (name == "gpu")), name
            ))
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        pass
    # Some tenants can read specific namespaces but cannot list all of them.
    names = []
    for ns in GPU_OPERATOR_NAMESPACES:
        try:
            if kubectl(["get", "namespace", ns], runner=runner, timeout=20).returncode == 0:
                names.append(ns)
        except (OSError, subprocess.TimeoutExpired):
            continue
    return names


def k8s_gpu_namespace(*, env: dict[str, str], runner: Runner) -> str | None:
    """Compatibility helper for callers that need the first namespace."""
    return next(iter(k8s_gpu_namespaces(env=env, runner=runner)), None)


def k8s_driver_pod(
    namespace: str, node: str, *, runner: Runner, gpu_vendor: str | None = None,
) -> dict[str, Any] | None:
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
        if gpu_vendor == "amd" and (
            re.search(r"(?:^|[-_])nvidia(?:[-_]|$)", name) or name.startswith("gpu-feature-discovery-")
        ):
            continue
        if gpu_vendor == "nvidia" and re.search(r"(?:^|[-_])amd(?:[-_]|$)", name):
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
        elif "-device-plugin-" in name or "-metrics-exporter-" in name:
            for container in item.get("spec", {}).get("containers", []):
                if container.get("securityContext", {}).get("privileged") is True:
                    candidates.append((4, name, container.get("name"), False))
    if not candidates:
        return None
    _, name, container, host_root = min(candidates)
    return {"name": name, "container": container, "hostRoot": host_root}


# Shell collector run inside the GPU system pod. NVIDIA driver pods carry
# nvidia-smi, and both NVIDIA and AMD pods expose host IB/net sysfs. These pods
# can omit python3, so the worker cannot run there as Python. This POSIX-sh
# snippet emits the same raw inputs
# classify_nics() needs (topo text + per-HCA rate/layer/state + frontend
# netdevs), tab-delimited, and the orchestrator (which has python3) parses and
# classifies them. Mirrors the local sysfs reads in _collect_*_local().
K8S_COLLECTOR_SH = r'''
echo @@TOPO_BEGIN@@
if [ "${CLUSTERMAX_GPU_VENDOR:-nvidia}" = nvidia ]; then
  nvidia-smi topo -m 2>/dev/null
fi
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
# Plane evidence (Tier A/B): high-rate HCAs first, then failed IB candidates.
# Tools are usually
# absent or unprivileged in system pods; the orchestrator records the exact
# reason as tri-state instead of failing. Bounded so a hung tool can never
# kill the exec and lose the classification above: `timeout 8` per command,
# at most 6 HCAs, and tools are SKIPPED outright when the pod image
# has no timeout(1) to enforce the bound (worst case 6 x 3 x 8s = 144s,
# inside this check's 180s exec window).
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 8"
plane_run() {
  pr_n="$1"; pr_t="$2"; shift 2
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "@@PLANE@@ $pr_n $pr_t MISSING"; return
  fi
  if [ -z "$TO" ]; then
    echo "@@PLANE@@ $pr_n $pr_t SKIPPED"; return
  fi
  echo "@@PLANE@@ $pr_n $pr_t BEGIN"
  $TO "$@" 2>&1
  echo "@@PLANE@@ $pr_n $pr_t END $?"
}
checked=0
for plane_pass in active failed; do
for d in /sys/class/infiniband/*; do
  [ -e "$d" ] || continue
  n=$(basename "$d"); case "$n" in bond*) continue;; esac
  r=$(cat "$d/ports/1/rate" 2>/dev/null)
  l=$(cat "$d/ports/1/link_layer" 2>/dev/null)
  s=$(cat "$d/ports/1/state" 2>/dev/null)
  failed_ib=false
  if [ "$l" = InfiniBand ]; then
    case "$s" in *": ACTIVE"|ACTIVE) ;; *) failed_ib=true ;; esac
  fi
  if [ "$plane_pass" = failed ]; then
    [ "$failed_ib" = true ] || continue
  else
    [ "$failed_ib" = false ] || continue
    case "$r" in [1-9][0-9][0-9]*) ;; *) continue;; esac
  fi
  [ "$checked" -ge 6 ] && continue
  checked=$((checked+1))
  g=$(cat "$d/node_guid" 2>/dev/null)
  printf '@@PLANEGUID@@\t%s\t%s\n' "$n" "$g"
  l=$(cat "$d/ports/1/link_layer" 2>/dev/null)
  plane_run "$n" mlxconfig mlxconfig -d "$n" query
  plane_run "$n" mlxlink mlxlink -d "$n" -m
  case "$l" in
    InfiniBand*)
      plane_run "$n" ibnetdiscover ibnetdiscover -C "$n" -p
      ;;
    *)
      nd=$(ls "$d/device/net" 2>/dev/null | head -1)
      if [ -n "$nd" ]; then
        plane_run "$n" lldp lldptool get-tlv -n -i "$nd"
      else
        echo "@@PLANE@@ $n lldp NONETDEV"
      fi
      ;;
  esac
done
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


def _k8s_rate_raws(text: str) -> dict[str, str]:
    """Raw sysfs rate strings per HCA from the @@HCA@@ lines (width/speed attrs)."""
    raws: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("@@HCA@@\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                raws[parts[1]] = parts[2].strip()
    return raws


def _parse_k8s_plane(text: str) -> tuple[dict[str, dict[str, tuple[str, str | None]]], dict[str, str]]:
    """Parse @@PLANE@@ / @@PLANEGUID@@ blocks from K8S_COLLECTOR_SH output.

    Returns (raws, guids): ``raws[dev][tool] = (stdout, failure_reason)`` in
    exactly the shape ``evidence_from_raw`` consumes, and ``guids[dev]`` the
    sysfs node_guid. MISSING marks a tool absent from the pod image; a
    nonzero END status is mapped through ``_failure_reason`` so the k8s and
    local paths record identical reasons.
    """
    raws: dict[str, dict[str, tuple[str, str | None]]] = {}
    guids: dict[str, str] = {}
    block: list[str] = []
    current: tuple[str, str] | None = None
    for line in text.splitlines():
        if line.startswith("@@PLANEGUID@@\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                guids[parts[1]] = parts[2].strip()
            continue
        if line.startswith("@@PLANE@@ "):
            parts = line.split()
            if len(parts) < 4:
                continue
            dev, tool, marker = parts[1], parts[2], parts[3]
            if marker == "BEGIN":
                current = (dev, tool)
                block = []
            elif marker == "MISSING":
                raws.setdefault(dev, {})[tool] = ("", "tool not installed")
                current = None
            elif marker == "SKIPPED":
                raws.setdefault(dev, {})[tool] = ("", "skipped (no timeout binary in pod)")
                current = None
            elif marker == "NONETDEV":
                raws.setdefault(dev, {})[tool] = ("", "no netdev exposed for this HCA")
                current = None
            elif marker == "END" and current == (dev, tool):
                status = int(parts[4]) if len(parts) > 4 and parts[4].lstrip("-").isdigit() else 0
                raw = "\n".join(block)
                if status != 0:
                    first = next((l.strip()[:120] for l in block if l.strip()), "")
                    raws.setdefault(dev, {})[tool] = ("", _failure_reason(status, first))
                elif not raw.strip():
                    raws.setdefault(dev, {})[tool] = ("", "no output (exit 0)")
                else:
                    raws.setdefault(dev, {})[tool] = (raw, None)
                current = None
            continue
        if current is not None:
            block.append(line)
    return raws, guids


def run_k8s_node_check(
    namespace: str, node: str, *, runner: Runner, gpu_vendor: str = "nvidia",
    pod_access: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    access = pod_access if pod_access is not None else k8s_driver_pod(
        namespace, node, runner=runner, gpu_vendor=gpu_vendor,
    )
    if not access:
        return None, f"{node}: no running GPU Operator system pod for NIC classification"
    exec_args = ["exec", "-i", "-n", namespace, access["name"]]
    if access["container"]:
        exec_args.extend(["-c", access["container"]])
    topo_applicable = gpu_vendor != "amd"
    collector = f"CLUSTERMAX_GPU_VENDOR={'nvidia' if topo_applicable else 'amd'}\n{K8S_COLLECTOR_SH}"
    exec_args.extend(["--", "sh", "-c", collector])
    if access["hostRoot"]:
        exec_args[-4:] = ["--", "chroot", "/host", "sh", "-c", collector]
    try:
        # 180s (not the default 60): the collector now also runs the bounded
        # plane-evidence tool attempts (worst case 144s when mft/ib tools are
        # actually installed in the pod; near-instant when absent).
        proc = kubectl(
            exec_args,
            runner=runner,
            timeout=K8S_PLANE_EXEC_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{node}: NIC check exec failed: {exc}"
    if proc.returncode != 0:
        return None, f"{node}: NIC check exec failed: {proc.stderr.strip()}"
    topo, hcas, netdevs = _parse_k8s_collector(proc.stdout)
    if not topo_applicable:
        topo = ""
    if not hcas and not netdevs:
        return None, f"{node}: NIC check returned no devices"
    record: dict[str, Any] = {
        "host": node,
        "gpu_vendor": gpu_vendor,
        "nics": classify_nics(topo, hcas, netdevs),
        "topo_collected": bool(topo.strip()),
        "nvlinkExposed": bool(re.search(r"\bNV[0-9]+\b", topo)) if topo.strip() else None,
    }
    if not topo_applicable:
        record["topo_applicable"] = False
    elif not topo.strip():
        record["topo_error"] = "no output"
    plane_raws, plane_guids = _parse_k8s_plane(proc.stdout)
    rate_raws = _k8s_rate_raws(proc.stdout)
    evidence = [
        evidence_from_raw(
            nic["name"],
            nic.get("layer", "?"),
            rate_raws.get(nic["name"], ""),
            plane_raws.get(nic["name"], {}),
            node_guid=plane_guids.get(nic["name"], ""),
            host=node,
        )
        for nic in record["nics"]
        if plane_candidate(nic)
    ]
    if evidence:
        record["plane_evidence"] = evidence
    return record, None


def _nic_per_node(namespaces: list[str], *, runner: Runner):
    """Per-node strategy: exec the worker inside a privileged GPU system pod."""
    def check_node(node):
        vendor = node.get("gpu_vendor", "nvidia")

        def priority(namespace):
            amd = "amd" in namespace.lower()
            nvidia = "nvidia" in namespace.lower() or namespace in {"gpu-operator", "gpu-operator-resources"}
            if (vendor == "amd" and amd) or (vendor == "nvidia" and nvidia):
                return 0
            return 2 if (amd or nvidia) else 1

        for namespace in sorted(namespaces, key=priority):
            access = k8s_driver_pod(namespace, node["name"], runner=runner, gpu_vendor=vendor)
            if access:
                return run_k8s_node_check(
                    namespace, node["name"], runner=runner, gpu_vendor=vendor, pod_access=access,
                )
        return None, f"{node['name']}: no running {vendor} GPU Operator system pod in the discovered namespaces"

    return check_node


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
        return [], ["no Kubernetes nodes advertise nvidia.com/gpu or amd.com/gpu capacity"]

    namespaces = k8s_gpu_namespaces(env=env, runner=runner)
    if not namespaces:
        return [], ["no supported GPU Operator namespace found; cannot reach a system pod for NIC classification"]

    try:
        max_nodes = int(str(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS")))
    except (TypeError, ValueError):
        max_nodes = len(nodes)

    return load_fanout().fan_out_k8s(_nic_per_node(namespaces, runner=runner), nodes=nodes, max_nodes=max_nodes)


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

    nvlink_records = [r for r in records if r.get("topo_applicable") is not False]
    nvlink_coverage_complete = bool(nvlink_records) and not errors and all(
        r.get("topo_collected") is True and isinstance(r.get("nvlinkExposed"), bool)
        for r in nvlink_records
    )
    topology = aggregate(records)
    evidence = plane_evidence_by_host(records, topology)
    undetermined = sorted(
        host
        for host, evs in evidence.items()
        if evs and all(e.get("presentation", {}).get("status") != "ok" for e in evs)
    )
    if undetermined:
        sample = evidence[undetermined[0]][0].get("presentation", {}).get("reason", "")
        errors.append(
            f"plane presentation not determined on {len(undetermined)} host(s) "
            f"(tenant privilege boundary; e.g. {sample})"
        )

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
    payload: dict[str, Any] = {"nic_topology": topology}
    payload["nvlink_topology"] = {
        "hosts": {
            str(r["host"]): {"checked": r.get("topo_collected") is True,
                             "exposed": r.get("nvlinkExposed"),
                             **({"applicable": False} if r.get("topo_applicable") is False else {})}
            for r in records if r.get("host")
        },
        "coverageComplete": nvlink_coverage_complete,
    }
    if status:
        payload["nic_topology_status"] = status
    if evidence:
        payload["nic_plane_evidence"] = evidence
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
