#!/usr/bin/env python3
"""Run ``df -hT`` on every Slurm worker node and compare the results.

The host check reads the storage of one representative worker. This check
fans out over the whole allocation, so a shared mount that is missing on one
node, or a node with a full disk, is reported with its hostname.

Worker arm (``--worker``): prints one JSON line with the ``df -hT`` rows of
this host. Controller arm: on Slurm, runs the worker on every node with
``srun``; on Kubernetes, runs ``df -hT`` in the host mount namespace of every
GPU node through a short-lived privileged pod (``nsenter -t 1 -m``). It then
compares mount target and filesystem type across nodes and emits the
``storage_config`` payload.

Kubernetes environment: ``CLUSTERMAX_AUDIT_K8S_NAMESPACE`` (default
``default``), ``CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE`` (default: digest-pinned
``python:3.12-alpine``; use a digest-pinned mirror for air-gapped clusters),
``CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS`` (default all GPU nodes).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

# Pin the multi-architecture index so both x86 and Arm hosts use fixed images.
DEFAULT_K8S_HOST_CHECK_IMAGE = (
    "python:3.12-alpine@"
    "sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b"
)

PSEUDO_FSTYPES = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "pstore",
    "efivarfs", "bpf", "securityfs", "debugfs", "tracefs", "configfs", "fusectl",
    "hugetlbfs", "mqueue", "autofs", "overlay", "squashfs", "binfmt_misc", "nsfs",
    "ramfs", "rpc_pipefs", "fuse.lxcfs", "fuse.gvfsd-fuse", "fuse.portal",
}
# Per-pod and per-container mounts differ on every node by design.
NODE_LOCAL_PREFIXES = (
    "/var/lib/kubelet/", "/var/lib/containerd/", "/run/containerd/", "/var/lib/docker/",
    "/var/lib/rancher/", "/run/k3s/", "/var/lib/containers/", "/snap/", "/run/netns/",
)
USAGE_WARN_PCT = int(os.environ.get("CLUSTERMAX_AUDIT_STORAGE_USAGE_WARN_PCT", "90") or 90)
SLURM_TIMEOUT_S = 180
K8S_POD_READY_TIMEOUT = "90s"


def parse_df(text: str) -> list[dict[str, str]]:
    """Parse ``df -hT`` output into rows keyed by column name."""
    rows: list[dict[str, str]] = []
    wrapped_source: str | None = None
    for line in text.splitlines()[1:]:
        if wrapped_source:
            line = wrapped_source + " " + line.lstrip()
            wrapped_source = None
        parts = line.split(None, 6)
        if len(parts) == 1:
            wrapped_source = parts[0]
            continue
        if len(parts) < 7 or parts[1] in PSEUDO_FSTYPES:
            continue
        if parts[6].strip().startswith(NODE_LOCAL_PREFIXES):
            continue
        rows.append(
            {"source": parts[0], "fstype": parts[1], "size": parts[2], "used": parts[3],
             "avail": parts[4], "use_pct": parts[5].rstrip("%"), "target": parts[6].strip()}
        )
    return rows


def worker_report() -> dict[str, Any]:
    host = os.environ.get("SLURMD_NODENAME") or socket.gethostname()
    try:
        proc = subprocess.run(["df", "-hTP"], capture_output=True, text=True, timeout=60)
        rows = parse_df(proc.stdout)
        error = proc.stderr.strip() or None
        if proc.returncode != 0 and not error:
            error = f"df -hT exited {proc.returncode}"
        if not rows and not error:
            error = "df -hT returned no rows"
        return {"host": host, "df": rows, "error": error}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"host": host, "df": [], "error": f"df -hT failed: {exc}"}


def aggregate(reports: list[dict[str, Any]], *, nodes_expected: int, mode: str) -> dict[str, Any]:
    if not reports:
        return {"status": "unknown", "message": "no worker node reported df -hT", "mode": mode,
                "nodes_expected": nodes_expected, "nodes_checked": 0, "hosts": []}
    hosts = sorted(r["host"] for r in reports)
    # A host whose df failed or returned nothing has no mount table to
    # compare. It is reported as a warning below, not as a host missing
    # every mount.
    by_host = {
        r["host"]: {row["target"]: row for row in r["df"]}
        for r in reports if r["df"] and not r.get("error")
    }
    all_targets = sorted({t for rows in by_host.values() for t in rows})
    failures: list[str] = []
    warnings: list[str] = []
    for target in all_targets:
        present = {h for h, rows in by_host.items() if target in rows}
        missing = sorted(set(by_host) - present)
        # A mount on a single node of many is a local disk layout, so only a
        # mount that at least half of the nodes share is required everywhere.
        # The documented audit allocation is two nodes, so one of two counts.
        if missing and len(present) * 2 >= len(by_host):
            failures.append(f"{target} is missing on {', '.join(missing)}")
        fstypes = sorted({by_host[h][target]["fstype"] for h in present})
        if len(fstypes) > 1:
            failures.append(f"{target} filesystem type differs across nodes: {', '.join(fstypes)}")
        for h in sorted(present):
            pct = by_host[h][target]["use_pct"]
            if pct.isdigit() and int(pct) >= USAGE_WARN_PCT:
                warnings.append(f"{target} on {h} is {pct}% used")
    for r in reports:
        if r.get("error"):
            warnings.append(f"{r['host']}: {r['error']}")
    if len(reports) < nodes_expected:
        warnings.append(f"only {len(reports)} of {nodes_expected} allocated node(s) reported")
    status = "fail" if failures else "warning" if warnings else "pass"
    message = "; ".join(failures + warnings) or f"{len(reports)} node(s) agree on {len(all_targets)} mount(s)"
    return {"status": status, "message": message, "mode": mode, "nodes_expected": nodes_expected,
            "nodes_checked": len(reports), "hosts_checked": hosts, "failures": failures,
            "warnings": warnings, "hosts": reports}


def k8s_pod_manifest(namespace: str, node: str, image: str, pod_name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace,
                     "labels": {"app.kubernetes.io/name": "clustermax-storage-audit"}},
        "spec": {
            "restartPolicy": "Never",
            "nodeName": node,
            "hostPID": True,
            "tolerations": [{"operator": "Exists"}],
            "containers": [{
                "name": "check",
                "image": image,
                "imagePullPolicy": os.environ.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_PULL_POLICY", "IfNotPresent"),
                "command": ["sh", "-c", "sleep 600"],
                "securityContext": {"privileged": True, "runAsUser": 0},
            }],
        },
    }


def k8s_node_report(namespace: str, node: str, image: str, *, runner: Callable[..., Any]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Run ``df -hT`` in the host mount namespace of one node."""
    pod_name = f"clustermax-storage-{uuid.uuid4().hex[:8]}"
    kubectl = lambda args, **kw: runner(["kubectl", *args], capture_output=True, text=True, **kw)  # noqa: E731
    try:
        apply = kubectl(["apply", "-f", "-"], input=json.dumps(k8s_pod_manifest(namespace, node, image, pod_name)), timeout=45)
        if apply.returncode != 0:
            return None, f"{node}: failed to create host check pod: {apply.stderr.strip()}"
        wait = kubectl(["wait", f"pod/{pod_name}", "-n", namespace, "--for=condition=Ready", f"--timeout={K8S_POD_READY_TIMEOUT}"], timeout=100)
        if wait.returncode != 0:
            return None, f"{node}: host check pod did not become Ready: {wait.stderr.strip()}"
        # PID 1 in the host PID namespace is the host init, so its mount
        # namespace is the host mount table, not the container's.
        proc = kubectl(["exec", "-n", namespace, pod_name, "--", "nsenter", "-t", "1", "-m", "--", "df", "-hT"], timeout=60)
        rows = parse_df(proc.stdout)
        error = None
        if proc.returncode != 0:
            error = f"df -hT exited {proc.returncode}: {proc.stderr.strip()[-200:]}"
        elif not rows:
            error = "df -hT returned no rows"
        return {"host": node, "df": rows, "error": error}, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{node}: host check failed: {exc}"
    finally:
        try:
            kubectl(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=false"], timeout=20)
        except Exception:  # noqa: BLE001
            pass


def k8s_reports(env: dict[str, str], runner: Callable[..., Any], fanout: Any) -> tuple[list[dict[str, Any]], list[str], int]:
    try:
        nodes_proc = runner(["kubectl", "get", "nodes", "-o", "json"], capture_output=True, text=True, timeout=45)
        if nodes_proc.returncode != 0:
            return [], [f"kubectl get nodes failed: {nodes_proc.stderr.strip()}"], 0
        nodes = [n["name"] for n in fanout.k8s_gpu_nodes(json.loads(nodes_proc.stdout))]
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [], [f"kubectl get nodes failed: {exc}"], 0
    if not nodes:
        return [], ["no Kubernetes GPU node was found"], 0
    namespace = env.get("CLUSTERMAX_AUDIT_K8S_NAMESPACE", "default")
    image = env.get("CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE", DEFAULT_K8S_HOST_CHECK_IMAGE)
    max_nodes = fanout._as_int(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS"), default=len(nodes)) or len(nodes)
    reports, errors = fanout.fan_out_k8s(
        lambda node: k8s_node_report(namespace, node, image, runner=runner), nodes=nodes, max_nodes=max_nodes
    )
    return reports, errors, min(max_nodes, len(nodes))


def build_check_payload(
    *,
    harness: str,
    env: Optional[dict[str, str]] = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    harness = harness.lower()
    if harness not in {"slurm", "k8s", "kubernetes"}:
        return {"storage_config": aggregate([worker_report()], nodes_expected=1, mode="local")}
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import _fanout  # noqa: E402

    if harness != "slurm":
        reports, errors, expected = k8s_reports(dict(env), runner, _fanout)
        payload = aggregate(reports, nodes_expected=expected, mode="k8s")
        if errors:
            payload["errors"] = errors
        return {"storage_config": payload}
    if not env.get("SLURM_JOB_ID"):
        payload = aggregate([], nodes_expected=0, mode="slurm")
        payload["errors"] = ["SLURM_JOB_ID is not set; no compute node was checked"]
        return {"storage_config": payload}

    node_count = env.get("SLURM_NNODES", "1")
    command = _fanout.slurm_python_command(node_count=node_count, worker_args=["--worker"])
    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        proc = runner(command, input=Path(__file__).read_text(), capture_output=True, text=True,
                      timeout=SLURM_TIMEOUT_S, env=dict(env))
        reports = _fanout.parse_json_lines(proc.stdout, require_host=True)
        if proc.returncode != 0:
            errors.append(f"srun exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"srun failed: {exc}")
    payload = aggregate(reports, nodes_expected=int(node_count or 1), mode="slurm")
    if errors:
        payload["errors"] = errors
    return {"storage_config": payload}


def main(argv: list[str]) -> int:
    if "--worker" in argv:
        print(json.dumps(worker_report(), sort_keys=True), flush=True)
        return 0
    harness = os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone")
    print(json.dumps(build_check_payload(harness=harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
