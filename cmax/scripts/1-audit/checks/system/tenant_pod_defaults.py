#!/usr/bin/env python3
"""Tenant pod defaults check (Kubernetes).

Multi-node GPU workloads that use RDMA transports (UCX, NCCL, NVSHMEM,
CUDA-aware MPI over InfiniBand) need pinned-memory registration, a large
/dev/shm, and the RDMA device nodes inside the pod. The stock container
runtime defaults (8 MiB RLIMIT_MEMLOCK, 64 MiB /dev/shm, no CAP_IPC_LOCK, no
/dev/infiniband) silently break all of them for an unprivileged tenant:
UCX aborts with "Please set max locked memory (ulimit -l) to unlimited",
NVSHMEM cannot initialize its IB transports, and NCCL falls back to TCP.
A privileged pod hides every one of these gaps, so this check measures what a
standard unprivileged tenant actually receives.

The check launches two pods on a GPU node through the normal scheduler:

  1. A "default" pod: an unprivileged GPU pod with no securityContext and no
     extra volumes. It reads RLIMIT_MEMLOCK, /dev/shm size, effective
     capabilities, and the /dev/infiniband and /dev/gdrdrv device nodes.
  2. A "tuned" pod: the same pod plus the documented pod-spec remedies
     (CAP_IPC_LOCK, a memory-backed emptyDir on /dev/shm, and one rdma
     extended resource when the cluster advertises one). It shows whether
     admission policy accepts the remedy and whether the remedy takes effect.

The two readings separate "the defaults are hostile and the tenant can fix
them in the pod spec" from "admission policy blocks the fix", which is the
distinction the provider conversation needs.

The check runs in CLUSTERMAX_AUDIT_TENANT_NAMESPACE (default: "default").
This is deliberately not CLUSTERMAX_AUDIT_K8S_NAMESPACE: that variable
relocates the audit-owned check namespace, which carries privileged
pod-security labels, and a measurement there would hide the admission
behavior a tenant namespace applies. As a defense in depth the check reads
the pod-security enforce label on the target namespace and grades the
admission check `unknown` when the namespace enforces the privileged
profile.

Every result grades at most `warning`. These are tenant-experience defaults
with documented remedies on both the tenant side and the provider side, so
the audit reports them for follow-up and never fails a cluster on them.

Environment overrides:

  CLUSTERMAX_AUDIT_TENANT_POD_CHECK=0     skip the check (grades unknown)
  CLUSTERMAX_AUDIT_TENANT_NAMESPACE       namespace for the tenant check pods
  CLUSTERMAX_AUDIT_K8S_GPU_IMAGE          check image (default: CUDA base)
  CLUSTERMAX_AUDIT_TENANT_POD_WAIT_S      per-pod Ready timeout (default 180)
  CLUSTERMAX_AUDIT_TENANT_MEMLOCK_MIN_MB  memlock warn minimum (default 65536)
  CLUSTERMAX_AUDIT_TENANT_SHM_MIN_MB      /dev/shm warn minimum (default 1024)
  CLUSTERMAX_AUDIT_TENANT_TUNED_SHM       tuned pod shm size (default 8Gi)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

_FANOUT = None

NO_K8S_GPU_NODES = "no Kubernetes nodes advertise nvidia.com/gpu or amd.com/gpu capacity"

DEFAULT_IMAGE = "nvcr.io/nvidia/cuda:12.6.0-base-ubuntu22.04"

# Bit positions in the CapEff mask from /proc/self/status.
CAP_IPC_LOCK = 14
CAP_SYS_ADMIN = 21
CAP_SYS_RESOURCE = 24

# Runs inside the check pod via `sh -c`. Emits one TENANT_ key per line. Uses
# only POSIX sh, awk, df, ls, grep, and id, so it works in slim images.
FACTS_SCRIPT = r"""
set -u
echo "TENANT_MEMLOCK_SOFT_KB=$(ulimit -S -l 2>/dev/null || echo unknown)"
echo "TENANT_MEMLOCK_HARD_KB=$(ulimit -H -l 2>/dev/null || echo unknown)"
shm_kb=$(df -kP /dev/shm 2>/dev/null | awk 'NR==2{print $2}')
echo "TENANT_SHM_KB=${shm_kb:-unknown}"
cap=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null)
echo "TENANT_CAP_EFF=${cap:-unknown}"
echo "TENANT_IB_UVERBS=$(ls /dev/infiniband 2>/dev/null | grep -c '^uverbs')"
if [ -e /dev/infiniband/rdma_cm ]; then echo "TENANT_RDMA_CM=true"; else echo "TENANT_RDMA_CM=false"; fi
if [ -e /dev/gdrdrv ]; then echo "TENANT_GDRDRV=true"; else echo "TENANT_GDRDRV=false"; fi
echo "TENANT_NVIDIA_DEVS=$(ls /dev/nvidia[0-9]* 2>/dev/null | wc -l | tr -d ' ')"
echo "TENANT_UID=$(id -u)"
"""


def load_fanout():
    """Import the shared checks/_fanout.py module, lazily (see hbm check)."""
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout

        _FANOUT = _fanout
    return _FANOUT


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def env_int(name: str, default: int) -> int:
    return as_int(os.environ.get(name), default=default)


def run_command(command: list[str], *, timeout: int = 30, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def kubectl(command: list[str], *, timeout: int = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return run_command(["kubectl", *command], timeout=timeout, input_text=input_text)


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in scripts/1-audit/audit/test_tenant_pod_defaults.py)
# ---------------------------------------------------------------------------


def parse_facts(stdout: str) -> dict[str, str]:
    """TENANT_KEY=value lines from the in-pod facts script."""
    facts: dict[str, str] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("TENANT_") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        facts[key] = value.strip()
    return facts


def decode_caps(mask: str) -> dict[str, bool | None]:
    """Decode the CapEff hex mask into the capabilities this check grades."""
    try:
        bits = int(str(mask).strip(), 16)
    except (TypeError, ValueError):
        return {"ipc_lock": None, "sys_admin": None, "sys_resource": None}
    return {
        "ipc_lock": bool(bits >> CAP_IPC_LOCK & 1),
        "sys_admin": bool(bits >> CAP_SYS_ADMIN & 1),
        "sys_resource": bool(bits >> CAP_SYS_RESOURCE & 1),
    }


def pod_facts(raw: dict[str, str]) -> dict[str, Any]:
    """Normalize raw TENANT_ keys into the JSON facts block for one pod."""
    caps = decode_caps(raw.get("TENANT_CAP_EFF", ""))
    hard = raw.get("TENANT_MEMLOCK_HARD_KB", "unknown")
    shm_kb = raw.get("TENANT_SHM_KB", "unknown")
    shm_mb = as_int(shm_kb, default=-1) // 1024 if as_int(shm_kb, default=-1) >= 0 else None
    return {
        "memlockSoftKb": raw.get("TENANT_MEMLOCK_SOFT_KB", "unknown"),
        "memlockHardKb": hard,
        "memlockUnlimited": hard == "unlimited",
        "shmMb": shm_mb,
        "capEffMask": raw.get("TENANT_CAP_EFF", "unknown"),
        "capIpcLock": caps["ipc_lock"],
        "capSysAdmin": caps["sys_admin"],
        "capSysResource": caps["sys_resource"],
        "ibUverbsDevices": as_int(raw.get("TENANT_IB_UVERBS")),
        "rdmaCmDevice": raw.get("TENANT_RDMA_CM") == "true",
        "gdrdrvDevice": raw.get("TENANT_GDRDRV") == "true",
        "nvidiaDevices": as_int(raw.get("TENANT_NVIDIA_DEVS")),
        "runAsUid": as_int(raw.get("TENANT_UID"), default=-1),
    }


# Public RDMA-capable extended resource keys with no "rdma" substring.
# Other keys match through the substring test. Arbitrary SR-IOV resource
# names cannot establish RDMA capability without configuration evidence.
FABRIC_RESOURCE_EXACT = (
    "vpc.amazonaws.com/efa",
    "nvidia.com/mlnxics",
    "nvidia.com/hostdev",
    "nvidia.com/switchdev",
)


def cluster_rdma_resources(nodes_json: dict[str, Any]) -> list[str]:
    """RDMA-capable extended resource names advertised by any node."""
    names: set[str] = set()
    for item in nodes_json.get("items", []):
        allocatable = item.get("status", {}).get("allocatable", {})
        if not isinstance(allocatable, dict):
            continue
        for key, quantity in allocatable.items():
            if as_int(quantity) <= 0:
                continue
            if "rdma" in key.lower() or key in FABRIC_RESOURCE_EXACT:
                names.add(key)
    return sorted(names)


def filter_dra_rdma_class_names(names: Any) -> list[str]:
    """Match RDMA-related public DeviceClass naming tokens."""
    return sorted(
        name
        for name in (str(item) for item in names)
        if any(token in name.lower() for token in ("rdma", "dranet", "dra.net"))
    )


def dra_rdma_device_classes() -> list[str]:
    """RDMA-capable DRA DeviceClass names from the live cluster. Empty when
    the resource.k8s.io API or the classes are absent, so pre-DRA clusters
    stay on the extended-resource path."""
    try:
        proc = kubectl(["get", "deviceclasses.resource.k8s.io", "-o", "json"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    names = (str(item.get("metadata", {}).get("name", "")) for item in payload.get("items", []))
    return filter_dra_rdma_class_names(names)


def namespace_enforces_privileged(namespace: str) -> bool | None:
    """Return the explicit privileged label, or None for unreadable policy.

    Admission acceptance without readable namespace policy is not a tenant signal.
    """
    try:
        proc = kubectl(["get", "namespace", namespace, "-o", "json"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("metadata"), dict):
        return None
    labels = payload["metadata"].get("labels")
    if labels is None:
        labels = {}
    if not isinstance(labels, dict):
        return None
    enforce = labels.get("pod-security.kubernetes.io/enforce", "")
    if not isinstance(enforce, str):
        return None
    return enforce.strip().lower() == "privileged"


def gpu_resource_key(nodes_json: dict[str, Any]) -> str:
    """The schedulable GPU extended resource, or '' on a DRA-only cluster."""
    for item in nodes_json.get("items", []):
        allocatable = item.get("status", {}).get("allocatable", {})
        if not isinstance(allocatable, dict):
            continue
        for key in ("nvidia.com/gpu", "amd.com/gpu"):
            if as_int(allocatable.get(key)) > 0:
                return key
    return ""


def _fmt_memlock(facts: dict[str, Any]) -> str:
    hard = facts.get("memlockHardKb")
    if hard == "unlimited":
        return "unlimited"
    kb = as_int(hard, default=-1)
    if kb < 0:
        return str(hard)
    if kb >= 1024 * 1024:
        return f"{kb // (1024 * 1024)} GiB"
    if kb >= 1024:
        return f"{kb // 1024} MiB"
    return f"{kb} KiB"


def evaluate_checks(
    default_facts: dict[str, Any] | None,
    tuned: dict[str, Any],
    *,
    gpu_requested: bool,
    rdma_resources: list[str],
    memlock_min_mb: int,
    shm_min_mb: int,
    dra_rdma_classes: list[str] | None = None,
    privileged_namespace: bool | None = False,
) -> dict[str, dict[str, str]]:
    """Per-check verdicts. The worst status any check emits is `warning`."""
    checks: dict[str, dict[str, str]] = {}

    # memlock: RDMA memory registration needs an unlimited RLIMIT_MEMLOCK or
    # CAP_IPC_LOCK. A finite limit above the minimum also passes; pinned-buffer
    # demand scales with the job, and the minimum keeps the check actionable.
    if default_facts is None:
        checks["memlock"] = {"status": "unknown", "detail": "the default pod facts were not collected"}
    elif default_facts["memlockUnlimited"] or default_facts["capIpcLock"] is True:
        checks["memlock"] = {
            "status": "pass",
            "detail": f"RLIMIT_MEMLOCK hard limit {_fmt_memlock(default_facts)}, CAP_IPC_LOCK {default_facts['capIpcLock']}",
        }
    else:
        hard_kb = as_int(default_facts["memlockHardKb"], default=-1)
        if hard_kb < 0:
            checks["memlock"] = {"status": "unknown", "detail": f"unreadable RLIMIT_MEMLOCK: {default_facts['memlockHardKb']}"}
        elif hard_kb < memlock_min_mb * 1024:
            checks["memlock"] = {
                "status": "warning",
                "detail": (
                    f"RLIMIT_MEMLOCK hard limit is {_fmt_memlock(default_facts)} and CAP_IPC_LOCK is absent; "
                    "RDMA memory registration fails for UCX, NCCL, NVSHMEM, and CUDA-aware MPI"
                ),
            }
        else:
            checks["memlock"] = {
                "status": "pass",
                "detail": f"RLIMIT_MEMLOCK hard limit {_fmt_memlock(default_facts)} meets the {memlock_min_mb} MiB minimum",
            }

    # /dev/shm: NCCL SHM transport, UCX posix/sysv, and MPI shared-memory BTLs
    # allocate per-rank segments here. The CRI sandbox default is 64 MiB.
    if default_facts is None or default_facts.get("shmMb") is None:
        checks["shm"] = {"status": "unknown", "detail": "the default pod /dev/shm size was not readable"}
    elif default_facts["shmMb"] < shm_min_mb:
        checks["shm"] = {
            "status": "warning",
            "detail": (
                f"/dev/shm is {default_facts['shmMb']} MiB; multi-GPU shared-memory transports "
                f"need at least {shm_min_mb} MiB"
            ),
        }
    else:
        checks["shm"] = {"status": "pass", "detail": f"/dev/shm is {default_facts['shmMb']} MiB"}

    # RDMA device nodes: a cluster that advertises an rdma extended resource
    # injects /dev/infiniband on request, so only the tuned pod can see it
    # there. With no advertised resource, no conformant pod spec can reach the
    # fabric, and the default-pod reading is the tenant experience.
    tuned_facts = tuned.get("facts")
    if default_facts is None:
        checks["rdmaDevices"] = {"status": "unknown", "detail": "the default pod facts were not collected"}
    elif default_facts["ibUverbsDevices"] > 0:
        checks["rdmaDevices"] = {
            "status": "present",
            "detail": f"{default_facts['ibUverbsDevices']} uverbs device(s) visible in the default pod",
        }
    elif rdma_resources and isinstance(tuned_facts, dict) and tuned_facts.get("ibUverbsDevices", 0) > 0:
        checks["rdmaDevices"] = {
            "status": "requestable",
            "detail": (
                f"absent from the default pod; requesting {tuned['rdmaResourceRequested']} injected "
                f"{tuned_facts['ibUverbsDevices']} uverbs device(s)"
            ),
        }
    elif rdma_resources:
        checks["rdmaDevices"] = {
            "status": "unknown",
            "detail": (
                f"absent from the default pod; the cluster advertises {', '.join(rdma_resources)} "
                "and the tuned pod could not verify injection"
            ),
        }
    elif dra_rdma_classes:
        checks["rdmaDevices"] = {
            "status": "unknown",
            "detail": (
                "absent from the default pod; the cluster exposes RDMA through DRA device "
                f"class(es) {', '.join(dra_rdma_classes)}, which this check does not request"
            ),
        }
    else:
        checks["rdmaDevices"] = {
            "status": "absent",
            "detail": "no /dev/infiniband device nodes in the default pod, and no RDMA-capable extended resource is advertised",
        }

    # GDRCopy device node: optional userspace GPU-memory copy acceleration.
    # Injection normally comes from the GPU Operator / CDI, not from a
    # resource request, so the default-pod reading is the tenant experience.
    if default_facts is None:
        checks["gdrcopyDevice"] = {"status": "unknown", "detail": "the default pod facts were not collected"}
    elif default_facts["gdrdrvDevice"] or (isinstance(tuned_facts, dict) and tuned_facts.get("gdrdrvDevice")):
        checks["gdrcopyDevice"] = {"status": "present", "detail": "/dev/gdrdrv is visible to tenant pods"}
    elif not gpu_requested:
        checks["gdrcopyDevice"] = {
            "status": "unknown",
            "detail": "the check pod did not request a GPU, so device injection was not exercised",
        }
    else:
        checks["gdrcopyDevice"] = {"status": "absent", "detail": "/dev/gdrdrv is not visible to tenant pods"}

    # Tuned pod: does admission accept the documented pod-spec remedy, and
    # does the remedy take effect at runtime? A namespace that enforces the
    # privileged pod-security profile admits everything, so acceptance there
    # is not a tenant signal.
    if privileged_namespace:
        checks["tunedPodAdmission"] = {
            "status": "unknown",
            "detail": (
                "the check namespace enforces the privileged pod-security profile, so admission "
                "acceptance there is not a tenant signal; set CLUSTERMAX_AUDIT_TENANT_NAMESPACE "
                "to a tenant namespace"
            ),
        }
    elif not tuned.get("attempted"):
        checks["tunedPodAdmission"] = {
            "status": "unknown",
            "detail": str(tuned.get("reason") or "the tuned pod was not attempted"),
        }
    elif not tuned.get("admitted"):
        checks["tunedPodAdmission"] = {
            "status": "warning",
            "detail": f"admission rejected the tuned pod spec: {tuned.get('reason')}",
        }
    elif not tuned.get("ready"):
        checks["tunedPodAdmission"] = {
            "status": "unknown",
            "detail": f"the tuned pod was admitted and did not reach Ready: {tuned.get('reason')}",
        }
    elif privileged_namespace is None:
        checks["tunedPodAdmission"] = {
            "status": "unknown",
            "detail": (
                "the namespace pod-security policy could not be read, so admission "
                "acceptance is not a verified tenant signal"
            ),
        }
    elif isinstance(tuned_facts, dict) and tuned_facts.get("capIpcLock") is True and as_int(tuned_facts.get("shmMb"), default=0) >= shm_min_mb:
        checks["tunedPodAdmission"] = {
            "status": "pass",
            "detail": (
                f"admitted; CAP_IPC_LOCK granted, /dev/shm {tuned_facts.get('shmMb')} MiB"
            ),
        }
    else:
        cap_state = tuned_facts.get("capIpcLock") if isinstance(tuned_facts, dict) else None
        shm_state = tuned_facts.get("shmMb") if isinstance(tuned_facts, dict) else None
        checks["tunedPodAdmission"] = {
            "status": "warning",
            "detail": (
                f"the tuned pod ran and the remedies did not take effect: "
                f"CAP_IPC_LOCK={cap_state}, /dev/shm={shm_state} MiB"
            ),
        }

    return checks


def aggregate(
    checks: dict[str, dict[str, str]],
    *,
    default_pod: dict[str, Any],
    tuned: dict[str, Any],
    errors: list[str],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Fold per-check verdicts into the check result. Never grades `fail`."""
    warnings = [f"{name}: {check['detail']}" for name, check in checks.items() if check["status"] == "warning"]
    warnings.extend(errors)
    facts = default_pod.get("facts")
    if not isinstance(facts, dict):
        status = "unknown"
        message = str(default_pod.get("reason") or "the default tenant pod check did not run")
    elif any(check["status"] == "warning" for check in checks.values()):
        status = "warning"
        message = "; ".join(
            f"{name}: {check['detail']}" for name, check in checks.items() if check["status"] == "warning"
        )
    elif context.get("namespaceEnforcesPrivileged", False) is None:
        status = "unknown"
        message = checks.get("tunedPodAdmission", {}).get("detail") or (
            "the namespace pod-security policy could not be read"
        )
    else:
        status = "pass"
        message = (
            f"default tenant pod: memlock {_fmt_memlock(facts)}, "
            f"/dev/shm {facts.get('shmMb')} MiB, "
            f"{facts.get('ibUverbsDevices')} uverbs device(s), gdrdrv {facts.get('gdrdrvDevice')}"
        )
    return {
        "status": status,
        "message": message,
        "failures": [],
        "warnings": warnings,
        **context,
        "default": default_pod,
        "tuned": tuned,
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Kubernetes plumbing
# ---------------------------------------------------------------------------


def pod_manifest(
    namespace: str,
    pod_name: str,
    image: str,
    *,
    gpu_key: str,
    tuned: bool,
    rdma_resource: str,
    tuned_shm: str,
) -> dict[str, Any]:
    limits: dict[str, str] = {}
    if gpu_key:
        limits[gpu_key] = "1"
    container: dict[str, Any] = {
        "name": "check",
        "image": image,
        "imagePullPolicy": os.environ.get("CLUSTERMAX_AUDIT_K8S_GPU_CHECK_PULL_POLICY", "IfNotPresent"),
        "command": ["sh", "-c", "sleep 600"],
    }
    if limits:
        container["resources"] = {"limits": dict(limits)}
    spec: dict[str, Any] = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 5,
        "activeDeadlineSeconds": 900,
        "tolerations": [{"operator": "Exists"}],
        "containers": [container],
    }
    if tuned:
        container["securityContext"] = {"capabilities": {"add": ["IPC_LOCK"]}}
        container["volumeMounts"] = [{"name": "shm", "mountPath": "/dev/shm"}]
        spec["volumes"] = [{"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": tuned_shm}}]
        if rdma_resource:
            limits[rdma_resource] = "1"
            container["resources"] = {"limits": dict(limits)}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "clustermax-tenant-audit"},
        },
        "spec": spec,
    }


def run_pod_check(namespace: str, manifest: dict[str, Any], wait_s: int) -> dict[str, Any]:
    """Apply one check pod, read its facts, and always delete it."""
    pod_name = manifest["metadata"]["name"]
    result: dict[str, Any] = {
        "admitted": False,
        "ready": False,
        "reason": "",
        "node": "",
        "facts": None,
    }
    try:
        apply_proc = kubectl(["apply", "-f", "-"], timeout=45, input_text=json.dumps(manifest))
        if apply_proc.returncode != 0:
            result["reason"] = apply_proc.stderr.strip()
            return result
        result["admitted"] = True

        wait_proc = kubectl(
            ["wait", f"pod/{pod_name}", "-n", namespace, "--for=condition=Ready", f"--timeout={wait_s}s"],
            timeout=wait_s + 15,
        )
        if wait_proc.returncode != 0:
            status_proc = kubectl(
                ["get", "pod", pod_name, "-n", namespace, "-o",
                 'jsonpath={.status.phase} {.status.conditions[?(@.type=="PodScheduled")].message}'],
                timeout=30,
            )
            detail = status_proc.stdout.strip() if status_proc.returncode == 0 else wait_proc.stderr.strip()
            result["reason"] = f"pod did not reach Ready in {wait_s}s: {detail}"
            return result
        result["ready"] = True

        node_proc = kubectl(["get", "pod", pod_name, "-n", namespace, "-o", "jsonpath={.spec.nodeName}"], timeout=30)
        if node_proc.returncode == 0:
            result["node"] = node_proc.stdout.strip()

        exec_proc = kubectl(
            ["exec", "-n", namespace, pod_name, "--", "sh", "-c", FACTS_SCRIPT],
            timeout=60,
        )
        if exec_proc.returncode != 0:
            result["reason"] = f"facts exec failed: {exec_proc.stderr.strip()}"
            return result
        result["facts"] = pod_facts(parse_facts(exec_proc.stdout))
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = f"check pod failed: {exc}"
        return result
    finally:
        try:
            kubectl(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=false"], timeout=20)
        except Exception:
            pass


def run_k8s_check() -> dict[str, Any]:
    namespace = os.environ.get("CLUSTERMAX_AUDIT_TENANT_NAMESPACE", "default")
    image = os.environ.get("CLUSTERMAX_AUDIT_K8S_GPU_IMAGE", DEFAULT_IMAGE)
    wait_s = env_int("CLUSTERMAX_AUDIT_TENANT_POD_WAIT_S", 180)
    memlock_min_mb = env_int("CLUSTERMAX_AUDIT_TENANT_MEMLOCK_MIN_MB", 65536)
    shm_min_mb = env_int("CLUSTERMAX_AUDIT_TENANT_SHM_MIN_MB", 1024)
    tuned_shm = os.environ.get("CLUSTERMAX_AUDIT_TENANT_TUNED_SHM", "8Gi")

    context: dict[str, Any] = {
        "harness": "k8s",
        "namespace": namespace,
        "image": image,
        "gpuResource": "",
        "clusterRdmaResources": [],
        "thresholds": {"memlockMinMb": memlock_min_mb, "shmMinMb": shm_min_mb},
    }
    empty_tuned: dict[str, Any] = {"attempted": False, "admitted": False, "ready": False, "reason": "", "node": "", "rdmaResourceRequested": "", "facts": None}

    try:
        nodes_proc = kubectl(["get", "nodes", "-o", "json"], timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return aggregate({}, default_pod={"admitted": False, "ready": False, "reason": f"kubectl get nodes failed: {exc}", "node": "", "facts": None}, tuned=empty_tuned, errors=[], context=context)
    if nodes_proc.returncode != 0:
        return aggregate({}, default_pod={"admitted": False, "ready": False, "reason": f"kubectl get nodes failed: {nodes_proc.stderr.strip()}", "node": "", "facts": None}, tuned=empty_tuned, errors=[], context=context)
    try:
        nodes_json = json.loads(nodes_proc.stdout)
    except json.JSONDecodeError as exc:
        return aggregate({}, default_pod={"admitted": False, "ready": False, "reason": f"kubectl get nodes returned invalid JSON: {exc}", "node": "", "facts": None}, tuned=empty_tuned, errors=[], context=context)

    if not load_fanout().k8s_gpu_nodes(nodes_json):
        result = aggregate({}, default_pod={"admitted": False, "ready": False, "reason": NO_K8S_GPU_NODES, "node": "", "facts": None}, tuned=empty_tuned, errors=[], context=context)
        result["status"] = "not_applicable"
        result["message"] = NO_K8S_GPU_NODES
        return result

    gpu_key = gpu_resource_key(nodes_json)
    rdma_resources = cluster_rdma_resources(nodes_json)
    dra_rdma = dra_rdma_device_classes()
    privileged_ns = namespace_enforces_privileged(namespace)
    context["gpuResource"] = gpu_key
    context["clusterRdmaResources"] = rdma_resources
    context["draRdmaDeviceClasses"] = dra_rdma
    context["namespaceEnforcesPrivileged"] = privileged_ns
    errors: list[str] = []
    if not gpu_key:
        errors.append("no scalar GPU extended resource is allocatable (DRA cluster?); the check pods request no GPU")

    suffix = uuid.uuid4().hex[:8]
    default_pod = run_pod_check(
        namespace,
        pod_manifest(namespace, f"cmax-tenant-default-{suffix}", image, gpu_key=gpu_key, tuned=False, rdma_resource="", tuned_shm=tuned_shm),
        wait_s,
    )

    tuned = dict(empty_tuned)
    if default_pod.get("facts") is not None:
        rdma_request = rdma_resources[0] if rdma_resources else ""
        tuned_run = run_pod_check(
            namespace,
            pod_manifest(namespace, f"cmax-tenant-tuned-{suffix}", image, gpu_key=gpu_key, tuned=True, rdma_resource=rdma_request, tuned_shm=tuned_shm),
            wait_s,
        )
        tuned = {"attempted": True, "rdmaResourceRequested": rdma_request, **tuned_run}
    else:
        tuned["reason"] = "the default pod check did not run, so the tuned pod was not attempted"

    checks = evaluate_checks(
        default_pod.get("facts"),
        tuned,
        gpu_requested=bool(gpu_key),
        rdma_resources=rdma_resources,
        memlock_min_mb=memlock_min_mb,
        shm_min_mb=shm_min_mb,
        dra_rdma_classes=dra_rdma,
        privileged_namespace=privileged_ns,
    )
    return aggregate(checks, default_pod=default_pod, tuned=tuned, errors=errors, context=context)


def run_default_check(harness: str) -> dict[str, Any]:
    if harness != "k8s":
        return {
            "tenant_pod_defaults": {
                "status": "not_applicable",
                "message": "the tenant pod defaults check covers the Kubernetes harness only",
                "failures": [],
                "warnings": [],
                "harness": harness,
            }
        }
    if os.environ.get("CLUSTERMAX_AUDIT_TENANT_POD_CHECK", "1") == "0":
        return {
            "tenant_pod_defaults": {
                "status": "unknown",
                "message": "the tenant pod defaults check was disabled by CLUSTERMAX_AUDIT_TENANT_POD_CHECK=0",
                "failures": [],
                "warnings": [],
                "harness": harness,
            }
        }
    return {"tenant_pod_defaults": run_k8s_check()}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone"))
    args = parser.parse_args(argv)
    print(json.dumps(run_default_check(args.harness), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
