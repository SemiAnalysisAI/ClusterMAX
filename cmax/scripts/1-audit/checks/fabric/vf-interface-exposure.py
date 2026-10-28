#!/usr/bin/env python3
"""Collect VF/interface metadata without opening devices or submitting commands.

This is supporting evidence, not a security verdict or a reachability test.
Only sysfs/proc text, symlinks, and device-node metadata are read. Remote arms
run the same collector under the selected task/container identity, without sudo,
privileged pods, device allocation, firmware queries, or driver changes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from typing import Any

MAX_ENTRIES = 512
MAX_TEXT = 8192
KEY = "vf_interface_exposure"


def collect(*, root: Path = Path("/")) -> dict[str, Any]:
    """Inspect the current process view. A different root supports fixture tests."""
    errors: list[str] = []

    def path(name: str) -> Path:
        return root / name.lstrip("/")

    def entries(directory: Path, *, required: bool = False) -> list[Path]:
        try:
            # Bound iteration before sorting, not after materializing the directory.
            found = []
            for item in directory.iterdir():
                if len(found) >= MAX_ENTRIES:
                    errors.append(f"{directory}: inventory limit {MAX_ENTRIES} reached")
                    break
                found.append(item)
            return sorted(found)
        except FileNotFoundError:
            if required:
                errors.append(f"{directory}: not visible")
        except OSError as exc:
            errors.append(f"{directory}: {type(exc).__name__}")
        return []

    def text(file: Path, *, required: bool = False) -> str | None:
        try:
            with file.open(errors="replace") as stream:
                value = stream.read(MAX_TEXT + 1)
            if len(value) > MAX_TEXT:
                errors.append(f"{file}: text limit reached")
                return None
            return value.strip()
        except FileNotFoundError:
            if required:
                errors.append(f"{file}: not visible")
        except OSError as exc:
            errors.append(f"{file}: {type(exc).__name__}")
        return None

    def target(link: Path) -> Path | None:
        try:
            link.readlink()
            return link.resolve(strict=True)
        except FileNotFoundError:
            return None
        except (OSError, RuntimeError) as exc:
            errors.append(f"{link}: {type(exc).__name__}")
            return None

    def node(file: Path) -> dict[str, Any]:
        record: dict[str, Any] = {"path": "/" + str(file.relative_to(root))}
        try:
            metadata = file.stat()
            character = stat.S_ISCHR(metadata.st_mode)
            record.update({
                "character_device": character,
                "mode": oct(stat.S_IMODE(metadata.st_mode)),
                "uid": metadata.st_uid, "gid": metadata.st_gid,
                "major": os.major(metadata.st_rdev) if character else None,
                "minor": os.minor(metadata.st_rdev) if character else None,
                "effective_access_hint": os.access(
                    file, os.R_OK | os.W_OK, effective_ids=True
                ),
                "device_open": "not_tested",
            })
        except (OSError, NotImplementedError) as exc:
            record["error"] = type(exc).__name__
            errors.append(f"{file}: {type(exc).__name__}")
        return record

    status_text = text(path("proc/self/status"), required=True) or ""
    selected = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
                "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}
    process_status = {
        key: value.strip()
        for line in status_text.splitlines() if ":" in line
        for key, value in [line.split(":", 1)] if key in selected
    }
    namespaces = {}
    for name in ("user", "mnt", "pid", "net"):
        try:
            namespaces[name] = str(path(f"proc/self/ns/{name}").readlink())
        except OSError:
            namespaces[name] = "unknown"

    visible = [
        node(item) for item in entries(path("dev/infiniband"))
        if re.fullmatch(r"uverbs\d+", item.name)
    ]
    visible += [
        node(item) for item in entries(path("dev/vfio"))
        if item.name.isdigit()
    ]
    visible += [
        node(item) for item in entries(path("dev/vfio/devices"))
        if re.fullmatch(r"vfio\d+", item.name)
    ]
    by_path = {item["path"]: item for item in visible}
    hcas: dict[str, list[dict[str, Any]]] = {}
    hca_pci: dict[str, str] = {}
    for hca in entries(path("sys/class/infiniband")):
        pci = target(hca / "device")
        if pci is not None:
            hca_pci[hca.name] = pci.name
            hcas.setdefault(pci.name, []).append({
                "name": hca.name, "firmware": text(hca / "fw_ver") or "unknown",
                "firmware_source": "sysfs fw_ver",
            })
    verbs: dict[str, list[dict[str, Any]]] = {}
    for interface in entries(path("sys/class/infiniband_verbs")):
        # Linux ibdev_show is a read-only text attribute containing the HCA name.
        ibdev = text(interface / "ibdev", required=True)
        pci_name = hca_pci.get(ibdev) if ibdev else None
        device_node = by_path.get(f"/dev/infiniband/{interface.name}")
        if pci_name and device_node:
            verbs.setdefault(pci_name, []).append(device_node)

    devices = []
    for pci in entries(path("sys/bus/pci/devices"), required=True):
        vendor = text(pci / "vendor", required=True)
        if vendor != "0x15b3":
            continue
        pf = target(pci / "physfn")
        driver = target(pci / "driver")
        group = target(pci / "iommu_group")
        total_vfs = text(pci / "sriov_totalvfs")
        role = "vf" if pf else ("pf" if total_vfs is not None else "unknown")
        interfaces = list(verbs.get(pci.name, []))
        vfio = by_path.get(f"/dev/vfio/{group.name}") if group else None
        if vfio:
            interfaces.append(vfio)
        for cdev in entries(pci / "vfio-dev"):
            if (interface := by_path.get(f"/dev/vfio/devices/{cdev.name}")):
                interfaces.append(interface)
        devices.append({
            "pci_address": pci.name, "vendor": vendor,
            "device_id": text(pci / "device") or "unknown",
            "subsystem_vendor": text(pci / "subsystem_vendor") or "unknown",
            "subsystem_device": text(pci / "subsystem_device") or "unknown",
            "function_type": role,
            "physical_function": pf.name if pf else "unknown",
            "driver": driver.name if driver else "unknown",
            "iommu_group": group.name if group else "unknown",
            "sriov_totalvfs": total_vfs,
            "hcas": hcas.get(pci.name, []),
            "interfaces": interfaces,
        })

    uid_map = text(path("proc/self/uid_map")) or "unknown"
    return {
        "kind": KEY, "host": os.environ.get("SLURMD_NODENAME") or socket.gethostname(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "status": "observed" if devices and not errors else "unknown",
        "method": "metadata-only",
        "identity": {
            "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
            "egid": os.getegid(), "groups": os.getgroups(),
            "process_status": process_status,
            "uid_map": uid_map,
            "namespaces": namespaces,
        },
        "devices": devices, "visible_interfaces": visible, "errors": errors,
        "evidence": {
            "command_submission": "not_tested", "vulnerable_handler": "unverified",
            "memory_corruption": "unverified", "device_code_execution": "unverified",
            "host_or_cross_tenant_compromise": "unverified",
        },
        "limitations": [
            "Metadata permissions do not establish device-cgroup, LSM, or firmware authorization.",
            "Missing physfn does not prove a physical function or absence of a VF.",
            "No firmware command, device open, ioctl, or exploit is attempted.",
            "The recorded process identity does not attest another application identity.",
            "Guest-visible PCI addresses require provider mapping to physical adapters.",
        ],
    }


def build_payload(
    harness: str, *, env: dict[str, str] | None = None, runner=subprocess.run,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    scope: dict[str, Any] = {"harness": harness}
    command = None
    expected = 1
    if harness == "standalone":
        scope["coverage"] = "current_process_only"
        records = [collect()]
    elif harness == "slurm":
        scope.update(coverage="allocation_tasks_only", job_id=env.get("SLURM_JOB_ID"))
        count = env.get("SLURM_NNODES") or env.get("SLURM_JOB_NUM_NODES", "")
        if not env.get("SLURM_JOB_ID") or not count.isdigit() or not 0 < int(count) <= MAX_ENTRIES:
            errors.append("An existing Slurm allocation with a bounded node count is required")
        else:
            expected = int(count)
            scope["expected_workers"] = expected
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            import _fanout
            command = _fanout.slurm_python_command(
                node_count=count, worker_args=["--collect-local"]
            )
    elif harness == "k8s":
        # Never inherit the audit-owned privileged check namespace.
        namespace = env.get("CLUSTERMAX_AUDIT_VF_NAMESPACE", "default")
        pod = env.get("CLUSTERMAX_AUDIT_VF_POD", "")
        container = env.get("CLUSTERMAX_AUDIT_VF_CONTAINER", "")
        scope.update(coverage="selected_container_only", namespace=namespace,
                     pod=pod, container=container)
        if not all(re.fullmatch(r"[a-z0-9][a-z0-9.-]*", v)
                   for v in (namespace, pod, container)):
            errors.append("Set CLUSTERMAX_AUDIT_VF_POD and CLUSTERMAX_AUDIT_VF_CONTAINER explicitly")
        else:
            try:
                metadata = runner(
                    ["kubectl", "-n", namespace, "get", "pod", pod, "-o", "json"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                )
                if metadata.returncode:
                    raise ValueError("pod metadata unavailable")
                pod_data = json.loads(metadata.stdout)
                spec = pod_data["spec"]
                selected = next(
                    item for item in spec["containers"] if item["name"] == container
                )
                security_context = selected.get("securityContext") or {}
                scope.update({
                    "pod_uid": pod_data["metadata"]["uid"],
                    "node": spec.get("nodeName", "unknown"),
                    "pod_security_context": spec.get("securityContext", {}),
                    "container_security_context": security_context,
                    "host_network": spec.get("hostNetwork", False),
                    "host_pid": spec.get("hostPID", False),
                    "host_ipc": spec.get("hostIPC", False),
                })
                if security_context.get("privileged") or scope["host_pid"] or scope["host_ipc"]:
                    raise ValueError("privileged/host-namespace container is not tenant evidence")
                command = [
                    "kubectl", "-n", namespace, "exec", "-i", pod, "-c", container,
                    "--", "python3", "-", "--collect-local",
                ]
            except (OSError, subprocess.TimeoutExpired, ValueError, KeyError,
                    TypeError, StopIteration) as exc:
                errors.append(f"Container scope unverified: {type(exc).__name__}: {exc}")
    else:
        errors.append(f"Unsupported harness: {harness}")
    if command:
        try:
            result = runner(
                command, input=Path(__file__).read_text(), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            )
            if result.returncode:
                errors.append(f"Collector exit {result.returncode}: {result.stderr[:512].strip()}")
            seen = set()
            for line in result.stdout.splitlines():
                if not line.strip().startswith("{"):
                    continue
                try:
                    record = json.loads(line)
                    if (record.get("kind") != KEY or not isinstance(record.get("host"), str)
                            or not record["host"] or not isinstance(record.get("devices"), list)
                            or record.get("status") not in {"observed", "unknown"}):
                        raise ValueError("invalid worker record")
                    if record["host"] in seen:
                        raise ValueError("duplicate worker")
                    if len(records) >= expected:
                        raise ValueError("unexpected extra worker")
                    seen.add(record["host"])
                    records.append(record)
                except (ValueError, AttributeError) as exc:
                    errors.append(f"Invalid worker output: {exc}")
            if len(records) != expected:
                errors.append(f"Expected {expected} distinct workers, received {len(records)}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"Collector unavailable: {type(exc).__name__}")
    if harness == "k8s" and records:
        scope["pod_uid_stable"] = False
        try:
            current = runner(
                ["kubectl", "-n", scope["namespace"], "get", "pod", scope["pod"], "-o", "json"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            )
            if current.returncode:
                raise ValueError("post-collection pod metadata unavailable")
            current_uid = json.loads(current.stdout)["metadata"]["uid"]
            if current_uid != scope["pod_uid"]:
                raise ValueError("pod replaced during collection")
            scope["pod_uid_stable"] = True
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
            errors.append(f"Container identity unverified: {type(exc).__name__}: {exc}")
    status = (
        "observed" if records and not errors
        and all(record.get("status") == "observed" for record in records) else "unknown"
    )
    return {KEY: {
        "schema_version": 1, "status": status, "scope": scope, "records": records,
        "errors": errors, "message": (
            f"VF/interface exposure: {status}, {len(records)} process views. "
            "Command access and exploitation remain unverified."
        ),
    }}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-local", action="store_true")
    args = parser.parse_args()
    payload = collect() if args.collect_local else build_payload(
        os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone")
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
