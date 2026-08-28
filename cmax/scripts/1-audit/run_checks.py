#!/usr/bin/env python3
"""Run audit checks and merge their JSON objects."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


CHECK_PROFILES = {
    "fabric/nccl-ib-qps-check.py": frozenset({"networking"}),
    "fabric/nccl-topology-file-check.py": frozenset({"networking"}),
    "fabric/nic-topology-check.py": frozenset(
        {"security", "versions", "isolation", "networking"}
    ),
    "fabric/virtio-net-check.py": frozenset(
        {"security", "versions", "isolation"}
    ),
    "gpu/vboost.py": frozenset({"hardware"}),
    "system/arm-smmu-virtualization-check.py": frozenset({"hardware"}),
    "system/hbm_memory_exposure.py": frozenset({"hardware", "orchestration"}),
    "system/vm-iommu-check.py": frozenset({"hardware"}),
}
CHECK_HARNESSES = {
    "fabric/nccl-ib-qps-check.py": frozenset({"slurm", "k8s"}),
    "fabric/nccl-topology-file-check.py": frozenset({"slurm"}),
    "fabric/nic-topology-check.py": frozenset({"slurm", "k8s"}),
    "fabric/virtio-net-check.py": frozenset({"slurm", "k8s"}),
    "gpu/vboost.py": frozenset({"standalone", "slurm", "k8s"}),
    "system/arm-smmu-virtualization-check.py": frozenset(
        {"standalone", "slurm", "k8s"}
    ),
    "system/hbm_memory_exposure.py": frozenset({"standalone", "slurm", "k8s"}),
    "system/vm-iommu-check.py": frozenset({"standalone", "slurm", "k8s"}),
}
PLATFORM_CHECK_KEYS = {
    "fabric/nccl-ib-qps-check.py": "nccl_ib_qps",
    "fabric/nccl-topology-file-check.py": "nccl_topo_file",
    "system/arm-smmu-virtualization-check.py": "arm_smmu_virtualization",
    "system/vm-iommu-check.py": "vm_iommu",
}
VALID_HARNESSES = frozenset({"standalone", "slurm", "k8s"})
VALID_PROFILES = frozenset(
    {
        "full",
        "security",
        "versions",
        "isolation",
        "hardware",
        "software",
        "containers",
        "orchestration",
        "networking",
        "storage",
        "health",
        "access",
    }
)

GPU_OPERATOR_NAMESPACES = (
    "gpu-operator",
    "gpu-operator-resources",
    "nvidia-gpu-operator",
    "nvidia",
    "kube-amd-gpu",
    "amd-gpu-operator",
    "gpu",
)


def iter_checks(root: Path, harness: str, profile: str = "full") -> list[Path]:
    if not root.exists():
        return []
    if profile not in VALID_PROFILES:
        raise ValueError(f"unknown audit profile: {profile}")
    if harness not in VALID_HARNESSES:
        raise ValueError(f"unknown audit harness: {harness}")
    checks = [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and os.access(path, os.X_OK)
        and "__pycache__" not in path.parts
        and not path.name.startswith(".")
        and harness
        in CHECK_HARNESSES.get(str(path.relative_to(root)), VALID_HARNESSES)
    ]
    if profile == "full":
        return checks
    return [
        path
        for path in checks
        if profile in CHECK_PROFILES.get(str(path.relative_to(root)), frozenset())
    ]


def merge_check_data(merged: dict[str, Any], data: dict[str, Any], check_rel: str) -> None:
    for key, value in data.items():
        if key in merged and merged[key] != value:
            print(f"  WARNING: check {check_rel} overwrote check_data.{key}", file=sys.stderr)
        merged[key] = value


def select_gpu_operator_namespace(names: list[str]) -> str | None:
    available = set(names)
    for namespace in GPU_OPERATOR_NAMESPACES:
        if namespace in available:
            return namespace
    return next(
        (
            namespace
            for namespace in sorted(available)
            if re.search(r"gpu-operator|nvidia-gpu", namespace, re.IGNORECASE)
        ),
        None,
    )


def discover_gpu_operator_namespace() -> str | None:
    configured = os.environ.get("CLUSTERMAX_GPU_OPERATOR_NAMESPACE", "").strip()
    if configured:
        return configured
    try:
        proc = subprocess.run(
            ["kubectl", "get", "namespaces", "-o", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
        names = [
            str(item["metadata"]["name"])
            for item in payload.get("items", [])
            if isinstance(item, dict)
            and isinstance(item.get("metadata"), dict)
            and item["metadata"].get("name")
        ]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return select_gpu_operator_namespace(names)


# Check keys whose payload is a {status, message} verdict. Each one prints a
# summary line, and a fail / warning also reaches stderr so it is visible in a
# scrolling run log before audit_findings.py collects it at the end.
STATUS_CHECK_KEYS = (
    "hbm_memory_exposure",
    "kubelet_cpu_manager_policy",
    "vm_iommu",
    "arm_smmu_virtualization",
    "nccl_topo_file",
    "nccl_ib_qps",
)


def print_check_summary(data: dict[str, Any]) -> None:
    for key in STATUS_CHECK_KEYS:
        payload = data.get(key)
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("status") or "unknown").upper()
        message = str(payload.get("message") or "")
        print(f"  {key}: {status} - {message}")
        if status in {"FAIL", "WARNING"}:
            print(f"  WARNING: {key} {status.lower()}: {message}", file=sys.stderr)


def main(argv: list[str]) -> int:
    if len(argv) not in {4, 5}:
        print(
            "usage: run_checks.py <check-root> <check-data.json> <harness> [profile]",
            file=sys.stderr,
        )
        return 2

    check_root = Path(argv[1])
    out_path = Path(argv[2])
    harness = argv[3]
    profile = argv[4] if len(argv) == 5 else "full"
    try:
        checks = iter_checks(check_root, harness, profile)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    merged: dict[str, Any] = {}
    cache_directory = tempfile.TemporaryDirectory(prefix="clustermax-audit-checks-")
    platform_cache = Path(cache_directory.name) / "platform-config.json"
    platform_check_keys = sorted(
        PLATFORM_CHECK_KEYS[relative]
        for check in checks
        if (relative := str(check.relative_to(check_root))) in PLATFORM_CHECK_KEYS
    )
    gpu_operator_namespace = (
        discover_gpu_operator_namespace() if harness == "k8s" else None
    )
    if checks:
        print("")
    for check in checks:
        rel = str(check.relative_to(check_root))
        print(f"Running audit check: {rel}")
        env = {
            **os.environ,
            "CLUSTERMAX_AUDIT_HARNESS": harness,
            "CLUSTERMAX_PLATFORM_CHECK_CACHE": str(platform_cache),
            "CLUSTERMAX_PLATFORM_CHECK_KEYS": ",".join(platform_check_keys),
        }
        if gpu_operator_namespace:
            env["CLUSTERMAX_GPU_OPERATOR_NAMESPACE"] = gpu_operator_namespace
        # A checkout shared from Windows can carry CRLF even when the Git blob
        # uses LF. Launch Python checks through this interpreter so Linux never
        # asks /usr/bin/env to resolve the shebang as the invalid `python3\r`.
        argv = (
            [sys.executable, str(check)]
            if check.suffix == ".py"
            else [str(check)]
        )
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            print(f"  WARNING: check {rel} failed with exit {proc.returncode}", file=sys.stderr)
            continue
        stdout = proc.stdout.strip()
        if not stdout:
            continue
        try:
            data = json.loads(stdout)
            if not isinstance(data, dict):
                raise ValueError("check output must be a JSON object")
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"  WARNING: check {rel} emitted invalid JSON: {exc}", file=sys.stderr)
            continue
        merge_check_data(merged, data, rel)
        print_check_summary(data)
        nic_topology = data.get("nic_topology")
        if isinstance(nic_topology, dict):
            if nic_topology:
                print(f"  collected {len(nic_topology)} node(s)")
            else:
                print("  no nic_topology records")
        gpu_controls = data.get("gpu_controls")
        if isinstance(gpu_controls, dict):
            vboost = gpu_controls.get("vboost")
            if isinstance(vboost, dict):
                print(
                    "  vboost "
                    f"{vboost.get('status', 'unknown')}: "
                    f"{vboost.get('allowed_nodes', 0)}/{vboost.get('checked_nodes', 0)} node(s) allowed"
                )

    cache_directory.cleanup()
    out_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
