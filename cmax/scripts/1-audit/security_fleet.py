"""Merge per-host security verdicts into one fleet verdict.

The focused security audit reads one sampled GPU worker in full. A host-level
minimum (driver, runtime, firmware, kernel) on that one worker says nothing
about the others, so the collector also reads every GPU host and this module
reports the worst host for each host-level check.

Input on stdin:

    {
      "sampled": {"securityVersions": {...}, "security": {...}},
      "hostsTotal": 3,
      "hosts": [
        {"node": "gpu-a", "checked": true,
         "securityVersions": {...}, "security": {...}},
        {"node": "gpu-b", "checked": false, "error": "..."}
      ]
    }

Output on stdout: {"securityVersions": {...}, "security": {...}}, the sampled
blocks with each host-level check replaced by its fleet verdict.
"""

from __future__ import annotations

import copy
import json
import sys
from typing import Any

# Checks whose evidence lives on each GPU host. Cluster-level checks (the
# dcgm-exporter image, the CUDA runtime pods, and the BlueField VIRTIO-Net and
# DPU host-isolation results, which both come from the fabric-wide virtio-net
# check) already have their own scope and are left as the collector built them.
VERSION_KEYS = (
    "nvidiaDriver",
    "amdDriver",
    "nvidiaContainerToolkit",
    "runc",
    "docker",
    "connectxFirmware",
    "dcgm",
)
ADVISORY_KEYS = (
    "badEpoll",
    "fragnesia",
    "ubuntuNobleKernelMinimum",
    "januscape",
)

# Worst first. A status this table does not know ranks with "unknown", so a
# new vocabulary word can never outrank a failure or pass as clean.
_RANK = {
    "fail": 4,
    "host-patch-required": 4,
    "vulnerable": 4,
    "exposed": 4,
    "unknown": 3,
    "coverage-incomplete": 3,
    "provider_attestation_required": 3,
    "warning": 2,
    "pass": 1,
    "patched": 1,
    "not-exposed": 1,
    "not_applicable": 0,
    "not-applicable": 0,
    "not-installed": 0,
}
_UNKNOWN_RANK = _RANK["unknown"]
_CLEAN_RANK = _RANK["pass"]


def rank(status: Any) -> int:
    return _RANK.get(str(status or "unknown").strip().lower(), _UNKNOWN_RANK)


def _status(block: Any) -> str:
    if isinstance(block, dict):
        return str(block.get("status") or "unknown")
    return "unknown"


def _host_summary(node: str, block: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {"node": node, "status": _status(block)}
    if isinstance(block, dict) and block.get("version") not in (None, ""):
        summary["version"] = block["version"]
    return summary


def _merge_connectx(per_host: list[tuple[str, dict[str, Any]]], multi: bool) -> dict[str, Any]:
    worst_node, worst = max(per_host, key=lambda item: rank(_status(item[1])))
    merged = copy.deepcopy(worst)
    devices = []
    for node, block in per_host:
        for device in block.get("devices") or []:
            entry = dict(device)
            if multi:
                entry["device"] = f"{node}/{device.get('device', 'unknown')}"
                entry["host"] = node
            devices.append(entry)
    merged["devices"] = devices
    return merged


def merge_check(
    key: str,
    sampled: Any,
    hosts: list[dict[str, Any]],
    section: str,
    hosts_total: int,
) -> Any:
    checked = [h for h in hosts if h.get("checked") is True]
    per_host = [
        (str(h.get("node") or "unknown"), h.get(section, {}).get(key))
        for h in checked
        if isinstance(h.get(section, {}).get(key), dict)
    ]
    # The sampled block stays when no host record carries this check, so an
    # older or failed per-host build never erases evidence.
    if not per_host:
        return sampled
    unassessed = [str(h.get("node") or "unknown") for h in hosts if h.get("checked") is not True]
    read_nodes = {node for node, _ in per_host}
    unassessed += [
        str(h.get("node") or "unknown")
        for h in checked
        if str(h.get("node") or "unknown") not in read_nodes
    ]
    missing = max(hosts_total - len(hosts), 0)
    multi = len(per_host) > 1

    if key == "connectxFirmware":
        merged = _merge_connectx(per_host, multi)
        worst_node = max(per_host, key=lambda item: rank(_status(item[1])))[0]
    else:
        worst_node, worst = max(per_host, key=lambda item: rank(_status(item[1])))
        merged = copy.deepcopy(worst)
        if multi and merged.get("detail"):
            merged["detail"] = f"{worst_node}: {merged['detail']}"

    if (unassessed or missing) and rank(_status(merged)) <= _CLEAN_RANK:
        gap = len(unassessed) + missing
        read_status = _status(merged)
        merged["status"] = "unknown"
        merged["detail"] = (
            f"{len(per_host)} of {len(per_host) + gap} GPU hosts were read and graded "
            f"{read_status}; the hosts the audit could not read are unverified."
        )

    merged["fleet"] = {
        "scope": "every-gpu-host",
        "hostsTotal": max(hosts_total, len(hosts)),
        "hostsChecked": len(per_host),
        "coverageComplete": not unassessed and not missing,
        "unassessedHosts": unassessed,
        "worstHost": worst_node,
        "hosts": [_host_summary(node, block) for node, block in per_host],
    }
    return merged


def merge(payload: dict[str, Any]) -> dict[str, Any]:
    sampled = payload.get("sampled") or {}
    versions = copy.deepcopy(sampled.get("securityVersions") or {})
    security = copy.deepcopy(sampled.get("security") or {})
    hosts = [h for h in payload.get("hosts") or [] if isinstance(h, dict)]
    try:
        hosts_total = int(payload.get("hostsTotal") or len(hosts))
    except (TypeError, ValueError):
        hosts_total = len(hosts)
    for key in VERSION_KEYS:
        merged = merge_check(key, versions.get(key), hosts, "securityVersions", hosts_total)
        if merged is not None:
            versions[key] = merged
    for key in ADVISORY_KEYS:
        merged = merge_check(key, security.get(key), hosts, "security", hosts_total)
        if merged is not None:
            security[key] = merged
    return {"securityVersions": versions, "security": security}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"security_fleet: invalid input: {exc}", file=sys.stderr)
        return 1
    json.dump(merge(payload), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
