#!/usr/bin/env python3
"""Read-only toolkit inventory in active GPU workloads on the sampled worker."""
import argparse
import json
import re
import subprocess
import sys

import security_version_audit as policy

PROBE = r"""
p=$(command -v nvcc 2>/dev/null || true)
[ -n "$p" ] || { [ ! -x /usr/local/cuda/bin/nvcc ] || p=/usr/local/cuda/bin/nvcc; }
if [ -n "$p" ]; then
    out=$("$p" --version 2>/dev/null) || exit 2
    v=$(printf '%s\n' "$out" | sed -nE 's/.*V([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -1)
    [ -n "$v" ] || exit 2
    printf 'CUDA_TOOLKIT_VERSION=%s\n' "$v"
elif [ -r /usr/local/cuda/version.json ]; then
    printf 'CUDA_VERSION_JSON\n'
    head -c 65536 /usr/local/cuda/version.json
elif [ -d /usr/local/cuda ]; then
    printf 'CUDA_TOOLKIT_VERSION=unknown\n'
else
    printf 'CUDA_TOOLKIT_VERSION=not_installed\n'
fi
"""


def run(argv):
    try:
        p = subprocess.run(["kubectl", *argv], text=True, capture_output=True,
                           timeout=30, check=False)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def targets(pods, node):
    selected = []
    for pod in pods.get("items", []):
        spec = pod.get("spec", {})
        if spec.get("nodeName") != node or pod.get("status", {}).get("phase") != "Running":
            continue
        for container in spec.get("containers", []):
            resources = container.get("resources", {})
            gpu = any(
                re.fullmatch(r"nvidia[.]com/(?:gpu(?:[.]shared)?|mig-[A-Za-z0-9_.-]+)", str(k))
                and str(v) not in {"0", ""}
                for kind in ("requests", "limits")
                for k, v in resources.get(kind, {}).items()
            ) or bool(resources.get("claims"))
            if gpu:
                selected.append({
                    "namespace": pod["metadata"]["namespace"],
                    "pod": pod["metadata"]["name"], "container": container["name"],
                    "node": node,
                })
    return sorted(selected, key=lambda t: (t["namespace"], t["pod"], t["container"]))


def verdict(version):
    return policy._verdict_record(policy.cuda_toolkit_verdict(version), "cudaToolkit")


def enrich(document, node, runner=run):
    rc, raw = runner(["get", "pods", "-A", "--field-selector",
                      f"spec.nodeName={node}", "-o", "json"])
    coverage = rc == 0
    try:
        discovered = targets(json.loads(raw), node) if coverage else []
    except (ValueError, TypeError, KeyError):
        discovered, coverage = [], False
    if len(discovered) > 16:
        coverage = False
    records = []
    for target in discovered[:16]:
        rc, raw = runner(["-n", target["namespace"], "exec", target["pod"],
                          "-c", target["container"], "--", "sh", "-c", PROBE])
        match = re.search(
            r"^CUDA_TOOLKIT_VERSION=([0-9]+\.[0-9]+\.[0-9]+|not_installed)$", raw, re.M
        )
        version = match.group(1) if rc == 0 and match else "unknown"
        if rc == 0 and raw.startswith("CUDA_VERSION_JSON\n"):
            try:
                metadata = json.loads(raw.split("\n", 1)[1])
                candidate = metadata.get("cuda", {}).get("version", "")
                if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", candidate):
                    version = candidate
            except (ValueError, AttributeError, TypeError):
                pass
        coverage = coverage and version != "unknown"
        records.append({**target, "scope": "gpu-workload-container", **verdict(version)})
    document.setdefault("runtimeSoftware", {})["cudaToolkit"] = {
        "scope": "active-gpu-containers-on-sampled-worker",
        "node": node, "coverageComplete": coverage,
        "discoveredContainers": len(discovered), "containers": records,
    }
    existing = document.setdefault("securityVersions", {}).get("cudaToolkit", {})
    if not records and coverage:
        return document
    candidates = [existing, *records]
    if not coverage:
        candidates.append(verdict("unknown"))
    rank = {"fail": 4, "unknown": 3, "pass": 2, "not_applicable": 1}
    worst = max(candidates, key=lambda row: rank.get(row.get("status", "unknown"), 3))
    # Keep grace-window metadata as well as the actual failing version.
    observed = dict(worst)
    observed.update(scope="host-and-active-gpu-containers-on-sampled-worker",
                    coverageComplete=coverage, containers=records)
    if not coverage and observed["status"] != "fail":
        observed["detail"] = "GPU workload toolkit inventory is incomplete; no clean verdict is possible."
    document["securityVersions"]["cudaToolkit"] = observed
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    print(json.dumps(enrich(json.load(sys.stdin), args.node)))


if __name__ == "__main__":
    main()
