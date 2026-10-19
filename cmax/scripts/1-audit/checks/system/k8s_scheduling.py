#!/usr/bin/env python3
"""Record Kubernetes scheduling policy without changing cluster state."""

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import yaml

GROUP = "kueue.x-k8s.io"
RESOURCES = {
    "nodes": "nodes",
    "namespaces": "namespaces",
    "localQueues": f"localqueues.{GROUP}",
    "clusterQueues": f"clusterqueues.{GROUP}",
    "resourceFlavors": f"resourceflavors.{GROUP}",
    "topologies": f"topologies.{GROUP}",
    "cohorts": f"cohorts.{GROUP}",
    "admissionChecks": f"admissionchecks.{GROUP}",
    "workloads": f"workloads.{GROUP}",
    "workloadPriorityClasses": f"workloadpriorityclasses.{GROUP}",
    "multiKueueConfigs": f"multikueueconfigs.{GROUP}",
    "multiKueueClusters": f"multikueueclusters.{GROUP}",
    "provisioningRequestConfigs": f"provisioningrequestconfigs.{GROUP}",
    "resourceQuotas": "resourcequotas",
    "limitRanges": "limitranges",
    "priorityClasses": "priorityclasses.scheduling.k8s.io",
    "runtimeClasses": "runtimeclasses.node.k8s.io",
    "controllers": "deployments.apps",
}
SCOPED = {"localQueues", "workloads", "resourceQuotas", "limitRanges"}
MAX_BYTES = 192 * 1024
# A node record holds a few KiB of labels and capacity, so the shared budget
# covers only tens of nodes. Placement evidence must cover large clusters.
NODE_MAX_BYTES = 1024 * 1024


def zero_quantity(value):
    """Recognize zero without rounding nonzero quantities or applying units."""
    match = re.fullmatch(
        r"(?P<number>[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))"
        r"(?:[eE][+-]?[0-9]+|[numkKMGTPE]|[KMGTPE]i)?",
        str(value),
    )
    return match is not None and not any(
        digit in "123456789" for digit in match["number"]
    )


def redact(value):
    if isinstance(value, dict):
        return {
            k: "[redacted]"
            if re.search(
                r"password|token|credential|secret|private.?key", k, re.IGNORECASE
            )
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def read_resource(resource, namespace="", name=""):
    args = ["kubectl", "get", resource]
    if name:
        args.append(name)
    args += ["-A"] if namespace == "*" else ["-n", namespace] if namespace else []
    row = {
        "resource": resource,
        "namespace": namespace,
        "status": "error",
        "complete": False,
        "items": [],
    }
    try:
        proc = subprocess.run(
            args + ["-o", "json", "--request-timeout=12s"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode:
            error = proc.stderr.lower()
            if "forbidden" in error or "unauthorized" in error:
                row["status"] = "forbidden"
            elif any(
                s in error
                for s in (
                    "doesn't have a resource type",
                    "the server could not find the requested resource",
                )
            ):
                row.update(status="absent", complete=True)
            return row
        data = json.loads(proc.stdout)
        items = [data] if name else data["items"]
        if not isinstance(items, list) or any(
            not isinstance(x, dict)
            or not isinstance(x.get("metadata"), dict)
            or not x["metadata"].get("name")
            for x in items
        ):
            raise ValueError("Invalid resource list")
        row.update(status="collected" if items else "empty", complete=True, items=items)
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
        row["detail"] = f"The resource read failed with {type(exc).__name__}."
    return row


def select(item, key):
    metadata = item.get("metadata", {})
    result = {
        "metadata": {
            k: metadata[k] for k in ("name", "namespace", "labels") if k in metadata
        }
    }
    result["metadata"]["annotations"] = {
        k: v
        for k, v in metadata.get("annotations", {}).items()
        if k.partition("/")[0] == GROUP
    }
    if key == "controllers":
        pod = item.get("spec", {}).get("template", {}).get("spec", {})
        containers = pod.get("containers", [])
        if not (
            "kueue" in metadata.get("name", "").lower()
            or "kueue" in metadata.get("labels", {}).values()
            or any(
                re.search(r"(?:^|/)kueue(?:[/:@-])", c.get("image", ""))
                for c in containers
            )
        ):
            return None
        result["containers"] = []
        for c in containers:
            args = c.get("args", [])
            kept = []
            for i, arg in enumerate(args):
                if arg.startswith(("--config=", "--feature-gates=")):
                    kept.append(arg)
                elif arg in {"--config", "--feature-gates"} and i + 1 < len(args):
                    kept.extend([arg, args[i + 1]])
            result["containers"].append(
                {"name": c.get("name"), "image": c.get("image"), "args": kept}
            )
        sources = [
            s
            for v in pod.get("volumes", [])
            for s in [v, *v.get("projected", {}).get("sources", [])]
        ]
        result["configMaps"] = sorted(
            {
                s["configMap"]["name"]
                for s in sources
                if s.get("configMap", {}).get("name")
                and s["configMap"]["name"] != "kube-root-ca.crt"
            }
        )
        result["status"] = item.get("status", {})
    elif key in {"nodes", "workloads"}:
        spec_keys = (
            ("taints", "unschedulable")
            if key == "nodes"
            else ("queueName", "priority", "active")
        )
        status_keys = (
            ("conditions", "capacity", "allocatable")
            if key == "nodes"
            else ("conditions", "admission", "admissionChecks", "requeueState")
        )
        result["spec"] = {
            k: v for k, v in item.get("spec", {}).items() if k in spec_keys
        }
        result["status"] = {
            k: v for k, v in item.get("status", {}).items() if k in status_keys
        }
        conditions = result["status"].get("conditions")
        if key == "nodes" and isinstance(conditions, list):
            # Condition timestamps dominate the record size and carry no
            # placement evidence, so only the health verdict fields remain.
            result["status"]["conditions"] = [
                {k: c[k] for k in ("type", "status", "reason") if k in c}
                for c in conditions
                if isinstance(c, dict)
            ]
    else:
        result.update(
            {
                k: item[k]
                for k in (
                    "spec",
                    "status",
                    "value",
                    "globalDefault",
                    "preemptionPolicy",
                    "handler",
                    "overhead",
                    "scheduling",
                )
                if k in item
            }
        )
    return redact(result)


def group_message(names, one, many):
    if len(names) == 1:
        return f"Node {names[0]} {one}."
    return f"{len(names)} nodes {many}, for example {', '.join(sorted(names)[:3])}."


def collect(namespace):
    def read(entry):
        key, resource = entry
        row = read_resource(
            resource,
            namespace if key in SCOPED else "*" if key == "controllers" else "",
        )
        selected = [
            s for s in (select(item, key) for item in row["items"]) if s is not None
        ]
        limit = NODE_MAX_BYTES if key == "nodes" else MAX_BYTES
        kept, size = [], 0
        for item in selected:
            size += len(json.dumps(item).encode())
            if len(kept) >= 1024 or size > limit:
                row.update(
                    complete=False, detail="The resource retention limit was reached."
                )
                break
            kept.append(item)
        if row["status"] == "collected" and not selected and row["complete"]:
            row["status"] = "empty"
        return key, {**row, "items": kept}, selected

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(read, RESOURCES.items()))
    resources = {key: row for key, row, _ in results}
    # The findings scan below reads the full selected lists, not the retained
    # items, so a taint or cordon beyond the retention limit still reports.
    scanned = {key: selected for key, _, selected in results}
    findings = []
    for key, row in resources.items():
        if row["complete"]:
            continue
        if row["status"] == "collected":
            message = f"The {row['resource']} inventory is truncated at the retention limit."
        else:
            message = f"The {row['resource']} inventory is incomplete ({row['status']})."
        findings.append({"key": f"resources.{key}", "message": message})
    taints, cordoned = {}, []
    for node in scanned["nodes"]:
        spec, name = node["spec"], node["metadata"]["name"]
        for taint in spec.get("taints", []):
            label = f"{taint['key']}={taint.get('value', '')}:{taint['effect']}"
            taints.setdefault(label, []).append(name)
        if spec.get("unschedulable"):
            cordoned.append(name)
    for label, names in sorted(taints.items()):
        findings.append(
            {
                "key": "resources.nodes",
                "message": group_message(
                    names, f"has taint {label}", f"have taint {label}"
                ),
            }
        )
    if cordoned:
        findings.append(
            {
                "key": "resources.nodes",
                "message": group_message(cordoned, "is cordoned", "are cordoned"),
            }
        )
    if not scanned["nodes"]:
        findings.append(
            {
                "key": "resources.nodes",
                "message": "The audit could not inventory any visible node.",
            }
        )
    for key, kind in (("localQueues", "LocalQueue"), ("clusterQueues", "ClusterQueue")):
        for queue in scanned[key]:
            spec, name = queue.get("spec", {}), queue["metadata"]["name"]
            if spec.get("stopPolicy", "None") != "None":
                findings.append(
                    {
                        "key": f"resources.{key}",
                        "message": f"{kind} {name} has stopPolicy={spec['stopPolicy']}.",
                    }
                )
            for group in spec.get("resourceGroups", []):
                for flavor in group.get("flavors", []):
                    for r in flavor.get("resources", []):
                        if zero_quantity(r.get("nominalQuota")):
                            findings.append(
                                {
                                    "key": f"resources.{key}",
                                    "message": f"{kind} {name}, flavor {flavor['name']}, has zero nominal quota for {r['name']}. Cohort borrowing can still permit admission.",
                                }
                            )
    configs = []
    references = sorted(
        {
            (c["metadata"]["namespace"], name)
            for c in scanned["controllers"]
            for name in c["configMaps"]
        }
    )
    for ns, name in references[:16]:
        row = read_resource("configmaps", ns, name)
        parsed = {}
        size = 0
        for item in row.pop("items"):
            for key, value in item.get("data", {}).items():
                if not key.endswith((".yaml", ".yml")):
                    continue
                try:
                    size += len(value.encode())
                    if size > MAX_BYTES:
                        raise ValueError(
                            "The configuration exceeds the retention limit"
                        )
                    config = yaml.safe_load(value)
                    if (
                        isinstance(config, dict)
                        and str(config.get("apiVersion", "")).partition("/")[0]
                        == f"config.{GROUP}"
                    ):
                        parsed[key] = redact(config)
                except (ValueError, yaml.YAMLError):
                    row.update(status="error", complete=False)
        if row["status"] == "collected" and not parsed and row["complete"]:
            row["status"] = "empty"
        if not row["complete"] or row["status"] == "absent":
            findings.append(
                {
                    "key": "controllerConfigs",
                    "message": f"The controller ConfigMap {ns}/{name} read is {row['status']}.",
                }
            )
        configs.append({**row, "name": name, "configuration": parsed})
    if len(references) > 16:
        findings.append(
            {
                "key": "controllerConfigs",
                "message": "The controller ConfigMap retention limit was reached.",
            }
        )
    return {
        "namespace": namespace,
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "resources": resources,
        "controllerConfigs": configs,
        "findings": findings,
        "status": "warning" if findings else "pass",
        "message": f"The scheduling inventory has {len(findings)} finding(s).",
    }


if __name__ == "__main__" and os.environ.get("CLUSTERMAX_AUDIT_HARNESS") == "k8s":
    namespace = os.environ.get("CLUSTERMAX_AUDIT_TENANT_NAMESPACE", "default")
    print(json.dumps({"k8s_scheduling": collect(namespace)}, indent=2))
