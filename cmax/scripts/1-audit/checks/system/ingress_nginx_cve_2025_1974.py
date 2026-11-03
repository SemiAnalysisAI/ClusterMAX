#!/usr/bin/env python3
"""Read pod image metadata for ingress-nginx CVE-2025-1974. No active probes."""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any


CVE = "CVE-2025-1974"
ADVISORY = "https://github.com/kubernetes/kubernetes/issues/131009"
KEY = "ingress_nginx_cve_2025_1974"
UPSTREAM_IMAGES = {
    "registry.k8s.io/ingress-nginx/controller",
    "k8s.gcr.io/ingress-nginx/controller",
    "quay.io/kubernetes-ingress-controller/nginx-ingress-controller",
}


def image_verdict(image: str) -> tuple[str, str]:
    """Grade upstream release tags only, without claiming digest attestation."""
    reference = image.split("@", 1)[0]
    repository, separator, tag = reference.rpartition(":")
    if not separator or repository not in UPSTREAM_IMAGES:
        return "unknown", "unknown"
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    if not match:
        # Prereleases and vendor suffixes cannot establish a fixed release.
        return "unknown", "unknown"
    version = tuple(int(part) for part in match.groups())
    if version[0] > 1:
        return "unknown", tag
    affected = version < (1, 11, 5) or (1, 12, 0) <= version < (1, 12, 1)
    return ("fail" if affected else "pass"), tag


def _candidate(container: dict[str, Any]) -> bool:
    image = container.get("image", "")
    command = container.get("command", [])
    return (
        "ingress-nginx/controller" in image
        or "nginx-ingress-controller" in image
        or any(arg.rsplit("/", 1)[-1] == "nginx-ingress-controller" for arg in command)
    )


def evaluate_inventory(payload: Any) -> dict[str, Any]:
    errors: list[str] = []
    controllers: list[dict[str, str]] = []
    items: list[Any] = []
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        errors.append("Pod inventory is not a Kubernetes list.")
    else:
        items = payload["items"]
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            errors.append("Pod list metadata is malformed.")
        elif metadata.get("continue") not in (None, "") or metadata.get(
            "remainingItemCount"
        ) not in (None, 0):
            errors.append("Pod inventory is incomplete.")

    for pod in items:
        if not isinstance(pod, dict) or pod.get("kind") != "Pod":
            errors.append("Pod inventory contains a malformed object.")
            continue
        metadata = pod.get("metadata")
        spec = pod.get("spec")
        status = pod.get("status", {})
        if (
            not isinstance(metadata, dict)
            or not all(
                isinstance(metadata.get(key), str) and metadata[key]
                for key in ("name", "namespace")
            )
            or not isinstance(spec, dict)
            or not isinstance(spec.get("containers"), list)
            or not spec["containers"]
            or not isinstance(status, dict)
        ):
            errors.append("Pod identity, spec, or status is malformed.")
            continue
        if status.get("phase") in ("Succeeded", "Failed"):
            continue
        labels = metadata.get("labels", {})
        if not isinstance(labels, dict):
            errors.append("Pod labels are malformed.")
            labels = {}
        candidates = []
        for container in spec["containers"]:
            if (
                not isinstance(container, dict)
                or not isinstance(container.get("image"), str)
                or not container["image"]
                or not isinstance(container.get("name"), str)
                or not container["name"]
                or not isinstance(container.get("command", []), list)
                or any(
                    not isinstance(arg, str)
                    for arg in container.get("command", [])
                )
            ):
                errors.append("Pod container metadata is malformed.")
                continue
            if _candidate(container) or (
                labels.get("app.kubernetes.io/name") == "ingress-nginx"
                and labels.get("app.kubernetes.io/component") != "admission-webhook"
                and container["name"] in ("controller", "nginx-ingress-controller")
            ):
                candidates.append(container)
        if (
            not candidates
            and labels.get("app.kubernetes.io/name") == "ingress-nginx"
            and labels.get("app.kubernetes.io/component") != "admission-webhook"
        ):
            errors.append(
                f"{metadata['namespace']}/{metadata['name']}: "
                "ingress-nginx labels present but controller image is unresolved."
            )
        for container in candidates:
            verdict, version = image_verdict(container["image"])
            controllers.append(
                {
                    "namespace": metadata["namespace"],
                    "pod": metadata["name"],
                    "container": container["name"],
                    "image": container["image"],
                    "version": version,
                    "status": verdict,
                }
            )

    if any(item["status"] == "fail" for item in controllers):
        verdict = "fail"
        message = "An ingress-nginx pod declares an image version affected by CVE-2025-1974."
    elif errors or any(item["status"] == "unknown" for item in controllers):
        verdict = "unknown"
        message = "The ingress-nginx pod inventory or image version could not be verified."
    elif controllers:
        verdict = "pass"
        message = "The identified ingress-nginx pod image tags meet the CVE-2025-1974 fixed versions."
    else:
        verdict = "not_applicable"
        message = "No ingress-nginx controller was identified in the complete non-terminal pod inventory."
    return {
        "status": verdict,
        "message": message,
        "cve": CVE,
        "reference": ADVISORY,
        "inventoryComplete": not errors,
        "controllers": controllers,
        "errors": errors,
    }


def collect() -> dict[str, Any]:
    if os.environ.get("CLUSTERMAX_AUDIT_HARNESS") != "k8s":
        return {KEY: {"status": "not_applicable", "message": "Kubernetes audits only."}}
    command = [
        "kubectl", "get", "pods", "--all-namespaces", "-o", "json",
        "--request-timeout=15s",
    ]
    payload = None
    error = None
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=20)
        if process.returncode:
            # Do not copy API responses or local kubeconfig details into reports.
            error = f"Cluster-wide pod inventory failed (kubectl exit {process.returncode})."
        else:
            payload = json.loads(process.stdout)
    except subprocess.TimeoutExpired:
        error = "Cluster-wide pod inventory timed out."
    except OSError:
        error = "kubectl could not run."
    except json.JSONDecodeError:
        error = "kubectl returned invalid JSON."
    result = evaluate_inventory(payload)
    if error:
        result["errors"].insert(0, error)
    return {KEY: result}


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
