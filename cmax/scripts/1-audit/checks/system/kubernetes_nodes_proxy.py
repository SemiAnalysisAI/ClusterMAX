#!/usr/bin/env python3
"""Report Kubernetes RBAC grants for GET requests to nodes/proxy."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


REQUEST_TIMEOUT = "15s"
PROCESS_TIMEOUT = 20


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return value


def _list_items(payload: Any, kind: str, errors: list[str]) -> list[Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        errors.append(f"{kind} inventory is not a Kubernetes list")
        return []
    metadata = payload.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append(f"{kind} list metadata is malformed")
    elif isinstance(metadata, dict):
        if metadata.get("continue") not in (None, ""):
            errors.append(f"{kind} inventory is partial (continue token present)")
        if metadata.get("remainingItemCount") not in (None, 0):
            errors.append(f"{kind} inventory is partial (remaining items present)")
    return payload["items"]


def _object_name(item: Any, kind: str, errors: list[str]) -> str | None:
    if not isinstance(item, dict) or item.get("kind") != kind:
        errors.append(f"{kind} inventory contains a malformed object")
        return None
    metadata = item.get("metadata")
    if (
        not isinstance(metadata, dict)
        or not isinstance(metadata.get("name"), str)
        or not metadata["name"]
    ):
        errors.append(f"{kind} inventory contains an object without a valid name")
        return None
    return metadata["name"]


def _matching_scopes(role: dict[str, Any], role_name: str, errors: list[str]) -> list[list[str]]:
    rules = role.get("rules")
    if rules is None:
        return []
    if not isinstance(rules, list):
        errors.append(f"ClusterRole {role_name} has malformed rules")
        return []

    scopes: list[list[str]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"ClusterRole {role_name} rule {index} is malformed")
            continue
        api_groups_value = rule.get("apiGroups")
        resources_value = rule.get("resources")
        verbs_value = rule.get("verbs")
        if "nonResourceURLs" in rule and api_groups_value is None and resources_value is None:
            urls = _string_list(rule.get("nonResourceURLs"))
            verbs = _string_list(verbs_value)
            if urls is None or verbs is None:
                errors.append(f"ClusterRole {role_name} rule {index} is malformed")
            continue
        if api_groups_value is None and resources_value is None and verbs_value is None:
            errors.append(f"ClusterRole {role_name} rule {index} is malformed")
            continue
        api_groups = _string_list(api_groups_value)
        resources = _string_list(resources_value)
        verbs = _string_list(verbs_value)
        if api_groups is None or resources is None or verbs is None:
            errors.append(f"ClusterRole {role_name} rule {index} is malformed")
            continue
        names_value = rule.get("resourceNames")
        if names_value is None:
            names_value = []
        resource_names = _string_list(names_value)
        if resource_names is None:
            errors.append(
                f"ClusterRole {role_name} rule {index} has malformed resourceNames"
            )
            continue
        if (
            any(value in {"", "*"} for value in api_groups)
            and any(value in {"get", "*"} for value in verbs)
            and any(value in {"nodes/proxy", "*/proxy", "*"} for value in resources)
        ):
            scopes.append(resource_names)
    return scopes


def evaluate_inventory(roles_payload: Any, bindings_payload: Any) -> dict[str, Any]:
    errors: list[str] = []
    role_scopes: dict[str, list[list[str]]] = {}
    role_names: set[str] = set()
    for item in _list_items(roles_payload, "ClusterRole", errors):
        name = _object_name(item, "ClusterRole", errors)
        if name is None:
            continue
        role_names.add(name)
        scopes = _matching_scopes(item, name, errors)
        if scopes:
            role_scopes[name] = scopes

    grants: list[dict[str, Any]] = []
    for item in _list_items(bindings_payload, "ClusterRoleBinding", errors):
        binding_name = _object_name(item, "ClusterRoleBinding", errors)
        if binding_name is None:
            continue
        role_ref = item.get("roleRef")
        if (
            not isinstance(role_ref, dict)
            or role_ref.get("apiGroup") != "rbac.authorization.k8s.io"
            or role_ref.get("kind") != "ClusterRole"
            or not isinstance(role_ref.get("name"), str)
            or not role_ref["name"]
        ):
            errors.append(f"ClusterRoleBinding {binding_name} has malformed roleRef")
            continue
        role_name = role_ref["name"]
        if role_name not in role_names:
            errors.append(
                f"ClusterRoleBinding {binding_name} references missing ClusterRole {role_name}"
            )
            continue
        subjects = item.get("subjects")
        if subjects is None:
            continue
        if not isinstance(subjects, list):
            errors.append(f"ClusterRoleBinding {binding_name} has malformed subjects")
            continue
        for index, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                errors.append(
                    f"ClusterRoleBinding {binding_name} subject {index} is malformed"
                )
                continue
            kind = subject.get("kind")
            name = subject.get("name")
            if (
                kind not in {"User", "Group", "ServiceAccount"}
                or not isinstance(name, str)
                or not name
            ):
                errors.append(
                    f"ClusterRoleBinding {binding_name} subject {index} is malformed"
                )
                continue
            evidence = {"kind": kind, "name": name}
            if kind == "ServiceAccount":
                namespace = subject.get("namespace")
                if not isinstance(namespace, str) or not namespace:
                    errors.append(
                        f"ClusterRoleBinding {binding_name} subject {index} is malformed"
                    )
                    continue
                evidence["namespace"] = namespace
            for resource_names in role_scopes.get(role_name, []):
                grants.append(
                    {
                        "role": role_name,
                        "binding": binding_name,
                        "subject": evidence.copy(),
                        "resourceNames": resource_names,
                    }
                )

    status = "fail" if grants else "unknown" if errors else "pass"
    if status == "fail":
        message = f"Found {len(grants)} Kubernetes RBAC nodes/proxy GET permission grant(s)."
    elif status == "unknown":
        message = "The Kubernetes RBAC inventory was incomplete or malformed."
    else:
        message = "The complete Kubernetes RBAC inventory contains no nodes/proxy GET grants."
    return {"status": status, "message": message, "grants": grants, "errors": errors}


def _get(resource: str) -> tuple[Any | None, str | None]:
    command = [
        "kubectl",
        "get",
        resource,
        "-o",
        "json",
        f"--request-timeout={REQUEST_TIMEOUT}",
    ]
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=PROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, f"kubectl get {resource} timed out"
    except OSError as exc:
        return None, f"kubectl get {resource} failed: {exc}"
    if process.returncode != 0:
        detail = process.stderr.strip() or f"exit {process.returncode}"
        return None, f"kubectl get {resource} failed: {detail}"
    try:
        return json.loads(process.stdout), None
    except json.JSONDecodeError:
        return None, f"kubectl get {resource} returned invalid JSON"


def collect() -> dict[str, Any]:
    if os.environ.get("CLUSTERMAX_AUDIT_HARNESS") != "k8s":
        return {
            "kubernetes_nodes_proxy": {
                "status": "not_applicable",
                "message": "This check applies only to Kubernetes audits.",
                "grants": [],
                "errors": [],
            }
        }
    roles, role_error = _get("clusterroles.rbac.authorization.k8s.io")
    bindings, binding_error = _get("clusterrolebindings.rbac.authorization.k8s.io")
    result = evaluate_inventory(roles, bindings)
    command_errors = [error for error in (role_error, binding_error) if error]
    result["errors"] = [*command_errors, *result["errors"]]
    if result["status"] == "unknown":
        result["message"] = "The Kubernetes RBAC inventory could not be completed."
    return {"kubernetes_nodes_proxy": result}


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
