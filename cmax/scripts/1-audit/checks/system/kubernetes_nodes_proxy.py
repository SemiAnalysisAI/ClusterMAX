#!/usr/bin/env python3
"""Inventory the ClusterRoleBindings that grant GET on the core nodes/proxy resource.

HTTP GET on `nodes/proxy` reaches the kubelet API through the API server. The
Kubernetes RBAC authorizer accepts a request when a rule names `nodes/proxy`,
`*`, or `*/proxy`, lists the `get` verb (or `*`), and applies to the core API
group (`""` or `*`). `*/proxy` covers the proxy subresource of every resource
in that group, including nodes. `nodes/*` does not match.

Kubernetes ships many ClusterRoles and ClusterRoleBindings labeled
`kubernetes.io/bootstrapping=rbac-defaults`. Those bindings are the stock
control plane grants, so the inventory skips a binding that carries the label.
The `cluster-admin` binding for `system:masters` is one of them. A custom
binding does not carry the label. The inventory reports that binding even when
the role itself is a stock role, because a tenant bound to `cluster-admin` can
reach the kubelet. Skipping the role would hide that grant.

The check reports each grant as the binding, the role, the subject, and the
`resourceNames` scope of the matching rule. An empty `resourceNames` list means
every node. The evaluator in `cmax/security.py` reads this object from the
top-level `kubernetes_nodes_proxy` key of `audit.values.json`.

The inventory fails closed. When `kubectl` cannot read ClusterRoles or
ClusterRoleBindings, it records the reason under `errors` instead of reporting
an empty grant list, because an empty grant list is a pass.

This check runs only on the Kubernetes harness. It uses the selected kubectl
context and it changes no cluster state.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

REQUEST_TIMEOUT = "30s"
COMMAND_TIMEOUT_S = 45
CORE_GROUPS = {"", "*"}
MATCHING_VERBS = {"get", "*"}
SUBJECT_KINDS = {"User", "Group", "ServiceAccount"}
BOOTSTRAP_LABEL = "kubernetes.io/bootstrapping"
BOOTSTRAP_LABEL_VALUE = "rbac-defaults"


def is_bootstrap_binding(binding: dict[str, Any]) -> bool:
    """Return True for a stock Kubernetes bootstrap ClusterRoleBinding."""
    labels = binding["metadata"].get("labels")
    return isinstance(labels, dict) and labels.get(BOOTSTRAP_LABEL) == BOOTSTRAP_LABEL_VALUE


def read_kubectl(resource: str) -> list[dict[str, Any]]:
    """Return the items of one cluster-scoped kubectl read."""
    proc = subprocess.run(
        ["kubectl", "get", resource, "-o", "json", f"--request-timeout={REQUEST_TIMEOUT}"],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_S,
        check=False,
    )
    if proc.returncode:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        detail = lines[0] if lines else "no detail"
        raise RuntimeError(f"kubectl get {resource} failed with exit {proc.returncode}: {detail}")
    data = json.loads(proc.stdout)
    items = data.get("items")
    if not isinstance(items, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("metadata"), dict)
        or not item["metadata"].get("name")
        for item in items
    ):
        raise ValueError(f"kubectl get {resource} returned an invalid item list")
    return items


def resource_covers_nodes_proxy(resource: object) -> bool:
    """Return True when one RBAC resource entry covers nodes/proxy.

    Kubernetes matches `*`, the exact name `nodes/proxy`, and `*/proxy`.
    `*/proxy` covers the proxy subresource of every resource. `nodes/*` does not.
    """
    return resource == "*" or resource == "nodes/proxy" or resource == "*/proxy"


def matching_resource_names(rule: dict[str, Any]) -> list[str] | None:
    """Return the rule's node scope when the rule grants GET on nodes/proxy.

    `None` means the rule does not match. An empty list means every node.
    """
    api_groups = rule.get("apiGroups")
    verbs = rule.get("verbs")
    resources = rule.get("resources")
    if (
        not isinstance(api_groups, list)
        or not any(group in CORE_GROUPS for group in api_groups)
        or not isinstance(verbs, list)
        or not any(verb in MATCHING_VERBS for verb in verbs)
        or not isinstance(resources, list)
        or not any(resource_covers_nodes_proxy(resource) for resource in resources)
    ):
        return None
    names = rule.get("resourceNames")
    if not isinstance(names, list):
        return []
    return [name for name in names if isinstance(name, str)]


def role_grants(role: dict[str, Any]) -> list[list[str]]:
    rules = role.get("rules")
    if not isinstance(rules, list):
        return []
    matches = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        names = matching_resource_names(rule)
        if names is not None:
            matches.append(names)
    return matches


def collect() -> dict[str, Any]:
    errors: list[str] = []
    roles: dict[str, dict[str, Any]] = {}
    roles_ok = True
    try:
        for role in read_kubectl("clusterroles"):
            roles[role["metadata"]["name"]] = role
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        errors.append(f"The ClusterRole inventory is incomplete: {exc}")
        roles_ok = False

    grants: list[dict[str, Any]] = []
    try:
        bindings = read_kubectl("clusterrolebindings")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        errors.append(f"The ClusterRoleBinding inventory is incomplete: {exc}")
        bindings = []
    if not roles_ok:
        # Every binding would report a missing role, so one error is enough.
        bindings = []

    for binding in bindings:
        if is_bootstrap_binding(binding):
            continue
        role_ref = binding.get("roleRef")
        if not isinstance(role_ref, dict) or role_ref.get("kind") != "ClusterRole":
            continue
        role_name = role_ref.get("name")
        if not isinstance(role_name, str) or not role_name:
            continue
        role = roles.get(role_name)
        if role is None:
            errors.append(f"ClusterRole {role_name} is missing for its binding.")
            continue
        matches = role_grants(role)
        if not matches:
            continue
        subjects = binding.get("subjects")
        if not isinstance(subjects, list):
            continue
        binding_name = binding["metadata"]["name"]
        for subject in subjects:
            if not isinstance(subject, dict):
                continue
            kind = subject.get("kind")
            name = subject.get("name")
            namespace = subject.get("namespace")
            if kind not in SUBJECT_KINDS or not isinstance(name, str) or not name:
                continue
            if kind == "ServiceAccount" and (
                not isinstance(namespace, str) or not namespace
            ):
                continue
            resource_names: set[str] = set()
            unrestricted = False
            for names in matches:
                if not names:
                    unrestricted = True
                    break
                resource_names.update(names)
            grants.append(
                {
                    "role": role_name,
                    "binding": binding_name,
                    "subject": {
                        "kind": kind,
                        "namespace": namespace if isinstance(namespace, str) else "",
                        "name": name,
                    },
                    "resourceNames": []
                    if unrestricted
                    else sorted(resource_names),
                }
            )

    grants.sort(
        key=lambda grant: (
            grant["binding"],
            grant["role"],
            grant["subject"]["kind"],
            grant["subject"]["namespace"],
            grant["subject"]["name"],
        )
    )
    status = "fail" if grants or errors else "pass"
    if grants:
        message = (
            f"{len(grants)} ClusterRoleBinding grant(s) allow GET on the core "
            "nodes/proxy resource."
        )
    elif errors:
        message = "The nodes/proxy RBAC inventory could not complete."
    else:
        message = "No ClusterRoleBinding grants GET on the core nodes/proxy resource."
    return {
        "kubernetes_nodes_proxy": {
            "status": status,
            "grants": grants,
            "errors": errors,
            "message": message,
        }
    }


if __name__ == "__main__" and os.environ.get("CLUSTERMAX_AUDIT_HARNESS") == "k8s":
    print(json.dumps(collect(), indent=2, sort_keys=True))
