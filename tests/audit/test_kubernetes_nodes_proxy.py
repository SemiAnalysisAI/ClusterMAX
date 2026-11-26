#!/usr/bin/env python3
"""Behavior tests for the Kubernetes nodes/proxy RBAC inventory."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "checks"
    / "system"
    / "kubernetes_nodes_proxy.py"
)


def role(
    name: str,
    rules: list[dict[str, object]] | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {"name": name}
    if labels is not None:
        metadata["labels"] = labels
    value: dict[str, object] = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": metadata,
    }
    if rules is not None:
        value["rules"] = rules
    return value


def binding(
    name: str,
    role_name: str,
    subjects: list[dict[str, str]] | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {"name": name}
    if labels is not None:
        metadata["labels"] = labels
    value: dict[str, object] = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": metadata,
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role_name,
        },
    }
    if subjects is not None:
        value["subjects"] = subjects
    return value


def inventory(*items: dict[str, object]) -> dict[str, object]:
    return {"items": list(items)}


def run_collector(roles: dict[str, object], bindings: dict[str, object]) -> dict[str, object]:
    """Run the real check with a kubectl stub that returns the fixtures."""
    kubectl_body = (
        "#!/bin/sh\n"
        'case "$2" in\n'
        f"  clusterroles*) printf '%s' {json.dumps(roles)!r} ;;\n"
        f"  clusterrolebindings*) printf '%s' {json.dumps(bindings)!r} ;;\n"
        "  *) exit 9 ;;\n"
        "esac\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        kubectl = directory / "kubectl"
        kubectl.write_text(kubectl_body)
        kubectl.chmod(0o755)
        process = subprocess.run(
            [sys.executable, str(CHECK)],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PATH": f"{directory}:{os.environ.get('PATH', '')}",
                "CLUSTERMAX_AUDIT_HARNESS": "k8s",
            },
            timeout=30,
        )
    if process.returncode != 0:
        raise AssertionError(process.stderr)
    return json.loads(process.stdout)["kubernetes_nodes_proxy"]


class KubernetesNodesProxyTests(unittest.TestCase):
    def test_matching_binding_is_reported_with_its_resource_names(self) -> None:
        result = run_collector(
            inventory(
                role(
                    "proxy-reader",
                    [
                        {
                            "apiGroups": [""],
                            "resources": ["nodes/proxy"],
                            "verbs": ["get"],
                            "resourceNames": ["gpu-1"],
                        }
                    ],
                ),
                role(
                    "node-reader",
                    [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}],
                ),
            ),
            inventory(
                binding(
                    "metadata-collector",
                    "proxy-reader",
                    [
                        {
                            "kind": "ServiceAccount",
                            "namespace": "nvsentinel",
                            "name": "metadata-collector",
                        }
                    ],
                ),
                binding(
                    "node-reader-binding",
                    "node-reader",
                    [{"kind": "User", "name": "bob"}],
                ),
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            result["grants"],
            [
                {
                    "role": "proxy-reader",
                    "binding": "metadata-collector",
                    "subject": {
                        "kind": "ServiceAccount",
                        "namespace": "nvsentinel",
                        "name": "metadata-collector",
                    },
                    "resourceNames": ["gpu-1"],
                }
            ],
        )

    def test_custom_binding_to_a_stock_role_is_reported(self) -> None:
        result = run_collector(
            inventory(
                role(
                    "cluster-admin",
                    [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                    labels={"kubernetes.io/bootstrapping": "rbac-defaults"},
                ),
                role(
                    "support",
                    [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]}],
                ),
            ),
            inventory(
                binding(
                    "cluster-admin",
                    "cluster-admin",
                    [{"kind": "Group", "name": "system:masters"}],
                    labels={"kubernetes.io/bootstrapping": "rbac-defaults"},
                ),
                binding(
                    "tenant-cluster-admin",
                    "cluster-admin",
                    [{"kind": "User", "name": "alice"}],
                ),
                binding(
                    "support-binding",
                    "support",
                    [{"kind": "Group", "name": "provider:support"}],
                ),
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(
            result["grants"],
            [
                {
                    "role": "support",
                    "binding": "support-binding",
                    "subject": {
                        "kind": "Group",
                        "namespace": "",
                        "name": "provider:support",
                    },
                    "resourceNames": [],
                },
                {
                    "role": "cluster-admin",
                    "binding": "tenant-cluster-admin",
                    "subject": {
                        "kind": "User",
                        "namespace": "",
                        "name": "alice",
                    },
                    "resourceNames": [],
                },
            ],
        )

    def test_star_proxy_subresource_is_a_nodes_proxy_grant(self) -> None:
        result = run_collector(
            inventory(
                role(
                    "proxy-subresource",
                    [{"apiGroups": [""], "resources": ["*/proxy"], "verbs": ["get"]}],
                )
            ),
            inventory(
                binding(
                    "tenant-proxy",
                    "proxy-subresource",
                    [{"kind": "User", "name": "alice"}],
                )
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            result["grants"],
            [
                {
                    "role": "proxy-subresource",
                    "binding": "tenant-proxy",
                    "subject": {"kind": "User", "namespace": "", "name": "alice"},
                    "resourceNames": [],
                }
            ],
        )

    def test_unreadable_rbac_reports_errors_and_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            kubectl = directory / "kubectl"
            kubectl.write_text(
                "#!/bin/sh\necho 'Error from server (Forbidden): forbidden' >&2\nexit 1\n"
            )
            kubectl.chmod(0o755)
            process = subprocess.run(
                [sys.executable, str(CHECK)],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{directory}:{os.environ.get('PATH', '')}",
                    "CLUSTERMAX_AUDIT_HARNESS": "k8s",
                },
                timeout=30,
            )

        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)["kubernetes_nodes_proxy"]
        self.assertNotEqual(result["status"], "pass")
        self.assertEqual(result["grants"], [])
        self.assertTrue(
            any(
                "clusterroles" in error and "Forbidden" in error
                for error in result["errors"]
            ),
            result["errors"],
        )
        self.assertTrue(
            any(
                "clusterrolebindings" in error and "Forbidden" in error
                for error in result["errors"]
            ),
            result["errors"],
        )


if __name__ == "__main__":
    unittest.main()
