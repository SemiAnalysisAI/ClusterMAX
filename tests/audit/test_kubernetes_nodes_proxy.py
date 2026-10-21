#!/usr/bin/env python3
"""Behavior tests for the Kubernetes nodes/proxy RBAC check."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cmax import audit_report, audit_runner, runtime_paths, security


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "cmax/scripts/1-audit/checks/system/kubernetes_nodes_proxy.py"
SPEC = importlib.util.spec_from_file_location("kubernetes_nodes_proxy", CHECK)
assert SPEC and SPEC.loader
nodes_proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nodes_proxy)


def role(name: str, rules: list[dict[str, object]] | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": name},
    }
    if rules is not None:
        value["rules"] = rules
    return value


def binding(
    name: str, role_name: str, subjects: list[dict[str, str]] | None = None
) -> dict[str, object]:
    value: dict[str, object] = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role_name,
        },
    }
    if subjects is not None:
        value["subjects"] = subjects
    return value


def inventory(*items: dict[str, object], metadata: object = None) -> dict[str, object]:
    value: dict[str, object] = {"items": list(items)}
    if metadata is not None:
        value["metadata"] = metadata
    return value


class KubernetesNodesProxyTests(unittest.TestCase):
    def test_exact_and_wildcard_rules_report_bound_subjects_and_names(self) -> None:
        rules = [
            {
                "apiGroups": [""],
                "resources": ["nodes/proxy"],
                "verbs": ["get"],
                "resourceNames": ["gpu-1"],
            },
            {"apiGroups": ["*"], "resources": ["*/proxy"], "verbs": ["*"]},
        ]
        result = nodes_proxy.evaluate_inventory(
            inventory(role("proxy-reader", rules)),
            inventory(
                binding(
                    "read-proxy",
                    "proxy-reader",
                    [
                        {"kind": "User", "name": "alice"},
                        {"kind": "Group", "name": "operators"},
                        {
                            "kind": "ServiceAccount",
                            "name": "agent",
                            "namespace": "ops",
                        },
                    ],
                )
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["grants"]), 6)
        self.assertEqual(result["grants"][0]["resourceNames"], ["gpu-1"])
        self.assertEqual(
            result["grants"][-1]["subject"],
            {"kind": "ServiceAccount", "name": "agent", "namespace": "ops"},
        )

    def test_nodes_child_wildcard_and_unbound_role_do_not_grant_proxy(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(
                role(
                    "wrong-resource",
                    [{"apiGroups": [""], "resources": ["nodes/*"], "verbs": ["get"]}],
                ),
                role(
                    "unbound",
                    [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}],
                ),
            ),
            inventory(binding("wrong", "wrong-resource", [{"kind": "User", "name": "bob"}])),
        )

        self.assertEqual(result, {"status": "pass", "message": "The complete Kubernetes RBAC inventory contains no nodes/proxy GET grants.", "grants": [], "errors": []})

    def test_materialized_aggregate_rules_are_evaluated_without_label_inference(self) -> None:
        aggregate = role(
            "aggregate",
            [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}],
        )
        aggregate["aggregationRule"] = {
            "clusterRoleSelectors": [{"matchLabels": {"monitoring": "true"}}]
        }
        result = nodes_proxy.evaluate_inventory(
            inventory(aggregate),
            inventory(binding("aggregate-binding", "aggregate", [{"kind": "Group", "name": "admins"}])),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["grants"][0]["subject"], {"kind": "Group", "name": "admins"})

    def test_other_api_groups_resources_and_verbs_do_not_grant_proxy_get(self) -> None:
        rules = (
            {"apiGroups": ["apps"], "resources": ["nodes/proxy"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["list", "watch"]},
        )
        for rule in rules:
            with self.subTest(rule=rule):
                result = nodes_proxy.evaluate_inventory(
                    inventory(role("reader", [rule])),
                    inventory(binding("reader", "reader", [{"kind": "User", "name": "alice"}])),
                )
                self.assertEqual(result["status"], "pass")
                self.assertEqual(result["grants"], [])
                self.assertEqual(result["errors"], [])

    def test_optional_empty_and_non_resource_rules_are_valid(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(
                role("empty"),
                role("non-resource", [{"nonResourceURLs": ["/healthz"], "verbs": ["get"]}]),
            ),
            inventory(binding("empty-binding", "empty"), binding("url-binding", "non-resource")),
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["errors"], [])

    def test_null_resource_names_means_all_node_names(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(
                role(
                    "reader",
                    [
                        {
                            "apiGroups": [""],
                            "resources": ["nodes/proxy"],
                            "verbs": ["get"],
                            "resourceNames": None,
                        }
                    ],
                )
            ),
            inventory(
                binding("reader-binding", "reader", [{"kind": "User", "name": "alice"}])
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["grants"][0]["resourceNames"], [])

    def test_partial_or_malformed_inventory_cannot_pass(self) -> None:
        for roles in (
            inventory(metadata={"continue": "next"}),
            inventory(metadata={"remainingItemCount": 2}),
            inventory(role("bad", [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"], "resourceNames": False}])),
            inventory(role("empty-rule", [{}])),
        ):
            with self.subTest(roles=roles):
                result = nodes_proxy.evaluate_inventory(roles, inventory())
                self.assertEqual(result["status"], "unknown")
                self.assertTrue(result["errors"])

    def test_empty_subject_identity_cannot_produce_a_clean_result(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(role("empty")),
            inventory(binding("binding", "empty", [{"kind": "User", "name": ""}])),
        )

        self.assertEqual(result["status"], "unknown")
        self.assertIn("subject 0 is malformed", result["errors"][0])

    def test_known_grant_wins_over_missing_role_and_other_errors(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(
                role("good", [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}]),
                {"kind": "wrong"},
            ),
            inventory(
                binding("good-binding", "good", [{"kind": "User", "name": "alice"}]),
                binding("missing-binding", "missing", [{"kind": "User", "name": "bob"}]),
            ),
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["grants"]), 1)
        self.assertGreaterEqual(len(result["errors"]), 2)

    def test_executable_uses_qualified_resources_and_reports_a_grant(self) -> None:
        roles = inventory(role("reader", [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}]))
        bindings = inventory(binding("reader-binding", "reader", [{"kind": "User", "name": "alice"}]))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            kubectl = directory / "kubectl"
            kubectl.write_text(
                "#!/bin/sh\n"
                "case \"$2\" in\n"
                f"  clusterroles.rbac.authorization.k8s.io) printf '%s' '{json.dumps(roles)}' ;;\n"
                f"  clusterrolebindings.rbac.authorization.k8s.io) printf '%s' '{json.dumps(bindings)}' ;;\n"
                "  *) exit 9 ;;\n"
                "esac\n"
            )
            kubectl.chmod(0o755)
            process = subprocess.run(
                [str(CHECK)],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{directory}:{os.environ.get('PATH', '')}",
                    "CLUSTERMAX_AUDIT_HARNESS": "k8s",
                },
            )

            check_root = directory / "checks"
            (check_root / "system").mkdir(parents=True)
            (check_root / "system" / CHECK.name).symlink_to(CHECK)
            audit_scripts = ROOT / "cmax/scripts/1-audit"
            collected = directory / "check-data.json"
            run_checks = subprocess.run(
                [
                    sys.executable, str(audit_scripts / "run_checks.py"),
                    str(check_root), str(collected), "k8s", "security",
                ],
                capture_output=True,
                text=True,
                env={**os.environ, "PATH": f"{directory}:{os.environ.get('PATH', '')}"},
                timeout=30,
            )
            self.assertEqual(run_checks.returncode, 0, run_checks.stderr)
            self.assertIn("kubernetes_nodes_proxy: FAIL", run_checks.stdout)

            raw = directory / "raw.json"
            raw.write_text(json.dumps({"security": {"existing": "preserved"}}))
            saved = directory / "audit.values.json"
            merge = subprocess.run(
                [
                    sys.executable, str(audit_scripts / "merge_audit.py"),
                    str(raw), str(saved), "test", "k8s", str(collected),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(merge.returncode, 0, merge.stderr)
            self.assertEqual(
                json.loads(saved.read_text())["audit_data"]["security"],
                {"existing": "preserved"},
            )
            review = subprocess.run(
                [
                    sys.executable, "-m", "cmax.cli", "audit", "review", str(saved),
                    "--command", "show kubernetes-nodes-proxy", "--no-interactive",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(review.returncode, 0, review.stderr)
            self.assertIn("status: fail", review.stdout)
            self.assertIn("User alice through reader-binding and reader", review.stdout)

        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)["kubernetes_nodes_proxy"]
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["grants"][0]["subject"]["name"], "alice")

    def test_non_kubernetes_invocation_is_not_applicable(self) -> None:
        original = os.environ.get("CLUSTERMAX_AUDIT_HARNESS")
        os.environ["CLUSTERMAX_AUDIT_HARNESS"] = "slurm"
        try:
            result = nodes_proxy.collect()["kubernetes_nodes_proxy"]
        finally:
            if original is None:
                os.environ.pop("CLUSTERMAX_AUDIT_HARNESS", None)
            else:
                os.environ["CLUSTERMAX_AUDIT_HARNESS"] = original
        self.assertEqual(result["status"], "not_applicable")

    def test_transport_failures_return_errors_instead_of_empty_inventory(self) -> None:
        outcomes = (
            subprocess.TimeoutExpired(["kubectl"], 20),
            subprocess.CompletedProcess(["kubectl"], 1, "", "Forbidden"),
            subprocess.CompletedProcess(["kubectl"], 0, "not-json", ""),
        )
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__), mock.patch.object(
                nodes_proxy.subprocess, "run", side_effect=outcome
                if isinstance(outcome, BaseException)
                else None,
                return_value=None if isinstance(outcome, BaseException) else outcome,
            ):
                payload, error = nodes_proxy._get(
                    "clusterroles.rbac.authorization.k8s.io"
                )
                self.assertIsNone(payload)
                self.assertTrue(error)

    def test_collection_failure_is_unknown(self) -> None:
        with mock.patch.dict(
            os.environ, {"CLUSTERMAX_AUDIT_HARNESS": "k8s"}
        ), mock.patch.object(
            nodes_proxy,
            "_get",
            side_effect=[(None, "roles denied"), (None, "bindings denied")],
        ):
            result = nodes_proxy.collect()["kubernetes_nodes_proxy"]

        self.assertEqual(result["status"], "unknown")
        self.assertIn("roles denied", result["errors"])

    def test_security_failure_matches_full_report_and_returns_exit_two(self) -> None:
        result = nodes_proxy.evaluate_inventory(
            inventory(role("reader", [{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}])),
            inventory(binding("reader-binding", "reader", [{"kind": "Group", "name": "operators"}])),
        )
        values = {
            "cluster": {"orchestrator": "k8s"},
            "audit_data": {"kubernetes_nodes_proxy": result},
        }
        runtime = runtime_paths.package_runtime_root()
        checks = []
        for category in (None, "security", "isolation"):
            checks.append(next(
                check for check in audit_report.evaluate(values, runtime, category=category)
                if check.key == "kubernetes-nodes-proxy"
            ))
        self.assertEqual([check.status for check in checks], ["fail", "fail", "fail"])
        self.assertEqual(checks[0], checks[1])
        self.assertEqual(checks[1], checks[2])
        for harness in ("slurm", "standalone"):
            check = next(
                check for check in audit_report.evaluate(values, runtime, harness=harness)
                if check.key == "kubernetes-nodes-proxy"
            )
            self.assertEqual(check.status, "skipped")

        def finish_collection(*args, **kwargs):
            audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
            (audit_dir / "audit.values.json").write_text(json.dumps(values))
            return 0, ""

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            audit_runner, "_audit_dir", return_value=Path(tmp) / "audit"
        ), mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_collection
        ):
            code = audit_runner.run(
                category="security",
                resolved_target=security.SecurityTarget("k8s", "k8s", True),
                exit_on_fail=True,
            )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
