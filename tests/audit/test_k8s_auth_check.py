"""RBAC probe in the Kubernetes collector (add_kubectl_auth_check)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-k8s.sh"
)
AUTH_FUNCTION = bashtest.extract_function(SCRIPT, "add_kubectl_auth_check")

# kubectl auth can-i prints its answer on stdout and also exits 1 on a denial.
GRANT = 'echo yes'
DENY = 'echo no; exit 1'


def run_checks(kubectl: str, out: Path, *calls: str) -> bashtest.BashRun:
    return bashtest.run_bash(
        "set -euo pipefail\n"
        "print_info() { echo \"INFO $*\"; }\n"
        "print_warn() { echo \"WARN $*\"; }\n"
        "KUBECTL_AUTH_JSON_ENTRIES=()\n"
        "KUBECTL_RBAC_SUMMARY=pass\n"
        + AUTH_FUNCTION
        + "\n"
        + "\n".join(calls)
        + "\nprintf '%s\\n' \"${KUBECTL_AUTH_JSON_ENTRIES[@]}\" | jq -s . > \"$CMAX_AUTH_OUT\""
        "\necho \"SUMMARY=$KUBECTL_RBAC_SUMMARY\"\n",
        stubs={"kubectl": kubectl},
        env={"CMAX_AUTH_OUT": str(out)},
    )


def entries(tmp_path: Path, kubectl: str, *calls: str) -> tuple[list[dict], bashtest.BashRun]:
    out = tmp_path / "auth.json"
    run = run_checks(kubectl, out, *calls)
    assert run.returncode == 0, run.stderr
    return json.loads(out.read_text()), run


@pytest.mark.parametrize(
    "call",
    [
        "add_kubectl_auth_check createPods create pods --all-namespaces",
        "add_kubectl_auth_check listNodes list nodes",
    ],
)
def test_denial_is_one_valid_json_entry(tmp_path: Path, call: str) -> None:
    # A read-only identity used to get result="no\nno", which made jq reject
    # the whole document and stopped the audit before any report was written.
    parsed, run = entries(tmp_path, DENY, call)
    assert len(parsed) == 1
    assert parsed[0]["allowed"] is False
    assert parsed[0]["result"] == "no"
    assert "SUMMARY=fail" in run.stdout
    assert "\nno\n" not in run.stdout


def test_grant_and_denial_together(tmp_path: Path) -> None:
    kubectl = 'if [[ "$3" == list && "$4" == pods ]]; then echo yes; else echo no; exit 1; fi'
    parsed, run = entries(
        tmp_path,
        kubectl,
        "add_kubectl_auth_check listPods list pods --all-namespaces",
        "add_kubectl_auth_check createPods create pods --all-namespaces",
    )
    assert [(e["name"], e["allowed"], e["result"], e["scope"]) for e in parsed] == [
        ("listPods", True, "yes", "--all-namespaces"),
        ("createPods", False, "no", "--all-namespaces"),
    ]
    assert run.calls("kubectl") == [
        ["auth", "can-i", "list", "pods", "--all-namespaces"],
        ["auth", "can-i", "create", "pods", "--all-namespaces"],
    ]


def test_grant_has_cluster_scope_without_namespace_flag(tmp_path: Path) -> None:
    parsed, run = entries(tmp_path, GRANT, "add_kubectl_auth_check listNodes list nodes")
    assert parsed == [{
        "name": "listNodes", "verb": "list", "resource": "nodes",
        "scope": "cluster", "allowed": True, "result": "yes",
    }]
    assert run.calls("kubectl") == [["auth", "can-i", "list", "nodes"]]
    assert "SUMMARY=pass" in run.stdout


@pytest.mark.parametrize(
    "kubectl",
    [
        "exit 1",                                 # API error, no answer
        "printf 'no - RBAC: access denied\\n'; exit 1",  # authorizer reason
        "printf 'no\\r\\n'; exit 1",              # CRLF output
        "printf '\"quoted\\\\\\n'; exit 1",       # never spliced raw into JSON
    ],
)
def test_unusual_answers_stay_valid_json_and_denied(tmp_path: Path, kubectl: str) -> None:
    parsed, _ = entries(tmp_path, kubectl, "add_kubectl_auth_check createPods create pods --all-namespaces")
    assert len(parsed) == 1
    assert parsed[0]["allowed"] is False
    assert parsed[0]["result"] in {"no", "\"quoted\\"}
