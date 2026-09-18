"""Behavioral tests for the k8s collector's RBAC probe.

Executes the real add_kubectl_auth_check from cluster-audit-k8s.sh against a
stub kubectl, one permission answer per case, and asserts the JSON entry it
appends is parseable.

Guarded incident: `kubectl auth can-i` reports a denial twice, once on stdout
and once through exit status 1, so `|| echo "no"` appended a second line
instead of supplying a missing one. The two-line value was spliced into a JSON
string literal, where a bare newline is illegal, and jq rejected the whole
document. The audit aborted at check 4 of 41 and produced no report. Only an
identity that cannot create pods reaches this path, so read-only audits
crashed while admin runs stayed green.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
SCRIPT = WORKLOAD / "cluster-audit-k8s.sh"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

# print_* are shell functions in the full collector; stub them as executables
# so the extracted function runs standalone.
FUNCTION_STUBS = {"print_info": "", "print_warn": ""}

DENIED = 'echo "no"\nexit 1'
ALLOWED = 'echo "yes"\nexit 0'


def run_check(kubectl: str, *args: str) -> bashtest.BashRun:
    """Call the real probe once and emit the entry it appended."""
    snippet = "\n".join(
        [
            "KUBECTL_AUTH_JSON_ENTRIES=()",
            'KUBECTL_RBAC_SUMMARY="pass"',
            bashtest.extract_function(SCRIPT, "add_kubectl_auth_check"),
            "add_kubectl_auth_check " + " ".join(args),
            'printf "%s" "${KUBECTL_AUTH_JSON_ENTRIES[0]}"',
        ]
    )
    return bashtest.run_bash(snippet, stubs={"kubectl": kubectl, **FUNCTION_STUBS})


@pytest.mark.parametrize(
    "args",
    [
        ("createPods", "create", "pods", "--all-namespaces"),
        ("listNodes", "list", "nodes"),
    ],
    ids=["scoped", "cluster-wide"],
)
def test_a_denial_still_yields_parseable_json(args):
    """Both call sites must survive the answer that arrives twice."""
    run = run_check(DENIED, *args)
    assert run.returncode == 0
    entry = json.loads(run.stdout)  # a bare newline here would abort the audit
    assert entry["result"] == "no"
    assert entry["allowed"] is False


def test_a_grant_is_recorded_as_allowed():
    run = run_check(ALLOWED, "createPods", "create", "pods", "--all-namespaces")
    entry = json.loads(run.stdout)
    assert entry["result"] == "yes"
    assert entry["allowed"] is True


def test_the_probe_asks_kubectl_exactly_what_it_was_given():
    run = run_check(DENIED, "createPods", "create", "pods", "--all-namespaces")
    assert run.calls("kubectl") == [
        ["auth", "can-i", "create", "pods", "--all-namespaces"]
    ]
