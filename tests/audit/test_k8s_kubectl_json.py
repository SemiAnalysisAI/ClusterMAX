#!/usr/bin/env python3
"""Executable tests for Kubernetes JSON collection failures."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bashtest  # noqa: E402


COLLECTOR = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-k8s.sh"
)
KUBECTL_FUNCTION = bashtest.extract_function(COLLECTOR, "kubectl")
NODE_CACHE_BLOCK = bashtest.extract_block(
    COLLECTOR,
    "NODES_JSON=$(kubectl get nodes -o json 2>/dev/null)",
    "# SECTION 1: Kubernetes Version & Cluster Identity",
)
TOOLKIT_READY_FUNCTION = bashtest.extract_function(
    COLLECTOR, "k8s_toolkit_daemonset_ready"
)
TOOLKIT_IMAGE_FUNCTION = bashtest.extract_function(
    COLLECTOR, "k8s_toolkit_daemonset_image"
)


class KubernetesJsonCollectionTests(unittest.TestCase):
    def run_get(self, stub: str, *, env: dict[str, str] | None = None):
        return bashtest.run_bash(
            "set -euo pipefail\n"
            + KUBECTL_FUNCTION
            + "\nkubectl get nodes -o json",
            stubs={"kubectl": stub},
            env={
                "CLUSTERMAX_KUBECTL_GET_RETRIES": "3",
                "CLUSTERMAX_KUBECTL_RETRY_DELAY": "0",
                **(env or {}),
            },
        )

    def test_transient_failure_is_retried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            counter = Path(tmp) / "calls"
            run = self.run_get(
                'count=$(cat "$CMAX_TEST_COUNTER" 2>/dev/null || echo 0)\n'
                'count=$((count + 1))\n'
                'printf "%s" "$count" > "$CMAX_TEST_COUNTER"\n'
                'if [[ "$count" -lt 3 ]]; then\n'
                '  echo "dial tcp: lookup api.example: no such host" >&2\n'
                '  exit 1\n'
                'fi\n'
                "printf '%s\\n' '{\"items\":[{\"metadata\":{\"name\":\"gpu-1\"}}]}'\n",
                env={"CMAX_TEST_COUNTER": str(counter)},
            )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            json.loads(run.stdout)["items"][0]["metadata"]["name"],
            "gpu-1",
        )
        self.assertEqual(len(run.calls("kubectl")), 3)

    def test_persistent_api_failure_does_not_become_an_empty_list(self) -> None:
        run = self.run_get(
            'echo "dial tcp: lookup api.example: no such host" >&2\nexit 1\n'
        )

        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn('{"items":[]}', run.stdout)
        self.assertIn("failed after 3 attempts", run.stderr)

    def test_missing_optional_resource_becomes_an_empty_list(self) -> None:
        run = self.run_get(
            'echo "error: the server doesn\'t have a resource type widgets" >&2\n'
            "exit 1\n"
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {"items": []})
        self.assertEqual(len(run.calls("kubectl")), 1)

    def test_large_toolkit_daemonset_json_uses_pipe_based_parsers(self) -> None:
        payload = json.dumps(
            {
                "status": {"numberReady": 4},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "image": (
                                        "nvcr.io/nvidia/k8s/container-toolkit:v1.20.0"
                                    )
                                }
                            ]
                        }
                    }
                },
                "metadata": {"annotations": {"large": "x" * 100_000}},
            }
        )
        run = bashtest.run_bash(
            "set -euo pipefail\n"
            + TOOLKIT_READY_FUNCTION
            + TOOLKIT_IMAGE_FUNCTION
            + "\npayload=$(kubectl)\n"
            + 'k8s_toolkit_daemonset_ready "$payload"\n'
            + 'k8s_toolkit_daemonset_image "$payload"\n',
            stubs={"kubectl": f"printf '%s\\n' {payload!r}"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            run.stdout.splitlines(),
            [
                "4",
                "nvcr.io/nvidia/k8s/container-toolkit:v1.20.0",
            ],
        )

    def test_invalid_toolkit_daemonset_json_uses_safe_defaults(self) -> None:
        run = bashtest.run_bash(
            "set -euo pipefail\n"
            + TOOLKIT_READY_FUNCTION
            + TOOLKIT_IMAGE_FUNCTION
            + "\nk8s_toolkit_daemonset_ready 'not-json'\n"
            + "k8s_toolkit_daemonset_image 'not-json'\n",
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), ["0"])

    def test_named_object_not_found_remains_a_collection_failure(self) -> None:
        run = self.run_get(
            'echo \'Error from server (NotFound): nodes "gpu-1" not found\' >&2\n'
            "exit 1\n"
        )

        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn('{"items":[]}', run.stdout)
        self.assertIn("failed after 3 attempts", run.stderr)
        self.assertEqual(len(run.calls("kubectl")), 3)

    def test_caller_stderr_suppression_does_not_hide_final_error(self) -> None:
        run = bashtest.run_bash(
            "set -e\n"
            "exec {CLUSTERMAX_KUBECTL_ERROR_FD}>&2\n"
            + KUBECTL_FUNCTION
            + "\nkubectl get nodes -o json 2>/dev/null",
            stubs={
                "kubectl": (
                    'echo "dial tcp: lookup api.example: no such host" >&2\n'
                    "exit 1\n"
                )
            },
            env={
                "CLUSTERMAX_KUBECTL_GET_RETRIES": "1",
                "CLUSTERMAX_KUBECTL_RETRY_DELAY": "0",
            },
        )

        self.assertNotEqual(run.returncode, 0)
        self.assertIn("kubectl JSON request failed after 1 attempts", run.stderr)
        self.assertIn("no such host", run.stderr)

    def test_dra_resource_slice_failure_stops_node_inventory(self) -> None:
        run = bashtest.run_bash(
            "set -e\n"
            "exec {CLUSTERMAX_KUBECTL_ERROR_FD}>&2\n"
            + KUBECTL_FUNCTION
            + "\nk8s_gpu_dra_enabled() { return 0; }\n"
            + "k8s_audit_dra_gpu_counts() { printf '{}\\n'; }\n"
            + "k8s_audit_inject_dra_gpu_capacity() { printf '%s\\n' \"$1\"; }\n"
            + NODE_CACHE_BLOCK,
            stubs={
                "kubectl": (
                    'if [[ "$*" == "get nodes -o json" ]]; then\n'
                    "  printf '%s\\n' '{\"items\":[]}'\n"
                    "  exit 0\n"
                    "fi\n"
                    'echo "Error from server (Forbidden): resourceslices is forbidden" >&2\n'
                    "exit 1\n"
                )
            },
            env={
                "CLUSTERMAX_KUBECTL_GET_RETRIES": "1",
                "CLUSTERMAX_KUBECTL_RETRY_DELAY": "0",
            },
        )

        self.assertNotEqual(run.returncode, 0)
        self.assertIn("resourceslices is forbidden", run.stderr)
        self.assertEqual(len(run.calls("kubectl")), 2)


if __name__ == "__main__":
    unittest.main()
