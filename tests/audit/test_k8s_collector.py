"""Kubernetes JSON collection, host facts, images, RDMA, and deadlines."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
import pytest
import re
import importlib.util
import subprocess
from unittest import mock
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
SCRIPT = WORKLOAD / "cluster-audit-k8s.sh"

# JSON collection
KUBECTL_FUNCTION = bashtest.extract_function(SCRIPT, "kubectl")

NODE_CACHE_BLOCK = bashtest.extract_block(
    SCRIPT,
    "NODES_JSON=$(kubectl get nodes -o json 2>/dev/null)",
    "# SECTION 1: Kubernetes Version & Cluster Identity",
)

TOOLKIT_READY_FUNCTION = bashtest.extract_function(
    SCRIPT, "k8s_toolkit_daemonset_ready"
)

TOOLKIT_IMAGE_FUNCTION = bashtest.extract_function(
    SCRIPT, "k8s_toolkit_daemonset_image"
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

AUDIT_COMMON = WORKLOAD / "audit-common.sh"

# RDMA and EFA resources
FUNCTION_STUBS = {
    "print_section": "",
    "print_info": "",
    "print_warn": "",
    "print_detail": "",
    "audit_ufm_secured_profile": "",
}

def detection_snippet() -> str:
    return "\n".join(
        [
            bashtest.extract_function(AUDIT_COMMON, "k8s_quantity_to_number"),
            bashtest.extract_function(AUDIT_COMMON, "sum_k8s_quantities"),
            bashtest.extract_block(
                SCRIPT,
                "# RDMA / EFA detection",
                'audit_ufm_secured_profile "$RDMA_TYPE"',
            ),
            'printf "TYPE=%s\\n" "$RDMA_TYPE"',
        ]
    )

def run_detection(resources: dict[str, str]) -> bashtest.BashRun:
    node = {
        "status": {"capacity": resources, "allocatable": resources},
        "metadata": {"labels": {}},
    }
    return bashtest.run_bash(
        detection_snippet(),
        stubs=FUNCTION_STUBS,
        env={"NODES_JSON": json.dumps({"items": [node]})},
    )

def info_lines(run: bashtest.BashRun) -> list[str]:
    return [call[0] for call in run.calls("print_info")]

@pytest.mark.parametrize(
    ("resources", "expected_type", "expected_info"),
    [
        pytest.param(
            {"rdma/ib": "8"}, "infiniband", "Type: InfiniBand", id="rdma-ib"
        ),
        pytest.param(
            {"nvidia.com/rdma_ib": "8"},
            "infiniband",
            "Type: InfiniBand",
            id="nvidia-rdma-ib",
        ),
        pytest.param({"rdma/roce": "8"}, "roce", "Type: RoCE", id="rdma-roce"),
        pytest.param(
            {"nvidia.com/rdma_roce": "8"},
            "roce",
            "Type: RoCE",
            id="nvidia-rdma-roce",
        ),
        pytest.param(
            {"rdma/rdma_nic": "8"},
            "rdma",
            "Type: RDMA (generic extended resource)",
            id="generic-rdma-nic",
        ),
        pytest.param(
            {"vpc.amazonaws.com/efa": "4"},
            "efa",
            "Type: AWS EFA (Elastic Fabric Adapter)",
            id="efa",
        ),
    ],
)
def test_resource_key_selects_fabric_type(
    resources: dict[str, str], expected_type: str, expected_info: str
) -> None:
    run = run_detection(resources)
    assert run.returncode == 0, run.stderr
    assert f"TYPE={expected_type}" in run.stdout
    assert expected_info in info_lines(run)

    assert run.calls("audit_ufm_secured_profile") == [[expected_type]]

def test_generic_rdma_resource_reports_devices_and_names() -> None:

    run = run_detection({"rdma/rdma_nic": "8"})
    assert run.returncode == 0, run.stderr
    assert "TYPE=rdma" in run.stdout
    lines = info_lines(run)
    assert "Type: RDMA (generic extended resource)" in lines
    assert "RDMA devices: 8" in lines
    details = [call[0] for call in run.calls("print_detail")]
    assert "Resource(s): rdma/rdma_nic" in details

def test_no_rdma_resources_reports_none() -> None:
    run = run_detection({})
    assert run.returncode == 0, run.stderr
    assert "TYPE=none" in run.stdout
    assert "No RDMA resources (using TCP)" in [
        call[0] for call in run.calls("print_warn")
    ]
    assert run.calls("audit_ufm_secured_profile") == [["none"]]

# Driver-pod and host-root fact merge
DRIVER_POD_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=nvidia-driver-daemonset-2hhjv",
        "WORKER_DRIVER_VERSION=580.173.02",
        "WORKER_GPU_COUNT=4",
        "WORKER_GPU_MODEL=NVIDIA GB300",
        "WORKER_CUDA_VERSION=13.0",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=",
        "WORKER_PERF_STAT_ACCESS=no-perf",
        "WORKER_IPMITOOL_PATH=",
        "WORKER_IPMI_USER_ACCESS=not-installed",
        "WORKER_NCU_PATH=",
        "WORKER_NCU_COUNTER_ACCESS=no-ncu",
        "WORKER_NVHPC_INSTALLED=false",
        "WORKER_NVHPC_COMPONENTS_MISSING=not-checked",
        "WORKER_NCCL_VERSION=not-found",
    ]
)

HOST_ROOT_OUT = "\n".join(
    [
        "WORKER_HOSTNAME=gpu080023",
        "WORKER_DRIVER_VERSION=unknown",
        "WORKER_GPU_COUNT=0",
        "WORKER_GPU_MODEL=no-nvidia-smi",
        "WORKER_CUDA_VERSION=not-found",
        "WORKER_PERF_EVENT_PARANOID=4",
        "WORKER_PERF_PATH=/usr/bin/perf",
        "WORKER_PERF_STAT_ACCESS=granted",
        "WORKER_IPMITOOL_PATH=",
        "WORKER_IPMI_USER_ACCESS=blocked",
        "WORKER_NCU_PATH=/usr/local/cuda/bin/ncu",
        "WORKER_NCU_COUNTER_ACCESS=granted",
        "WORKER_NVHPC_INSTALLED=true",
        "WORKER_NVHPC_COMPONENTS_MISSING=none",
        "WORKER_NCCL_VERSION=2.30.7",
        "WORKER_NETUTIL_LSPCI_PATH=/usr/bin/lspci",
        "WORKER_SOMETHING_HOST_ONLY=1",
    ]
)

def merge(driver_out: str, host_out: str) -> dict[str, str]:
    text = SCRIPT.read_text(encoding="utf-8")
    allow = re.search(r"^HOST_ROOT_FACT_KEYS=.*$", text, re.M)
    assert allow, "HOST_ROOT_FACT_KEYS assignment not found"
    block = allow.group(0) + "\n" + bashtest.extract_function(SCRIPT, "merge_host_check_facts")
    run = bashtest.run_bash(
        block + '\nmerge_host_check_facts "$DRIVER_OUT" "$HOST_OUT"',
        env={"DRIVER_OUT": driver_out, "HOST_OUT": host_out},
    )
    assert run.returncode == 0, run.stderr
    facts: dict[str, str] = {}
    for line in run.stdout.splitlines():
        key, _, value = line.partition("=")
        assert key not in facts, f"duplicate key in merged output: {key}"
        facts[key] = value
    return facts

def test_host_root_supplies_host_installed_tools():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_PERF_PATH"] == "/usr/bin/perf"
    assert facts["WORKER_PERF_STAT_ACCESS"] == "granted"

def test_host_sentinels_do_not_replace_driver_pod_gpu_facts():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_DRIVER_VERSION"] == "580.173.02"
    assert facts["WORKER_GPU_COUNT"] == "4"
    assert facts["WORKER_GPU_MODEL"] == "NVIDIA GB300"
    assert facts["WORKER_CUDA_VERSION"] == "13.0"
    assert facts["WORKER_HOSTNAME"] == "nvidia-driver-daemonset-2hhjv"

def test_host_root_is_authoritative_for_whole_tool_families():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_NCU_PATH"] == "/usr/local/cuda/bin/ncu"
    assert facts["WORKER_NCU_COUNTER_ACCESS"] == "granted"
    assert facts["WORKER_IPMI_USER_ACCESS"] == "blocked"
    assert facts["WORKER_NCCL_VERSION"] == "2.30.7"

    assert facts["WORKER_NVHPC_INSTALLED"] == "true"
    assert facts["WORKER_NVHPC_COMPONENTS_MISSING"] == "none"

def test_host_tool_sentinels_also_come_from_the_host_root():
    facts = merge("WORKER_PERF_PATH=/opt/perf", "WORKER_PERF_PATH=")
    assert facts["WORKER_PERF_PATH"] == ""

def test_empty_on_both_sides_stays_empty():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_IPMITOOL_PATH"] == ""

def test_only_allowlisted_host_only_facts_are_added():
    facts = merge(DRIVER_POD_OUT, HOST_ROOT_OUT)
    assert facts["WORKER_NETUTIL_LSPCI_PATH"] == "/usr/bin/lspci"
    assert "WORKER_SOMETHING_HOST_ONLY" not in facts

def test_no_host_root_output_leaves_driver_facts_unchanged():
    facts = merge(DRIVER_POD_OUT, "")
    assert facts == dict(line.split("=", 1) for line in DRIVER_POD_OUT.splitlines())

def test_values_containing_equals_signs_survive():
    facts = merge("WORKER_PERF_PATH=a=b", "WORKER_NCU_PATH=c=d")
    assert facts == {"WORKER_PERF_PATH": "a=b", "WORKER_NCU_PATH": "c=d"}

# Utility pod images
CURL_IMAGE = (
    "curlimages/curl:8.21.0@"
    "sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13"
)

UBUNTU_IMAGE = (
    "ubuntu:24.04@"
    "sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea"
)

PYTHON_IMAGE = (
    "python:3.12-alpine@"
    "sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b"
)

@pytest.mark.parametrize("check_path", ["platform_config.py", "system/hbm_memory_exposure.py"])
@pytest.mark.parametrize("override", [None, "registry.example/python@" + PYTHON_IMAGE.split("@")[1]])
def test_python_host_checks_use_pinned_default_and_preserve_override(check_path, override):
    spec = importlib.util.spec_from_file_location("host_check", SCRIPT.parent / "checks" / check_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    node = {"name": "gpu-0"}
    fanout = mock.Mock()
    fanout.k8s_gpu_nodes.return_value = [node]
    fanout.fan_out_k8s.side_effect = lambda worker, **kwargs: worker(node)
    env = {} if override is None else {"CLUSTERMAX_AUDIT_K8S_HOST_CHECK_IMAGE": override}
    with (
        mock.patch.dict(module.os.environ, env, clear=True),
        mock.patch.object(module, "load_fanout", return_value=fanout),
        mock.patch.object(module, "kubectl", return_value=subprocess.CompletedProcess([], 0, "{}")),
        mock.patch.object(module, "run_k8s_host_check") as run_host,
    ):
        if check_path == "platform_config.py":
            module.run_k8s_check([node])
        else:
            module.run_k8s_check()
    namespace, selected_node, image = run_host.call_args.args
    manifest = module.pod_manifest(namespace, selected_node, image, "test-pod")
    assert manifest["spec"]["containers"][0]["image"] == (override or PYTHON_IMAGE)

def _applied_manifest(function_name: str, setup: str) -> dict:
    function = bashtest.extract_function(SCRIPT, function_name)
    with tempfile.TemporaryDirectory() as temp_dir:
        applied = Path(temp_dir) / "applied.yaml"
        run = bashtest.run_bash(
            f"{function}\n{setup}",
            stubs={"kubectl": 'cat > "$APPLIED_MANIFEST"'},
            env={"APPLIED_MANIFEST": str(applied)},
        )
        assert run.returncode == 0, run.stderr
        return yaml.safe_load(applied.read_text())

def test_geolocation_pod_uses_reviewed_image_and_no_service_account_token():
    manifest = _applied_manifest(
        "apply_geolocation_check_pod",
        "GEO_POD=cmax-audit-geo-test\napply_geolocation_check_pod",
    )

    assert manifest["kind"] == "Pod"
    assert manifest["spec"]["automountServiceAccountToken"] is False
    assert manifest["spec"]["containers"][0]["image"] == CURL_IMAGE

def test_privileged_host_pod_uses_reviewed_image_and_no_service_account_token():
    manifest = _applied_manifest(
        "apply_privileged_host_check_pod",
        """
ensure_audit_check_namespace() { return 0; }
check_log() { return 0; }
audit_check_wait_ready() { return 0; }
cleanup_audit_check_pod() { return 0; }
K8S_AUDIT_CHECK_NS=test-ns
apply_privileged_host_check_pod gpu-1
""",
    )

    assert manifest["kind"] == "Pod"
    assert manifest["spec"]["automountServiceAccountToken"] is False
    assert manifest["spec"]["hostPID"] is True
    assert manifest["spec"]["hostNetwork"] is True
    assert manifest["spec"]["containers"][0]["image"] == UBUNTU_IMAGE
    assert manifest["spec"]["containers"][0]["securityContext"]["privileged"] is True

def test_check_deadline_fallback_does_not_hold_command_substitution_open():
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("check_deadline() {")
    end = source.index("\n}", start) + len("\n}")
    function = source[start:end]

    script = f"""
command() {{
    if [[ "$1" == "-v" && "${{2:-}}" == "timeout" ]]; then
        return 1
    fi
    builtin command "$@"
}}
{function}
result="$(check_deadline 5 bash -c 'printf complete')"
[[ "$result" == "complete" ]]
"""

    subprocess.run(["bash", "-c", script], check=True, timeout=2)
