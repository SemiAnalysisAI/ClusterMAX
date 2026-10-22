#!/usr/bin/env python3
"""Unit tests for shared audit shell helpers."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

from cmax import audit_profiles


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
COMMON_PATH = AUDIT_SCRIPTS / "audit-common.sh"
RUN_CHECKS_PATH = AUDIT_SCRIPTS / "run_checks.py"
HOST_CHECK_PATH = AUDIT_SCRIPTS / "host-check.sh"
RUN_CHECKS_SPEC = importlib.util.spec_from_file_location(
    "clustermax_run_checks", RUN_CHECKS_PATH
)
assert RUN_CHECKS_SPEC is not None and RUN_CHECKS_SPEC.loader is not None
run_checks = importlib.util.module_from_spec(RUN_CHECKS_SPEC)
RUN_CHECKS_SPEC.loader.exec_module(run_checks)


sys.path.insert(0, str(COMMON_PATH.parent))
import minimum_versions

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


class AuditCommonTests(unittest.TestCase):
    K8S_SCRIPT = AUDIT_SCRIPTS / "cluster-audit-k8s.sh"
    SLURM_SCRIPT = AUDIT_SCRIPTS / "cluster-audit-slurm.sh"
    K8S_MONITORING_SCRIPT = AUDIT_SCRIPTS / "monitoring-k8s.sh"

    def run_helper(self, function: str, value: str) -> str:
        command = f'source "$1"; {function} "$2"'
        result = subprocess.run(
            ["bash", "-c", command, "bash", str(COMMON_PATH), value],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_json_bool_or_unknown_preserves_missing_security_evidence(self) -> None:
        self.assertEqual(self.run_helper("json_bool_or_unknown", "true"), "true")
        self.assertEqual(self.run_helper("json_bool_or_unknown", "false"), "false")
        self.assertEqual(self.run_helper("json_bool_or_unknown", ""), '"unknown"')
        self.assertEqual(
            self.run_helper("json_bool_or_unknown", "unexpected"), '"unknown"'
        )

    def test_sanitize_git_remote_url_removes_https_credentials(self) -> None:
        remote = "https://token-user:secret-value@github.com/example/repo.git"
        self.assertEqual(
            self.run_helper("sanitize_git_remote_url", remote),
            "https://github.com/example/repo.git",
        )

    def test_sanitize_git_remote_url_removes_query_credentials(self) -> None:
        remote = "https://github.com/example/repo.git?access_token=secret-value"
        self.assertEqual(
            self.run_helper("sanitize_git_remote_url", remote),
            "https://github.com/example/repo.git",
        )

    def test_sanitize_git_remote_url_removes_ssh_uri_credentials(self) -> None:
        remote = "ssh://token-user:secret-value@github.com/example/repo.git"
        self.assertEqual(
            self.run_helper("sanitize_git_remote_url", remote),
            "ssh://github.com/example/repo.git",
        )

    def test_sanitize_git_remote_url_removes_scp_user(self) -> None:
        self.assertEqual(
            self.run_helper(
                "sanitize_git_remote_url", "git@github.com:example/repo.git"
            ),
            "github.com:example/repo.git",
        )

    def test_gpu_error_scan_reads_retained_kernel_journal(self) -> None:
        function = bashtest.extract_function(COMMON_PATH, "gpu_error_scan_script")
        run = bashtest.run_bash(
            function + '\nbash -c "$(gpu_error_scan_script)"',
            stubs={
                "journalctl": (
                    "printf '%s\\n' "
                    "'audit: permission denied for an unrelated request' "
                    "'NVRM: Xid (PCI:0000:31:00): 31, MMU Fault' "
                    "'NVRM: Xid (PCI:0000:31:00): 79, fallen off bus'"
                ),
                "dmesg": "exit 99",
                "hostname": "echo gpu-a",
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "GPU_ERROR\tgpu-a\tjournalctl\t2\t79\t0")
        self.assertIn("7 days ago", run.calls("journalctl")[0])
        self.assertIn("_TRANSPORT=kernel", run.calls("journalctl")[0])
        self.assertEqual(run.calls("dmesg"), [])

    def test_gpu_error_scan_falls_back_to_dmesg_when_journal_is_hidden(self) -> None:
        function = bashtest.extract_function(COMMON_PATH, "gpu_error_scan_script")
        run = bashtest.run_bash(
            function + '\nbash -c "$(gpu_error_scan_script)"',
            stubs={
                "journalctl": "echo 'not seeing messages from other users' >&2",
                "dmesg": "echo 'NVRM: Xid (PCI:0000:31:00): 79, fallen off bus'",
                "hostname": "echo gpu-b",
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "GPU_ERROR\tgpu-b\tdmesg\t1\t79\t0")

    def test_gpu_error_aggregation_sums_node_results(self) -> None:
        function = bashtest.extract_function(COMMON_PATH, "aggregate_gpu_error_history")
        rows = "GPU_ERROR\\tgpu-a\\tjournalctl\\t2\\t31\\t0\\nGPU_ERROR\\tgpu-b\\tdmesg\\t1\\t79\\t3"
        run = bashtest.run_bash(
            function
            + f"\naggregate_gpu_error_history $'{rows}'"
            + '\nprintf "%s %s %s %s\\n" "$GPU_ERROR_NODES_CHECKED" "$DMESG_XIDS_COUNT" "$DMESG_XID_LAST" "$DMESG_AMDGPU_ERRORS_COUNT"',
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "2 3 79 3")

    def test_failed_gpu_error_aggregation_preserves_fallback(self) -> None:
        function = bashtest.extract_function(COMMON_PATH, "aggregate_gpu_error_history")
        run = bashtest.run_bash(
            function
            + "\nGPU_ERROR_NODES_CHECKED=1; DMESG_XIDS_COUNT=4"
            + "\naggregate_gpu_error_history '' || true"
            + '\nprintf "%s %s\\n" "$GPU_ERROR_NODES_CHECKED" "$DMESG_XIDS_COUNT"',
        )

        self.assertEqual(run.stdout.strip(), "1 4")

    def test_gpu_error_scan_fans_out_to_every_slurm_node(self) -> None:
        block = bashtest.extract_block(
            self.SLURM_SCRIPT,
            "# Read seven days of retained kernel history",
            "fi",
        )
        run = bashtest.run_bash(
            "print_section() { :; }\n"
            + bashtest.extract_function(COMMON_PATH, "gpu_error_scan_script")
            + bashtest.extract_function(COMMON_PATH, "aggregate_gpu_error_history")
            + "\nAUDIT_SRUN_FLAGS=(); SLURM_JOB_ID=1; SLURM_NNODES=3\n"
            + block,
            stubs={"srun": "printf 'GPU_ERROR\\tgpu-a\\tjournalctl\\t0\\tnone\\t0\\n'"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("-N3", run.calls("srun")[0])
        self.assertIn("--ntasks=3", run.calls("srun")[0])
        self.assertIn("--ntasks-per-node=1", run.calls("srun")[0])

    def test_gpu_error_scan_visits_every_kubernetes_gpu_node(self) -> None:
        block = bashtest.extract_block(
            self.K8S_SCRIPT,
            "DMESG_XIDS_COUNT=unavailable",
            'aggregate_gpu_error_history "$GPU_ERROR_OUTPUT" || true',
        )
        run = bashtest.run_bash(
            bashtest.extract_function(COMMON_PATH, "aggregate_gpu_error_history")
            + "\nrun_gpu_error_check_on_node() { printf 'GPU_ERROR\\t%s\\tjournalctl\\t0\\tnone\\t0\\n' \"$1\"; }"
            + "\nGPU_NODE_COUNT=3; GPU_CHECK_NODE_NAMES='gpu-a gpu-b gpu-c'\n"
            + block
            + '\nprintf "%s %s\\n" "$GPU_ERROR_NODES_CHECKED" "$GPU_ERROR_NODES_TOTAL"',
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "3 3")

    def test_run_checks_uses_shebang_for_non_python_executables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checks"
            root.mkdir()
            check = root / "shell-check.sh"
            check.write_text('#!/bin/sh\nprintf \'{"shell_check": true}\\n\'\n')
            check.chmod(0o755)
            output = Path(tmp) / "check-data.json"

            run = subprocess.run(
                [
                    sys.executable,
                    str(RUN_CHECKS_PATH),
                    str(root),
                    str(output),
                    "k8s",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(output.read_text()), {"shell_check": True})

    def test_each_named_profile_selects_only_its_supplemental_checks(self) -> None:
        check_root = AUDIT_SCRIPTS / "checks"

        self.assertEqual(
            run_checks.VALID_PROFILES,
            frozenset({"full", *audit_profiles.AUDIT_PROFILE_NAMES}),
        )

        selected = {
            profile: {
                str(path.relative_to(check_root))
                for path in run_checks.iter_checks(check_root, "slurm", profile)
            }
            for profile in run_checks.VALID_PROFILES
        }

        self.assertEqual(selected["software"], set())
        self.assertEqual(selected["containers"], set())
        self.assertEqual(selected["health"], set())
        self.assertEqual(
            selected["security"],
            {
                "fabric/nic-topology-check.py",
                "fabric/virtio-net-check.py",
            },
        )
        self.assertEqual(
            selected["hardware"],
            {
                "gpu/vboost.py",
                "system/arm-smmu-virtualization-check.py",
                "system/hbm_memory_exposure.py",
                "system/vm-iommu-check.py",
            },
        )
        self.assertEqual(
            selected["full"],
            {
                name for name in run_checks.CHECK_PROFILES
                if "slurm" in run_checks.CHECK_HARNESSES[name]
            },
        )

    def test_standalone_omits_scale_out_checks(self) -> None:
        check_root = AUDIT_SCRIPTS / "checks"

        standalone = {
            str(path.relative_to(check_root))
            for path in run_checks.iter_checks(check_root, "standalone")
        }
        slurm = {
            str(path.relative_to(check_root))
            for path in run_checks.iter_checks(check_root, "slurm")
        }
        k8s = {
            str(path.relative_to(check_root))
            for path in run_checks.iter_checks(check_root, "k8s")
        }

        fabric = {
            "fabric/nccl-ib-qps-check.py",
            "fabric/nccl-topology-file-check.py",
            "fabric/nic-topology-check.py",
            "fabric/virtio-net-check.py",
        }
        self.assertTrue(fabric.isdisjoint(standalone))
        self.assertTrue(fabric.issubset(slurm))
        self.assertTrue(
            fabric.difference({"fabric/nccl-topology-file-check.py"}).issubset(k8s)
        )

    def test_standalone_host_check_does_not_run_scale_out_tools(self) -> None:
        scale_out_tools = {
            "ib_write_bw",
            "ibdev2netdev",
            "ibhosts",
            "ibstat",
            "ibstatus",
            "ibv_devices",
            "mpirun",
            "ofed_info",
            "ompi_info",
            "rdma",
            "sharp_hello",
        }
        run = bashtest.run_bash(
            'bash "$HOST_CHECK_PATH"',
            stubs={
                **{tool: "exit 97" for tool in scale_out_tools},
                "find": "exit 0",
                "lspci": "printf '0000:00:1f.0 0601: 8086:a1c1\\n'",
            },
            env={
                "CLUSTERMAX_AUDIT_HARNESS": "standalone",
                "HOST_CHECK_PATH": str(HOST_CHECK_PATH),
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(all(run.calls(tool) == [] for tool in scale_out_tools))
        self.assertIn("WORKER_ACS_METHOD=skipped", run.stdout)
        self.assertIn("WORKER_IB_DEVICES=", run.stdout)
        self.assertNotIn("WORKER_IB_RATE_", run.stdout)
        self.assertIn("WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true", run.stdout)
        self.assertIn("WORKER_SECURITY_NVIDIA_GPU_PRESENT=false", run.stdout)

    def test_standalone_scale_out_skip_defines_shared_json_fields(self) -> None:
        collector = AUDIT_SCRIPTS / "cluster-audit-standalone.sh"
        skip_block = bashtest.extract_block(
            collector,
            "    IB_INSTALLED=false",
            "    UFM_SECURED_PROFILE_JSON=",
        )
        run = bashtest.run_bash(
            skip_block
            + "\nprintf '%s\\n' \"$COMPUTE_FABRIC_GBPS\" "
            '"$NIC_HAS_INFINIBAND" "$NIC_HAS_ROCE" '
            '"$NIC_HAS_EFA" "$NIC_HAS_OTHER"\n'
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), ["0", "false", "false", "false", "false"])

    def test_k8s_gpu_operator_discovery_accepts_nvidia_namespace(self) -> None:
        function = bashtest.extract_function(
            self.K8S_SCRIPT, "find_gpu_operator_namespace"
        )
        run = bashtest.run_bash(
            function + "find_gpu_operator_namespace",
            stubs={"kubectl": '[[ "$*" == "get namespace nvidia" ]]'},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "nvidia")

    def test_k8s_gfd_discovery_accepts_nvidia_namespace(self) -> None:
        function = bashtest.extract_function(
            self.K8S_MONITORING_SCRIPT, "find_gfd_namespace"
        )
        run = bashtest.run_bash(
            function + "find_gfd_namespace",
            stubs={
                "kubectl": (
                    'if [[ "$*" == *"get pods -n nvidia "* ]]; then '
                    'echo gpu-feature-discovery; fi'
                )
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "nvidia")

    def test_k8s_gfd_discovery_scans_branded_namespaces(self) -> None:
        function = bashtest.extract_function(
            self.K8S_MONITORING_SCRIPT, "find_gfd_namespace"
        )
        run = bashtest.run_bash(
            function + "find_gfd_namespace",
            stubs={
                "kubectl": (
                    'if [[ "$*" == *"--all-namespaces -l app=gpu-feature-discovery"* ]]; then '
                    "printf 'example-nvidia-gpu-operator'; fi"
                )
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "example-nvidia-gpu-operator")

    def test_k8s_dcgm_discovery_scans_branded_namespaces(self) -> None:
        block = bashtest.extract_block(
            self.K8S_MONITORING_SCRIPT,
            'if [[ "$DCGM_INSTALLED" == "false" ]]; then',
            "# End cross-namespace DCGM exporter discovery.",
        )
        pods = json.dumps(
            {
                "items": [
                    {
                        "metadata": {
                            "namespace": "cw-exporters",
                            "name": "dcgm-exporter-abc12",
                        },
                        "status": {"phase": "Running"},
                    }
                ]
            }
        )
        run = bashtest.run_bash(
            block
            + '\nprintf "%s|%s|%s|%s\\n" "$DCGM_INSTALLED" '
            '"$DCGM_NAMESPACE" "$DCGM_POD" "$DCGM_PODS_RUNNING"',
            stubs={
                "kubectl": (
                    'if [[ "$*" == *"get pods --all-namespaces -o json"* ]]; then '
                    f"cat <<'JSON'\n{pods}\nJSON\n"
                    'elif [[ "$*" == *"get pods -n cw-exporters -o json"* ]]; then '
                    f"cat <<'JSON'\n{pods}\nJSON\n"
                    "fi"
                )
            },
            env={"DCGM_INSTALLED": "false"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            run.stdout.strip(),
            "true|cw-exporters|dcgm-exporter-abc12|1",
        )

    def test_k8s_logging_keeps_aggregation_stack_when_promtail_is_present(self) -> None:
        block = bashtest.extract_block(
            self.K8S_MONITORING_SCRIPT,
            'LOGGING_STACK="none"',
            '[[ "$LOGGING_STACK" == "none" ]] && print_warn "No log aggregation detected"',
        )
        run = bashtest.run_bash(
            "print_info() { :; }\n"
            "print_warn() { :; }\n"
            + block
            + '\nprintf "%s\\n" "$LOGGING_STACK"\n',
            stubs={
                "kubectl": (
                    'if [[ "$*" == *"app.kubernetes.io/name=loki"* ]]; then\n'
                    "  printf 'loki-0 1/1 Running\\n'\n"
                    'elif [[ "$*" == *"app=promtail -o json"* ]]; then\n'
                    "  printf '%s\\n' '{\"items\":[{\"status\":{\"phase\":\"Running\"}}]}'\n"
                    "fi"
                )
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "loki")

    def test_k8s_aks_detection_requires_canonical_cluster_label(self) -> None:
        function = bashtest.extract_function(self.K8S_SCRIPT, "is_aks_nodes_json")
        labeled = json.dumps(
            {
                "items": [
                    {
                        "metadata": {
                            "labels": {"kubernetes.azure.com/cluster": "MC_rg_cluster_region"}
                        },
                        "spec": {"providerID": "azure:///subscriptions/example"},
                    }
                ]
            }
        )
        self_managed = json.dumps(
            {
                "items": [
                    {
                        "metadata": {"labels": {}},
                        "spec": {"providerID": "azure:///subscriptions/example"},
                    }
                ]
            }
        )

        detected = bashtest.run_bash(
            function + 'is_aks_nodes_json "$NODES_JSON"', env={"NODES_JSON": labeled}
        )
        rejected = bashtest.run_bash(
            function + 'is_aks_nodes_json "$NODES_JSON"',
            env={"NODES_JSON": self_managed},
        )

        self.assertEqual(detected.returncode, 0, detected.stderr)
        self.assertNotEqual(rejected.returncode, 0, rejected.stderr)

    def test_k8s_coreweave_detection_uses_provider_label_domain(self) -> None:
        function = bashtest.extract_function(
            self.K8S_SCRIPT, "is_coreweave_nodes_json"
        )
        labeled = json.dumps(
            {
                "items": [
                    {
                        "metadata": {
                            "labels": {
                                "node.coreweave.cloud/class": "gpu",
                                "topology.kubernetes.io/region": "US-WEST-04",
                            }
                        }
                    }
                ]
            }
        )
        generic = json.dumps(
            {
                "items": [
                    {
                        "metadata": {
                            "labels": {"node.kubernetes.io/instance-type": "gpu"}
                        }
                    }
                ]
            }
        )

        detected = bashtest.run_bash(
            function + 'is_coreweave_nodes_json "$NODES_JSON"',
            env={"NODES_JSON": labeled},
        )
        rejected = bashtest.run_bash(
            function + 'is_coreweave_nodes_json "$NODES_JSON"',
            env={"NODES_JSON": generic},
        )

        self.assertEqual(detected.returncode, 0, detected.stderr)
        self.assertNotEqual(rejected.returncode, 0, rejected.stderr)

    def test_k8s_gpu_operator_discovery_scans_branded_namespaces(self) -> None:
        function = bashtest.extract_function(
            self.K8S_SCRIPT, "find_gpu_operator_namespace"
        )
        namespaces = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "default"}},
                    {"metadata": {"name": "example-nvidia-gpu-operator"}},
                ]
            }
        )
        run = bashtest.run_bash(
            function + "find_gpu_operator_namespace",
            stubs={
                "kubectl": (
                    'if [[ "$*" == "get namespaces -o json" ]]; then '
                    f"cat <<'JSON'\n{namespaces}\nJSON\n"
                    "else exit 1; fi"
                )
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "example-nvidia-gpu-operator")

    def test_supplemental_checks_select_branded_gpu_operator_namespace(self) -> None:
        self.assertEqual(
            run_checks.select_gpu_operator_namespace(
                ["default", "example-nvidia-gpu-operator", "kube-system"]
            ),
            "example-nvidia-gpu-operator",
        )

    def test_bmc_ipmi_summary_retains_per_node_coverage(self) -> None:
        function = bashtest.extract_function(
            self.K8S_SCRIPT, "summarize_bmc_ipmi_nodes"
        )
        hosts = [
            {"node": "gpu-1", "checked": True, "exposed": True},
            {"node": "gpu-2", "checked": True, "exposed": False},
            {"node": "cpu-1", "checked": False, "exposed": "unknown"},
        ]
        run = bashtest.run_bash(
            function + 'printf "%s" "$BMC_HOSTS" | summarize_bmc_ipmi_nodes',
            env={"BMC_HOSTS": "\n".join(json.dumps(host) for host in hosts)},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        summary = json.loads(run.stdout)
        self.assertTrue(summary["exposed"])
        self.assertEqual(summary["nodesTotal"], 3)
        self.assertEqual(summary["nodesChecked"], 2)
        self.assertFalse(summary["nodeCoverageComplete"])
        self.assertEqual(summary["exposedNodes"], ["gpu-1"])
        self.assertEqual(summary["unassessedNodes"], ["cpu-1"])
        self.assertFalse(summary["ordinaryPodExposureTested"])

    def test_summarize_gpu_nodes_ignores_cpu_only_nodes(self) -> None:
        nodes = [
            {"name": "cpu-1", "cpus": 128, "memory": 1048576, "gpus": 0},
            {"name": "gpu-1", "cpus": 192, "memory": 4128768, "gpus": 8},
            {"name": "gpu-2", "cpus": 192, "memory": 4128768, "gpus": 8},
        ]
        summary = json.loads(self.run_helper("summarize_gpu_nodes", json.dumps(nodes)))

        self.assertEqual(
            summary,
            {
                "nodeCount": 2,
                "totalGpus": 16,
                "perNode": 8,
                "totalCpus": 384,
                "totalMemoryGB": 8064,
            },
        )

    def test_select_gpu_partition_prefers_gpu_only_accelerator_partition(self) -> None:
        rows = "\n".join(
            [
                "all      |cpu-1    |(null)",
                "all      |gpu-1    |gpu:B300:8(S:0-1)",
                "hpc-mid* |gpu-1    |gpu:B300:8(S:0-1)",
                "b300     |gpu-1    |gpu:B300:8(S:0-1)",
                "all      |gpu-2    |gpu:B300:8(S:0-1)",
                "hpc-mid* |gpu-2    |gpu:B300:8(S:0-1)",
                "b300     |gpu-2    |gpu:B300:8(S:0-1)",
            ]
        )

        self.assertEqual(self.run_helper("select_gpu_partition", rows), "b300")

    def test_select_gpu_partition_falls_back_to_mixed_partition_with_gpu_gres(self) -> None:
        rows = "\n".join(
            [
                "all*|cpu-1|(null)",
                "all*|gpu-1|gpu:H100:8",
            ]
        )

        self.assertEqual(self.run_helper("select_gpu_partition", rows), "all")

    def test_amd_gpu_presence_uses_count_when_model_is_unknown(self) -> None:
        function = bashtest.extract_function(COMMON_PATH, "amd_gpu_check_present")

        counted = bashtest.run_bash(
            function + "\namd_gpu_check_present 8 unknown"
        )
        absent = bashtest.run_bash(
            function + "\namd_gpu_check_present 0 unknown"
        )
        modeled = bashtest.run_bash(
            function + "\namd_gpu_check_present 0 'AMD Instinct MI355X'"
        )

        self.assertEqual(counted.returncode, 0, counted.stderr)
        self.assertNotEqual(absent.returncode, 0, absent.stderr)
        self.assertEqual(modeled.returncode, 0, modeled.stderr)

    def run_ufm_profile_helper(self, rdma_type: str) -> dict:
        command = (
            'source "$1"; '
            'audit_ufm_secured_profile "$2" >/dev/null; '
            'printf "%s" "$UFM_SECURED_PROFILE_JSON"'
        )
        result = subprocess.run(
            ["bash", "-c", command, "bash", str(COMMON_PATH), rdma_type],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_ufm_secured_profile_requires_manual_verification_for_infiniband(self) -> None:
        profile = self.run_ufm_profile_helper("infiniband")

        self.assertTrue(profile["applicable"])
        self.assertEqual(profile["status"], "provider_attestation_required")
        self.assertEqual(profile["profile"], "Secured Bare Metal Cloud")
        self.assertEqual(len(profile["requiredControls"]), 7)
        self.assertTrue(
            any("allowed_guid_list" in item for item in profile["requiredControls"])
        )
        self.assertTrue(
            any("service_key" in item for item in profile["requiredControls"])
        )

    def test_ufm_secured_profile_is_not_applicable_without_infiniband(self) -> None:
        profile = self.run_ufm_profile_helper("roce")

        self.assertFalse(profile["applicable"])
        self.assertEqual(profile["status"], "not_applicable")

    def test_ufm_secured_profile_is_unknown_for_generic_rdma(self) -> None:
        profile = self.run_ufm_profile_helper("rdma")

        self.assertIsNone(profile["applicable"])
        self.assertEqual(profile["status"], "unknown")

    def test_k8s_quantity_parser_accepts_canonical_si_suffixes(self) -> None:
        self.assertEqual(self.run_helper("k8s_quantity_to_number", "1k"), "1000")
        self.assertEqual(self.run_helper("k8s_quantity_to_number", "250m"), "0.25")

    def test_k8s_quantity_parser_accepts_binary_and_exponent_suffixes(self) -> None:
        self.assertEqual(self.run_helper("k8s_quantity_to_number", "2Ki"), "2048")
        self.assertEqual(self.run_helper("k8s_quantity_to_number", "3e3"), "3000")
        self.assertEqual(
            self.run_helper("format_k8s_memory", "2786696428Ki"), "2657.6 GB"
        )
        self.assertEqual(self.run_helper("format_k8s_memory", "512Mi"), "512 MB")

    def test_k8s_quantity_sum_handles_vessl_shared_rdma_capacity(self) -> None:
        command = 'source "$1"; printf "1k\\n1k\\n1k\\n1k\\n" | sum_k8s_quantities'
        result = subprocess.run(
            ["bash", "-c", command, "bash", str(COMMON_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "4000")

    def test_host_nccl_search_prunes_enroot_container_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_lib = root / "usr" / "lib" / "libnccl.so.2"
            container_lib = (
                root
                / "usr"
                / "share"
                / "enroot"
                / "enroot-data"
                / "pyxis_partial"
                / "usr"
                / "lib"
                / "libnccl.so.9"
            )
            host_lib.parent.mkdir(parents=True)
            container_lib.parent.mkdir(parents=True)
            host_lib.touch()
            container_lib.touch()

            candidates = self.run_helper("find_host_nccl_candidates", str(root))

            self.assertEqual(candidates.splitlines(), [str(host_lib)])


class CollectorSafetyTests(unittest.TestCase):
    SLURM_SCRIPT = AUDIT_SCRIPTS / "cluster-audit-slurm.sh"
    K8S_SCRIPT = AUDIT_SCRIPTS / "cluster-audit-k8s.sh"
    PRINT_STUBS = "\n".join(
        f"{name}() {{ :; }}" for name in
        ("print_section", "print_detail", "print_warn", "print_info")
    ) + "\n"

    def test_failed_worker_checks_keep_gres_and_deliver_scripts_on_stdin(self) -> None:
        blocks = {
            "host": bashtest.extract_block(
                self.SLURM_SCRIPT,
                'if [[ -n "$GPU_PARTITION" ]]; then\n    print_section "Checking compute node',
                "# Build worker drive config JSON",
            ),
            "container": bashtest.extract_block(
                self.SLURM_SCRIPT,
                'if [[ -n "$GPU_PARTITION" && -f "$WORKLOAD_DIR/container-check.sh" ]]; then',
                "# Head-vs-worker consistency for container runtimes",
            ),
        }
        for name, block in blocks.items():
            with self.subTest(check=name), tempfile.TemporaryDirectory() as tmp:
                captured = Path(tmp) / "stdin"
                run = bashtest.run_bash(
                    self.PRINT_STUBS
                    + 'AUDIT_SRUN_FLAGS=(); GPU_SRUN_SCOPE_ARGS=(-p mixed)\n'
                    + 'AUDIT_STEP_TMPDIR_EXPORT_ARGS=(); GPU_PARTITION=mixed\n'
                    + f'WORKLOAD_DIR="{AUDIT_SCRIPTS}"\n'
                    + block,
                    stubs={"srun": 'cat > "$CAPTURE_STDIN"; exit 1'},
                    env={"CAPTURE_STDIN": str(captured)},
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                calls = run.calls("srun")
                self.assertEqual(len(calls), 1, calls)
                self.assertIn("--gres=gpu:1", calls[0])
                self.assertEqual(calls[0][-2:], ["bash", "-s"])
                self.assertEqual(
                    captured.read_bytes(),
                    (AUDIT_SCRIPTS / f"{name}-check.sh").read_bytes(),
                )

    def test_prolog_retries_only_with_gpu_gres(self) -> None:
        block = bashtest.extract_block(
            self.SLURM_SCRIPT, 'PROLOG_RUNTIME_SEC="unmeasured"', "# NHC (Node Health Check)"
        )
        for fallback_rc in (0, 1):
            with self.subTest(fallback_rc=fallback_rc):
                run = bashtest.run_bash(
                    self.PRINT_STUBS
                    + 'GPU_PARTITION=mixed; WORKER_CHECK_OK=true; GPUS_PER_NODE=4\n'
                    + 'DEFAULT_GPUS_PER_NODE=8; AUDIT_SRUN_FLAGS=(); GPU_SRUN_SCOPE_ARGS=(-p mixed)\n'
                    + block
                    + '\nprintf "%s\\n" "$PROLOG_FAST"',
                    stubs={
                        "srun": (
                            f'[[ " $* " == *" --gres=gpu:1 "* ]] && exit {fallback_rc}\nexit 1'
                        ),
                        "date": "echo 100",
                    },
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                calls = run.calls("srun")
                self.assertEqual(len(calls), 2, calls)
                self.assertIn("--gres=gpu:4", calls[0])
                self.assertIn("--gres=gpu:1", calls[1])
                for call in calls:
                    self.assertEqual(call[call.index("-p") + 1], "mixed")
                self.assertEqual(run.stdout.strip(), "true" if fallback_rc == 0 else "unknown")

    def test_runtime_scope_fails_closed_without_findmnt(self) -> None:
        blocks = {
            "container": (
                bashtest.extract_block(
                    AUDIT_SCRIPTS / "container-check.sh",
                    'RUNTIME_SCOPE="${CLUSTERMAX_CONTAINER_RUNTIME_SCOPE:-}"',
                    'echo "WORKER_CONTAINER_RUNTIME_SCOPE=$RUNTIME_SCOPE"',
                ),
                "RUNTIME_SCOPE",
            ),
            "standalone": (
                bashtest.extract_block(
                    AUDIT_SCRIPTS / "cluster-audit-standalone.sh",
                    'SECURITY_DOCKER_VERSION="unknown"',
                    'DOCKER_ON_WORKERS="$DOCKER_INSTALLED"',
                ),
                "CONTAINER_RUNTIME_SCOPE",
            ),
        }
        for collector, (block, variable) in blocks.items():
            for detector_rc in (None, 0, 1):
                with self.subTest(collector=collector, detector_rc=detector_rc), tempfile.TemporaryDirectory() as tmp:
                    isolated = block.replace("/.dockerenv", f"{tmp}/.dockerenv").replace(
                        "/run/.containerenv", f"{tmp}/.containerenv"
                    )
                    run = bashtest.run_bash(
                        'CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=; DOCKER_INSTALLED=true\n'
                        + isolated + f'\nprintf "scope=%s\\n" "${variable}"'
                        + (
                            '\nprintf "docker=%s\\n" "$SECURITY_DOCKER_VERSION"'
                            if collector == "standalone" else ""
                        ),
                        stubs={
                            **({} if detector_rc is None else
                               {"systemd-detect-virt": f"exit {detector_rc}"}),
                            "docker": (
                                '[[ "$1" == version ]] && echo 29.4.3\n'
                                '[[ "$1" == --version ]] && echo 99.0.0\n:'
                            ),
                        },
                        path_only=True,
                    )
                    self.assertEqual(run.returncode, 0, run.stderr)
                    expected = "host" if detector_rc == 1 else "nested-container"
                    self.assertIn(f"scope={expected}", run.stdout.splitlines())
                    if detector_rc is not None:
                        self.assertEqual(run.calls("systemd-detect-virt"), [["--container"]])
                    if collector == "standalone":
                        self.assertIn("docker=29.4.3", run.stdout.splitlines())
                        self.assertIn(
                            ["version", "--format", "{{.Server.Version}}"],
                            run.calls("docker"),
                        )

    def test_existing_namespace_is_not_relabeled_or_deleted(self) -> None:
        run = bashtest.run_bash(
            "\n".join(
                bashtest.extract_function(self.K8S_SCRIPT, name) for name in (
                    "ensure_audit_check_namespace",
                    "cleanup_audit_check_namespace",
                    "cleanup_audit_check_pod",
                )
            )
            + '\nK8S_AUDIT_CHECK_NS=shared; K8S_AUDIT_CHECK_NS_READY=\n'
            + 'ensure_audit_check_namespace\n'
            + 'cleanup_audit_check_pod shared owned-pod\ncleanup_audit_check_namespace',
            stubs={"kubectl": ""},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.calls("kubectl"), [
            ["get", "namespace", "shared", "--request-timeout=30s"],
            ["delete", "pod", "owned-pod", "-n", "shared", "--ignore-not-found=true",
             "--wait=false", "--request-timeout=30s"],
        ])

    def test_check_deadline_without_timeout_preserves_stdin_and_status(self) -> None:
        function = bashtest.extract_function(self.K8S_SCRIPT, "check_deadline")
        for rc in (0, 7):
            with self.subTest(rc=rc):
                run = bashtest.run_bash(
                    function + "\nprintf 'worker script\\n' | check_deadline 30 kubectl exec -i worker",
                    stubs={
                        "kubectl": f'IFS= read -r line; printf "%s\\n" "$line"; exit {rc}',
                        "sleep": f'exec "{shutil.which("sleep")}" "$@"',
                    },
                    path_only=True,
                    timeout=5,
                )
                self.assertEqual(run.returncode, rc, run.stderr)
                self.assertEqual(run.stdout, "worker script\n")
                self.assertEqual(run.calls("kubectl"), [["exec", "-i", "worker"]])

    def test_ncu_timeout_is_bounded_and_cannot_report_success(self) -> None:
        block = bashtest.extract_block(
            HOST_CHECK_PATH,
            '            NCU_COUNTER_TIMEOUT_S="${AUDIT_NCU_COUNTER_TIMEOUT_S:-60}"',
            '            rm -f "$NCU_TEST_BIN"',
        )
        for rc in (124, 137):
            with self.subTest(timeout_rc=rc):
                run = bashtest.run_bash(
                    'NCU_P=ncu; NCU_TEST_BIN=/fixture/counter\n' + block,
                    stubs={"timeout": f"exit {rc}", "rm": ""},
                    env={"AUDIT_NCU_COUNTER_TIMEOUT_S": "3"},
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.strip(), "WORKER_NCU_COUNTER_ACCESS=timeout")
                self.assertEqual(run.calls("timeout")[0][:3], ["-k", "5", "3"])
                self.assertIn("/fixture/counter", run.calls("timeout")[0])

    def test_slurm_security_driver_never_uses_head_fallback(self) -> None:
        block = bashtest.extract_block(
            self.SLURM_SCRIPT, '\nGPU_MODEL="unknown"', 'if [[ "$TOTAL_GPUS" -gt 0 ]]; then'
        ).rsplit('if [[ "$TOTAL_GPUS" -gt 0 ]]; then', 1)[0]
        for worker_ok in ("false", "true"):
            with self.subTest(worker_ok=worker_ok):
                run = bashtest.run_bash(
                    self.PRINT_STUBS + 'TOTAL_GPUS=8; WORKER_DRIVER_VERSION=580.159.03\n'
                    + block
                    + '\nprintf "security=%s\\n" "$SECURITY_DRIVER_VERSION"',
                    stubs={"nvidia-smi": "echo 999.0.0"},
                    env={"WORKER_CHECK_OK": worker_ok},
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                expected = "580.159.03" if worker_ok == "true" else "unknown"
                self.assertIn(f"security={expected}", run.stdout.splitlines())
                self.assertEqual(bool(run.calls("nvidia-smi")), worker_ok == "false")

    def test_k8s_security_builder_receives_only_worker_driver(self) -> None:
        initial = bashtest.extract_block(
            self.K8S_SCRIPT, 'K8S_SECURITY_DRIVER_VERSION="unknown"', 'K8S_SECURITY_DRIVER_VERSION="unknown"'
        )
        promotion = bashtest.extract_block(
            self.K8S_SCRIPT,
            '    if [[ -n "$HP_DRIVER" && "$HP_DRIVER" != "unknown" ]]; then',
            '    fi',
        )
        call = bashtest.extract_block(
            self.K8S_SCRIPT,
            "SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit \\",
            '"$K8S_SECURITY_DOCKER_VERSION" "$GPU_VENDOR")',
        )
        for worker in ("", "unknown", "580.159.03"):
            with self.subTest(worker=worker):
                run = bashtest.run_bash(
                    'build_security_version_audit() { printf "%s\\n" "$2"; }\n'
                    + 'DRIVER_VERSION=999.0.0\n' + initial + promotion + call
                    + '\nprintf "%s\\n" "$SECURITY_VERSION_AUDIT_JSON"',
                    env={"HP_DRIVER": worker},
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.strip(), worker if worker and worker != "unknown" else "unknown")

    def test_security_json_default_stays_valid(self) -> None:
        normalization = bashtest.extract_block(
            COMMON_PATH, 'local security_version_audit_json="${SECURITY_VERSION_AUDIT_JSON:-}"',
            '[[ -n "$security_version_audit_json" ]] || security_version_audit_json="{}"',
        )
        for supplied in ("", '{"docker":{"status":"unknown"}}'):
            with self.subTest(supplied=supplied):
                run = bashtest.run_bash(
                    f'source "{COMMON_PATH}"\nnormalize_security_json() {{\n' + normalization
                    + '\nprintf "%s\\n" "$security_version_audit_json"\n}\n'
                    + 'normalize_security_json',
                    env={"SECURITY_VERSION_AUDIT_JSON": supplied},
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                expected = json.loads(supplied) if supplied else {}
                self.assertEqual(json.loads(run.stdout), expected)


class StepTmpdirContractTests(unittest.TestCase):
    def test_container_checks_forward_step_tmpdir(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        block = bashtest.extract_block(
            script,
            "AUDIT_STEP_TMPDIR_EXPORT_ARGS=()",
            "fi",
        )
        run = bashtest.run_bash(
            block + "\nprintf '%s\\n' \"${AUDIT_STEP_TMPDIR_EXPORT_ARGS[@]}\"",
            env={"CLUSTERMAX_STEP_TMPDIR": "/local/clustermax-tmp"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            run.stdout.strip(),
            "--export=ALL,CLUSTERMAX_STEP_TMPDIR=/local/clustermax-tmp,"
            "TMPDIR=/local/clustermax-tmp",
        )

    def test_enroot_import_without_timeout_receives_worker_scratch_and_status(self) -> None:
        block = bashtest.extract_block(
            AUDIT_SCRIPTS / "container-check.sh",
            'if [[ -n "${CLUSTERMAX_STEP_TMPDIR:-}" && -d "${CLUSTERMAX_STEP_TMPDIR:-}" ]]; then',
            "# Singularity and Apptainer",
        )
        tools = {
            name: f'exec "{shutil.which(name)}" "$@"'
            for name in ("grep", "head", "mktemp", "rm")
        }
        for rc, expected in ((0, "pass"), (1, "failed"), (124, "timeout")):
            with self.subTest(import_rc=rc), tempfile.TemporaryDirectory() as tmp:
                run = bashtest.run_bash(
                    block,
                    stubs={
                        **tools,
                        "enroot": (
                            '[[ "$1" == version ]] && { echo 3.4.0; exit 0; }\n'
                            '[[ "$ENROOT_TEMP_PATH" == "$CLUSTERMAX_STEP_TMPDIR" '
                            '&& "$TMPDIR" == "$CLUSTERMAX_STEP_TMPDIR" ]] || exit 99\n'
                            f"exit {rc}"
                        ),
                    },
                    env={"CLUSTERMAX_STEP_TMPDIR": tmp},
                    path_only=True,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn(f"WORKER_CONTAINER_ENROOT_IMPORT={expected}", run.stdout)
                self.assertEqual(run.calls("enroot")[1][0], "import")
                self.assertEqual(run.calls("enroot")[1][-1], "docker://hello-world")


class ContainerWorkerCheckTests(unittest.TestCase):
    def security_policy(self, check: str, *, runc: str = "1.3.3", docker: str = "29.4.3") -> dict:
        run = bashtest.run_bash(
            f'source "{COMMON_PATH}"; WORKLOAD_DIR="{AUDIT_SCRIPTS}"; '
            'build_security_version_audit "$CHECK" 580.159.03 1.19.1 "$RUNC" "$DOCKER"',
            env={"CHECK": check, "RUNC": runc, "DOCKER": docker},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_security_inventory_uses_daemon_not_client_and_hides_nested_packages(self) -> None:
        tools = {
            name: f'exec "{shutil.which(name)}" "$@"'
            for name in ("grep", "head")
        }
        for scope, daemon in (
            ("host", "29.4.3"),
            ("host", ""),
            ("nested-container", "29.4.3"),
        ):
            with self.subTest(scope=scope, daemon=daemon):
                run = bashtest.run_bash(
                    f'/bin/bash "{AUDIT_SCRIPTS / "container-check.sh"}"',
                    stubs={
                        **tools,
                        "docker": (
                            'case "$1" in\n'
                            '--version) echo "Docker version 99.0.0, build client" ;;\n'
                            'info) echo \'{"nvidia":{}}\' ;;\n'
                            f'version) printf "%s\\n" "{daemon}" ;;\nesac'
                        ),
                        "nvidia-container-toolkit": "echo 1.0.0",
                        "runc": "echo 1.0.0",
                        "hostname": "echo worker",
                    },
                    env={"CLUSTERMAX_CONTAINER_RUNTIME_SCOPE": scope, "CLUSTERMAX_AUDIT_SCOPE": "security"},
                    path_only=True,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                facts = dict(line.split("=", 1) for line in run.stdout.splitlines())
                self.assertEqual(facts["WORKER_CONTAINER_DOCKER_VERSION"], "99.0.0")
                self.assertEqual(facts["WORKER_CONTAINER_SECURITY_DOCKER_VERSION"], daemon or "unknown")
                self.assertEqual(facts["WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED"], "true")
                self.assertEqual(facts["WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION"], "1.0.0")
                expected = "1.0.0" if scope == "host" else "unknown"
                self.assertEqual(facts["WORKER_CONTAINER_SECURITY_NCT_VERSION"], expected)
                self.assertEqual(facts["WORKER_CONTAINER_SECURITY_RUNC_VERSION"], expected)
                self.assertIn(["version", "--format", "{{.Server.Version}}"], run.calls("docker"))

    def test_nerdctl_docker_compatibility_link_is_not_docker_engine(self) -> None:
        check = COMMON_PATH.parent / "container-check.sh"
        run = bashtest.run_bash(
            f'bash "{check}"',
            stubs={
                "docker": "printf 'nerdctl version 2.1.6\\n'",
                "find": "exit 0",
            },
            env={"CLUSTERMAX_CONTAINER_RUNTIME_SCOPE": "host", "CLUSTERMAX_AUDIT_SCOPE": "security"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_CONTAINER_DOCKER_INSTALLED=false", run.stdout)
        self.assertIn("WORKER_CONTAINER_SECURITY_DOCKER_VERSION=not-installed", run.stdout)
        self.assertNotIn("WORKER_CONTAINER_DOCKER_VERSION=2.1.6", run.stdout)

    def test_runtime_only_toolkit_is_installed_with_unknown_security_version(
        self,
    ) -> None:
        run = bashtest.run_bash(
            f'/bin/bash "{AUDIT_SCRIPTS / "container-check.sh"}"',
            stubs={
                "docker": (
                    'case "$1" in\n'
                    '--version) echo "Docker version 29.4.3, build test" ;;\n'
                    'info) echo \'{"nvidia":{}}\' ;;\n'
                    'version) echo 29.4.3 ;;\nesac'
                ),
                **{name: f'exec "{shutil.which(name)}" "$@"' for name in ("grep", "head", "hostname")},
            },
            env={"CLUSTERMAX_CONTAINER_RUNTIME_SCOPE": "host", "CLUSTERMAX_AUDIT_SCOPE": "security"},
            path_only=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        facts = dict(line.split("=", 1) for line in run.stdout.splitlines())
        self.assertEqual(
            facts["WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED"], "true"
        )
        self.assertEqual(
            facts["WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED"], "true"
        )
        self.assertEqual(
            facts["WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION"], "unknown"
        )
        self.assertEqual(
            facts["WORKER_CONTAINER_SECURITY_NCT_VERSION"], "unknown"
        )

    def test_security_policy_receives_only_nvidia_nic_firmware(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NIC_PCI_VENDOR_mlx5_0=0x15b3",
                "WORKER_SECURITY_NIC_FW_VER_mlx5_0=40.47.2526",
                "WORKER_SECURITY_NIC_PCI_VENDOR_efa_0=0x1d0f",
                "WORKER_SECURITY_NIC_FW_VER_efa_0=0.0.1",
            ]
        )
        runc_minimum = minimum_versions.get("components.runc.ladder")["1.3"]
        docker_minimum = minimum_versions.get("components.docker.minimum")
        security = self.security_policy(check, runc=runc_minimum, docker=docker_minimum)
        self.assertEqual(security["nvidiaDriver"]["status"], "pass")
        self.assertEqual(security["runc"]["status"], "pass")
        self.assertEqual(security["docker"]["status"], "pass")
        self.assertEqual(security["connectxFirmware"]["status"], "pass")
        self.assertEqual(len(security["connectxFirmware"]["devices"]), 1)

    def test_nic_security_policy_distinguishes_empty_from_uncollected(self) -> None:
        non_nvidia = (
            "WORKER_SECURITY_NIC_PCI_VENDOR_efa_0=0x1d0f\n"
            "WORKER_SECURITY_NIC_FW_VER_efa_0=0.0.1"
        )
        for label, check, expected in (
            ("non-nvidia", "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true\n" + non_nvidia, "not_applicable"),
            ("empty", "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", "not_applicable"),
            ("truncated", non_nvidia, "unknown"),
            ("incomplete", "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", "unknown"),
        ):
            with self.subTest(evidence=label):
                self.assertEqual(self.security_policy(check)["connectxFirmware"]["status"], expected)

    def test_unknown_nic_vendor_requires_attestation(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NIC_PCI_VENDOR_mlx5_unknown=unknown",
                "WORKER_SECURITY_NIC_FW_VER_mlx5_unknown=40.47.2526",
            ]
        )
        security = self.security_policy(check)
        self.assertEqual(security["connectxFirmware"]["status"], "unknown")
        self.assertEqual(
            security["connectxFirmware"]["devices"][0]["device"], "mlx5_unknown"
        )

class HostCheckNicInventoryTests(unittest.TestCase):
    ANCHORS = (
        "# Security inventory includes logical/bonded devices",
        'echo "WORKER_SECURITY_NIC_INVENTORY_COMPLETE='
        '${WORKER_SECURITY_NIC_INVENTORY_COMPLETE}"',
    )

    def run_inventory(
        self, root: Path, *, lspci: str | None = None, empty_path: bool = False
    ) -> bashtest.BashRun:
        host_check = COMMON_PATH.parent / "host-check.sh"
        block = (
            'SECURITY_PCI_SYSFS="${CLUSTERMAX_AUDIT_ROOT:-}/sys/bus/pci/devices"\n'
            + bashtest.extract_function(
                host_check, "security_pci_bus_confirmed_empty"
            )
            + bashtest.extract_block(host_check, *self.ANCHORS)
        )
        snippet = ('PATH="/nonexistent"\n' if empty_path else "") + block
        return bashtest.run_bash(
            snippet,
            stubs={"lspci": lspci} if lspci is not None else None,
            env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
        )

    def sysfs_root(self, devices: dict[str, tuple[str, str]] | None = None) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        if devices is None:
            return root
        for name, (vendor, firmware) in devices.items():
            device = root / "sys" / "class" / "infiniband" / name
            (device / "device").mkdir(parents=True)
            (device / "device" / "vendor").write_text(f"{vendor}\n")
            (device / "fw_ver").write_text(f"{firmware}\n")
        return root

    def test_read_rdma_tree_reports_every_device_and_completes(self) -> None:
        root = self.sysfs_root({"mlx5_0": ("0x15b3", "40.47.2526")})
        run = self.run_inventory(root)
        self.assertEqual(run.returncode, 0)
        self.assertIn("WORKER_SECURITY_NIC_PCI_VENDOR_mlx5_0=0x15b3", run.stdout)
        self.assertIn("WORKER_SECURITY_NIC_FW_VER_mlx5_0=40.47.2526", run.stdout)
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def empty_tree_root(self) -> Path:
        root = self.sysfs_root({})
        (root / "sys" / "class" / "infiniband").mkdir(parents=True)
        return root

    def test_pci_evidence_controls_absent_or_empty_rdma_inventory(self) -> None:
        clean = "0000:00:1f.0 0601: 8086:a1c1\n0000:02:00.0 0200: 1af4:1041\n"
        nvidia = "0000:03:00.0 0207: 15b3:a2dc (rev 01)\n"
        for tree, listing, expected in (
            ("empty", nvidia, "false"),
            ("empty", clean, "true"),
            ("absent", "0000:00:1f.0 0601: 8086:a1c1\n" + nvidia, "false"),
            ("absent", clean, "true"),
        ):
            with self.subTest(tree=tree, complete=expected):
                root = self.empty_tree_root() if tree == "empty" else self.sysfs_root()
                run = self.run_inventory(root, lspci=f"printf '%s' '{listing}'")
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.calls("lspci")[0], ["-n"])
                self.assertIn(f"WORKER_SECURITY_NIC_INVENTORY_COMPLETE={expected}", run.stdout)
                self.assertNotIn("WORKER_SECURITY_NIC_FW_VER_", run.stdout)

    def test_empty_rdma_tree_without_a_pci_listing_is_incomplete(self) -> None:
        for label, kwargs in (
            ("lspci fails", {"lspci": "exit 1"}),
            ("lspci is absent", {"empty_path": True}),
        ):
            with self.subTest(label):
                run = self.run_inventory(self.empty_tree_root(), **kwargs)
                self.assertIn(
                    "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout
                )

    def test_unreadable_pci_listing_is_incomplete(self) -> None:
        root = self.sysfs_root()
        run = self.run_inventory(root, lspci="exit 1")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_absent_lspci_is_incomplete(self) -> None:
        root = self.sysfs_root()
        run = self.run_inventory(root, empty_path=True)
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_corroborated_empty_pci_listing_completes(self) -> None:
        root = self.sysfs_root()
        (root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def test_uncorroborated_empty_pci_listing_stays_incomplete(self) -> None:
        root = self.sysfs_root()
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_a_populated_sysfs_bus_contradicts_an_empty_listing(self) -> None:
        root = self.sysfs_root()
        device = root / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
        device.mkdir(parents=True)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_does_not_corroborate(self) -> None:
        root = self.sysfs_root()
        bus = root / "sys" / "bus" / "pci" / "devices"
        bus.mkdir(parents=True)
        bus.chmod(0o000)
        self.addCleanup(bus.chmod, 0o755)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_pyxis_cli_check_accepts_the_registered_srun_options(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        function = bashtest.extract_function(script, "pyxis_cli_is_available")
        run = bashtest.run_bash(
            function + "\npyxis_cli_is_available",
            stubs={
                "srun": """cat <<'EOF'
  --container-image=IMAGE
                          [pyxis] the image to use for the container
EOF""",
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.calls("srun"), [["--help"]])

    def test_pyxis_cli_check_rejects_generic_container_help(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        function = bashtest.extract_function(script, "pyxis_cli_is_available")
        run = bashtest.run_bash(
            function + "\npyxis_cli_is_available",
            stubs={"srun": "echo 'container support from another plugin'"},
        )

        self.assertNotEqual(run.returncode, 0)

    def test_pyxis_version_uses_debian_package_metadata(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        function = bashtest.extract_function(script, "detect_pyxis_version")
        run = bashtest.run_bash(
            function + "\ndetect_pyxis_version",
            stubs={"dpkg-query": "printf '0.24.0-1'", "rpm": "exit 1"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "0.24.0-1")
        self.assertEqual(
            run.calls("dpkg-query"),
            [["-W", "-f=${Version}", "nvslurm-plugin-pyxis"]],
        )
        self.assertEqual(run.calls("rpm"), [])

    def test_pyxis_version_falls_back_to_rpm_package_metadata(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        function = bashtest.extract_function(script, "detect_pyxis_version")
        run = bashtest.run_bash(
            function + "\ndetect_pyxis_version",
            stubs={"dpkg-query": "exit 1", "rpm": "printf '0.23.0-2.el9'"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "0.23.0-2.el9")
        self.assertEqual(
            run.calls("rpm"),
            [["-q", "--qf", "%{VERSION}-%{RELEASE}", "nvslurm-plugin-pyxis"]],
        )

    def test_pyxis_version_is_unknown_without_package_metadata(self) -> None:
        script = COMMON_PATH.parent / "cluster-audit-slurm.sh"
        function = bashtest.extract_function(script, "detect_pyxis_version")
        run = bashtest.run_bash(
            function + "\ndetect_pyxis_version",
            stubs={
                "dpkg-query": "exit 1",
                "rpm": "printf 'package nvslurm-plugin-pyxis is not installed'; exit 1",
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "unknown")

    def test_k8s_missing_volcano_config_is_nonfatal(self) -> None:
        line = bashtest.extract_block(
            COMMON_PATH.parent / "cluster-audit-k8s.sh",
            "VOLCANO_CONF=$(kubectl get configmap volcano-scheduler-configmap",
            "volcano-scheduler",
        )
        run = bashtest.run_bash(
            "set -e\n" + line + '\nprintf \'survived=%s conf=[%s]\' ok "$VOLCANO_CONF"',
            stubs={"kubectl": "exit 1"},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("survived=ok conf=[]", run.stdout)


class SecurityBulletinIntegrationTests(unittest.TestCase):
    def run_nvlink_probe(self, topology_body: str) -> dict[str, str]:
        block = bashtest.extract_block(
            HOST_CHECK_PATH,
            "WORKER_NVIDIA_MAY_2026_PATCHED=unknown",
            'echo "WORKER_NVLINK_TOPOLOGY_CHECKED=${WORKER_NVLINK_TOPOLOGY_CHECKED}"',
        )
        nvidia_smi = (
            'if [[ "$*" == "--query-gpu=driver_version --format=csv,noheader" ]]; '
            "then printf '580.159.03\\n'; exit 0; fi\n"
            'if [[ "$*" == "topo -m" ]]; then\n'
            f"{topology_body}\n"
            "exit $?\n"
            "fi\n"
            "exit 1"
        )
        run = bashtest.run_bash(block, stubs={"nvidia-smi": nvidia_smi})
        self.assertEqual(run.returncode, 0, run.stderr)
        return dict(
            line.split("=", 1)
            for line in run.stdout.splitlines()
            if line.startswith("WORKER_NVLINK_")
        )

    def test_nvlink_probe_distinguishes_absence_from_a_failed_read(self) -> None:
        failed = self.run_nvlink_probe("exit 1")
        self.assertEqual(failed["WORKER_NVLINK_EXPOSED"], "unknown")
        self.assertEqual(failed["WORKER_NVLINK_TOPOLOGY_CHECKED"], "false")

        absent = self.run_nvlink_probe(
            "printf 'GPU0\\tGPU1\\nGPU0\\tX\\tPHB\\nGPU1\\tPHB\\tX\\n'"
        )
        self.assertEqual(absent["WORKER_NVLINK_EXPOSED"], "false")
        self.assertEqual(absent["WORKER_NVLINK_TOPOLOGY_CHECKED"], "true")

    def test_nvlink_probe_detects_an_sxm_link(self) -> None:
        present = self.run_nvlink_probe(
            "printf 'GPU0\\tGPU1\\nGPU0\\tX\\tNV18\\nGPU1\\tNV18\\tX\\n'"
        )
        self.assertEqual(present["WORKER_NVLINK_EXPOSED"], "true")
        self.assertEqual(present["WORKER_NVLINK_TOPOLOGY_CHECKED"], "true")

    def collector_januscape_exposed(self, collector: str, check_value: str):
        workload = COMMON_PATH.parent
        if collector == "k8s":
            call = bashtest.extract_block(
                workload / "cluster-audit-k8s.sh",
                "SECURITY_ADVISORY_JSON=$(build_security_advisory_json \\",
                '--vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")',
            )
            setup = (
                f'HP_JANUSCAPE_EXPOSED="{check_value}"\n'
                'HP_JANUSCAPE_EXPOSED_JSON=$(json_bool_or_unknown "$HP_JANUSCAPE_EXPOSED")\n'
            )
            emit = '\nprintf "%s\\n" "$SECURITY_ADVISORY_JSON"\n'
        else:
            call = bashtest.extract_block(
                COMMON_PATH,
                "security_advisory_json=$(build_security_advisory_json \\",
                '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")',
            )
            setup = (
                f'WORKER_JANUSCAPE_EXPOSED="{check_value}"\n'
                'januscape_exposed_json=$(json_bool_or_unknown "${WORKER_JANUSCAPE_EXPOSED:-}")\n'
            )
            emit = '\nprintf "%s\\n" "$security_advisory_json"\n'

        run = bashtest.run_bash(
            f'source "{COMMON_PATH}"\n' + setup + call + emit
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        members = json.loads("{" + run.stdout + '"sentinel": true}')
        return members["januscape"]["exposed"]

    def test_missing_host_check_keeps_januscape_unknown(self) -> None:
        for collector in ("common", "k8s"):
            with self.subTest(collector=collector):
                self.assertEqual(
                    self.collector_januscape_exposed(collector, ""), "unknown"
                )
                self.assertIs(
                    self.collector_januscape_exposed(collector, "true"), True
                )
                self.assertIs(
                    self.collector_januscape_exposed(collector, "false"), False
                )


class K8sTopologyAuditTests(unittest.TestCase):
    K8S_SCRIPT = COMMON_PATH.parent / "cluster-audit-k8s.sh"

    def test_ncu_live_access_sets_the_effective_profiling_result(self) -> None:
        block = bashtest.extract_block(
            self.K8S_SCRIPT,
            '    case "$NCU_COUNTER_ACCESS" in',
            "    esac",
        )
        snippet = (
            "print_info() { :; }\n"
            "print_error() { :; }\n"
            "print_detail() { :; }\n"
            "print_warn() { :; }\n"
            'NCU_PROFILING_ENABLED="$1"\n'
            'NCU_COUNTER_ACCESS="$2"\n'
            + block
            + '\nprintf "%s\\n" "$NCU_PROFILING_ENABLED"\n'
        )

        denied = bashtest.run_bash(
            'set -- true denied\n' + snippet,
            timeout=5,
        )
        granted = bashtest.run_bash(
            'set -- false granted\n' + snippet,
            timeout=5,
        )

        self.assertEqual(granted.returncode, 0, granted.stderr)
        self.assertEqual(denied.returncode, 0, denied.stderr)
        self.assertEqual(granted.stdout.strip(), "true")
        self.assertEqual(denied.stdout.strip(), "false")

    def test_k8s_control_helpers_do_not_enable_audit_nounset_or_pipefail(self) -> None:
        function = bashtest.extract_function(
            self.K8S_SCRIPT, "k8s_audit_source_control_helpers"
        )
        snippet = function + """
set -e
WORKLOAD_DIR="$AUDIT_WORKLOAD_DIR"
k8s_audit_source_control_helpers
if [[ $- == *u* ]]; then echo nounset=on; else echo nounset=off; fi
if [[ $(set -o | awk '$1 == "pipefail" {print $2}') == on ]]; then
    echo pipefail=on
else
    echo pipefail=off
fi
"""
        run = bashtest.run_bash(
            snippet,
            env={"AUDIT_WORKLOAD_DIR": str(self.K8S_SCRIPT.parent)},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), ["nounset=off", "pipefail=off"])

    def test_gpu_dra_inventory_promotes_only_schedulable_workers(self) -> None:
        functions = "\n".join(
            [
                bashtest.extract_function(
                    self.K8S_SCRIPT, "k8s_audit_dra_gpu_counts"
                ),
                bashtest.extract_function(
                    self.K8S_SCRIPT, "k8s_audit_inject_dra_gpu_capacity"
                ),
            ]
        )
        nodes = {
            "items": [
                {
                    "metadata": {"name": "gpu-ready", "labels": {}},
                    "spec": {},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "capacity": {},
                        "allocatable": {},
                    },
                },
                {
                    "metadata": {"name": "gpu-cordoned", "labels": {}},
                    "spec": {"unschedulable": True},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "capacity": {},
                        "allocatable": {},
                    },
                },
                {
                    "metadata": {
                        "name": "control",
                        "labels": {"node-role.kubernetes.io/control-plane": ""},
                    },
                    "spec": {},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "capacity": {},
                        "allocatable": {},
                    },
                },
            ]
        }
        slices = {
            "items": [
                {
                    "spec": {
                        "driver": "gpu.nvidia.com",
                        "nodeName": node,
                        "devices": [{"name": str(index)} for index in range(count)],
                    }
                }
                for node, count in (
                    ("gpu-ready", 4),
                    ("gpu-cordoned", 8),
                    ("control", 4),
                )
            ]
        }
        snippet = functions + """
counts=$(k8s_audit_dra_gpu_counts "$NODES_SLICES" gpu.nvidia.com)
k8s_audit_inject_dra_gpu_capacity "$NODES_JSON" "$counts"
"""
        run = bashtest.run_bash(
            snippet,
            env={
                "NODES_JSON": json.dumps(nodes),
                "NODES_SLICES": json.dumps(slices),
            },
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        result = {item["metadata"]["name"]: item for item in json.loads(run.stdout)["items"]}
        self.assertEqual(
            result["gpu-ready"]["status"]["allocatable"]["nvidia.com/gpu"],
            "4",
        )
        self.assertNotIn("nvidia.com/gpu", result["gpu-cordoned"]["status"]["capacity"])
        self.assertNotIn("nvidia.com/gpu", result["control"]["status"]["capacity"])

    def test_gpu_dra_allocations_are_subtracted_from_free_capacity(self) -> None:
        functions = "\n".join(
            bashtest.extract_function(self.K8S_SCRIPT, name)
            for name in (
                "k8s_audit_scalar_gpu_alloc_by_node",
                "k8s_audit_dra_gpu_alloc_by_node",
                "k8s_audit_merge_gpu_allocations",
            )
        )
        pods = {
            "items": [
                {
                    "metadata": {"uid": "dra-pod"},
                    "spec": {"nodeName": "gpu-1", "containers": [{}]},
                    "status": {"phase": "Running"},
                },
                {
                    "metadata": {"uid": "scalar-pod"},
                    "spec": {
                        "nodeName": "gpu-1",
                        "containers": [
                            {"resources": {"limits": {"nvidia.com/gpu": "1"}}}
                        ],
                    },
                    "status": {"phase": "Running"},
                },
            ]
        }
        claims = {
            "items": [
                {
                    "status": {
                        "reservedFor": [{"resource": "pods", "uid": "dra-pod"}],
                        "allocation": {
                            "devices": {
                                "results": [
                                    {"driver": "gpu.nvidia.com", "device": "gpu-0"},
                                    {"driver": "gpu.nvidia.com", "device": "gpu-1"},
                                    {"driver": "dra.net", "device": "nic-0"},
                                ]
                            }
                        },
                    }
                }
            ]
        }
        snippet = functions + """
scalar=$(k8s_audit_scalar_gpu_alloc_by_node "$PODS_JSON" nvidia.com/gpu)
dra=$(k8s_audit_dra_gpu_alloc_by_node "$PODS_JSON" "$CLAIMS_JSON" gpu.nvidia.com)
k8s_audit_merge_gpu_allocations "$scalar" "$dra"
"""
        run = bashtest.run_bash(
            snippet,
            env={"PODS_JSON": json.dumps(pods), "CLAIMS_JSON": json.dumps(claims)},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {"gpu-1": 3})

    def test_gpu_dra_check_renders_a_claim_and_scheduler_node_selector(self) -> None:
        function = bashtest.extract_function(self.K8S_SCRIPT, "apply_gpu_check_pod")
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "applied.yaml"
            snippet = bashtest.extract_function(self.K8S_SCRIPT, "audit_node_is_live_check_target") + "\n" + function + """
ensure_audit_check_namespace() { return 0; }
check_log() { return 0; }
audit_check_wait_ready() { return 0; }
cleanup_audit_check_pod() { return 0; }
k8s_gpu_dra_enabled() { return 0; }
k8s_ensure_gpu_dra_claim_template() { echo cmax-gpu-dra-1; }
K8S_AUDIT_CHECK_NS=test-ns
GPU_RESOURCE_KEY=nvidia.com/gpu
apply_gpu_check_pod gpu-1 cuda:test
"""
            run = bashtest.run_bash(
                snippet,
                stubs={"kubectl": 'cat > "$APPLIED_MANIFEST"'},
                env={"APPLIED_MANIFEST": str(manifest)},
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            applied = manifest.read_text()
            self.assertIn("resourceClaimTemplateName: cmax-gpu-dra-1", applied)
            self.assertIn("kubernetes.io/hostname: gpu-1", applied)
            self.assertIn("claims:\n      - name: gpu", applied)
            self.assertNotIn("nodeName: gpu-1", applied)
            self.assertNotIn("nvidia.com/gpu: \"1\"", applied)


class HostCheckVirtualizationTests(unittest.TestCase):
    ANCHORS = (
        "# --- Hypervisor security bulletins (read-only, never triggers a PoC) ---",
        'echo "WORKER_IOMMU_GROUPS=${WORKER_IOMMU_GROUPS}"',
    )
    REAL_TOOLS = ("grep", "cat", "find", "wc", "tr", "uname")
    X86 = "printf 'x86_64\\n'"

    def tools_dir(self) -> Path:
        path = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, path, True)
        for tool in self.REAL_TOOLS:
            located = shutil.which(tool)
            if located:
                (path / tool).symlink_to(located)
        return path

    def make_root(
        self,
        *,
        cpuinfo: str | None = None,
        kvm_device: bool = False,
        nested: str | None = None,
    ) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        if cpuinfo is not None:
            (root / "proc").mkdir(parents=True)
            (root / "proc" / "cpuinfo").write_text(cpuinfo)
        if kvm_device:
            (root / "dev").mkdir(parents=True, exist_ok=True)
            (root / "dev" / "kvm").write_text("")
        if nested is not None:
            parameters = root / "sys" / "module" / "kvm_intel" / "parameters"
            parameters.mkdir(parents=True)
            (parameters / "nested").write_text(f"{nested}\n")
        return root

    def run_virt(
        self,
        root: Path,
        *,
        detect_virt: str | None = None,
        uname: str | None = None,
    ) -> dict[str, str]:
        block = bashtest.extract_block(
            COMMON_PATH.parent / "host-check.sh", *self.ANCHORS
        )
        stubs = {"uname": uname or self.X86}
        snippet = block
        if detect_virt is None:
            snippet = f'PATH="${{PATH%%:*}}:{self.tools_dir()}"\n' + block
        else:
            stubs["systemd-detect-virt"] = detect_virt
        run = bashtest.run_bash(
            snippet, stubs=stubs, env={"CLUSTERMAX_AUDIT_ROOT": str(root)}
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return dict(
            line.split("=", 1) for line in run.stdout.splitlines() if "=" in line
        )

    def test_absent_detect_virt_leaves_virtualization_unknown(self) -> None:
        facts = self.run_virt(self.make_root())
        self.assertEqual(facts["WORKER_VIRT_TYPE"], "unknown")
        self.assertEqual(facts["WORKER_VIRT_GUEST"], "unknown")
        self.assertEqual(facts["WORKER_VIRT_DETECTION"], "none")

    def test_detect_virt_naming_kvm_is_unchanged(self) -> None:
        facts = self.run_virt(self.make_root(), detect_virt="printf 'kvm\\n'")
        self.assertEqual(facts["WORKER_VIRT_TYPE"], "kvm")
        self.assertEqual(facts["WORKER_VIRT_GUEST"], "true")
        self.assertEqual(facts["WORKER_VIRT_DETECTION"], "systemd-detect-virt")

    def test_detect_virt_reporting_bare_metal_is_unchanged(self) -> None:
        facts = self.run_virt(
            self.make_root(), detect_virt="printf 'none\\n'\nexit 1"
        )
        self.assertEqual(facts["WORKER_VIRT_TYPE"], "none")
        self.assertEqual(facts["WORKER_VIRT_GUEST"], "false")

    def test_detect_virt_failing_otherwise_is_not_bare_metal(self) -> None:
        facts = self.run_virt(self.make_root(), detect_virt="exit 2")
        self.assertEqual(facts["WORKER_VIRT_TYPE"], "unknown")
        self.assertEqual(facts["WORKER_VIRT_GUEST"], "unknown")

    def test_cpuinfo_fallback_concludes_only_in_the_positive_direction(self) -> None:
        guest = self.run_virt(
            self.make_root(cpuinfo="flags\t: fpu vme hypervisor lm\n")
        )
        self.assertEqual(guest["WORKER_VIRT_GUEST"], "true")
        self.assertEqual(guest["WORKER_VIRT_DETECTION"], "cpuinfo-hypervisor")
        self.assertEqual(guest["WORKER_VIRT_TYPE"], "unknown")

        silent = self.run_virt(self.make_root(cpuinfo="flags\t: fpu vme lm\n"))
        self.assertEqual(silent["WORKER_VIRT_GUEST"], "unknown")
        self.assertEqual(silent["WORKER_VIRT_TYPE"], "unknown")
        self.assertEqual(silent["WORKER_VIRT_DETECTION"], "none")

    def test_unclassified_platform_does_not_conclude_januscape_is_clean(self) -> None:
        root = self.make_root(
            cpuinfo="flags\t: fpu vme vmx lm\n", kvm_device=True, nested="1"
        )
        facts = self.run_virt(root)
        self.assertEqual(facts["WORKER_JANUSCAPE_EXPOSED"], "unknown")
        self.assertEqual(facts["WORKER_JANUSCAPE_STATUS"], "unknown")

    def test_januscape_verdicts_on_a_classified_platform_are_unchanged(self) -> None:
        root = self.make_root(
            cpuinfo="flags\t: fpu vme vmx lm\n", kvm_device=True, nested="1"
        )
        exposed = self.run_virt(root, detect_virt="printf 'kvm\\n'")
        self.assertEqual(exposed["WORKER_JANUSCAPE_EXPOSED"], "true")
        self.assertEqual(exposed["WORKER_JANUSCAPE_STATUS"], "host-patch-required")

        bare = self.run_virt(root, detect_virt="printf 'none\\n'\nexit 1")
        self.assertEqual(bare["WORKER_JANUSCAPE_EXPOSED"], "false")
        self.assertEqual(bare["WORKER_JANUSCAPE_STATUS"], "not-exposed")

    def test_nested_kvm_reported_off_stays_a_confident_not_exposed(self) -> None:
        root = self.make_root(
            cpuinfo="flags\t: fpu vme vmx lm\n", kvm_device=True, nested="0"
        )
        facts = self.run_virt(root)
        self.assertEqual(facts["WORKER_NESTED_ENABLED"], "false")
        self.assertEqual(facts["WORKER_JANUSCAPE_EXPOSED"], "false")


class HostCheckGpuInventoryTests(unittest.TestCase):
    ANCHORS = (
        "# Local PCI security inventory is independent of the scale-out fabric.",
        'echo "WORKER_SECURITY_NVIDIA_GPU_PRESENT='
        '${WORKER_SECURITY_NVIDIA_GPU_PRESENT}"',
    )

    def run_inventory(
        self, root: Path, *, lspci: str | None = None, empty_path: bool = False
    ) -> bashtest.BashRun:
        block = bashtest.extract_block(
            AUDIT_SCRIPTS / "host-check.sh", *self.ANCHORS
        )
        snippet = ('PATH="/nonexistent"\n' if empty_path else "") + block
        return bashtest.run_bash(
            snippet,
            stubs={"lspci": lspci} if lspci is not None else None,
            env={"CLUSTERMAX_AUDIT_ROOT": str(root)},
        )

    def make_root(self, *, empty_pci_bus: bool = False) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        if empty_pci_bus:
            (root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)
        return root

    def facts(self, run: bashtest.BashRun) -> dict[str, str]:
        return dict(
            line.split("=", 1)
            for line in run.stdout.splitlines()
            if line.startswith("WORKER_SECURITY_GPU_")
            or line.startswith("WORKER_SECURITY_NVIDIA_")
        )

    def test_gpu_inventory_preserves_present_absent_and_unknown(self) -> None:
        for label, empty_bus, listing, complete, present in (
            ("nvidia", False, "0000:00:1f.0 0601: 8086:a1c1\n0000:07:00.0 0302: 10de:2901\n", "true", "true"),
            ("no-nvidia", False, "0000:00:1f.0 0601: 8086:a1c1\n0000:02:00.0 0200: 1af4:1041\n", "true", "false"),
            ("empty-confirmed", True, "", "true", "false"),
            ("empty-unconfirmed", False, "", "false", "unknown"),
        ):
            with self.subTest(evidence=label):
                facts = self.facts(self.run_inventory(
                    self.make_root(empty_pci_bus=empty_bus),
                    lspci=f"printf '%s' '{listing}'",
                ))
                self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], complete)
                self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], present)

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_stays_unknown(self) -> None:
        root = self.make_root(empty_pci_bus=True)
        bus = root / "sys" / "bus" / "pci" / "devices"
        bus.chmod(0o000)
        self.addCleanup(bus.chmod, 0o755)
        facts = self.facts(self.run_inventory(root, lspci="exit 0"))
        self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "false")
        self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "unknown")

    def test_a_failed_or_missing_lspci_stays_unknown(self) -> None:
        for label, kwargs in (
            ("lspci fails", {"lspci": "exit 1"}),
            ("lspci is absent", {"empty_path": True}),
        ):
            with self.subTest(label):
                facts = self.facts(
                    self.run_inventory(
                        self.make_root(empty_pci_bus=True), **kwargs
                    )
                )
                self.assertEqual(
                    facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "false"
                )
                self.assertEqual(
                    facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "unknown"
                )


class BuildSecurityAuditGpuAbsenceTests(unittest.TestCase):
    def build_security(self, check: str) -> dict:
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" unknown unknown unknown unknown'
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                command,
                "bash",
                str(COMMON_PATH),
                str(COMMON_PATH.parent),
                check,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_unanimous_absence_grades_the_driver_not_applicable(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NVIDIA_GPU_PRESENT=false",
            ]
        )
        security = self.build_security(check)
        self.assertEqual(security["nvidiaDriver"]["status"], "not_applicable")
        self.assertIn("No NVIDIA GPU is present", security["nvidiaDriver"]["detail"])

    def test_any_incomplete_host_keeps_the_driver_unknown(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NVIDIA_GPU_PRESENT=false",
                "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=false",
                "WORKER_SECURITY_NVIDIA_GPU_PRESENT=unknown",
            ]
        )
        security = self.build_security(check)
        self.assertEqual(security["nvidiaDriver"]["status"], "unknown")

    def test_any_present_host_keeps_the_driver_unknown(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NVIDIA_GPU_PRESENT=false",
                "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NVIDIA_GPU_PRESENT=true",
            ]
        )
        security = self.build_security(check)
        self.assertEqual(security["nvidiaDriver"]["status"], "unknown")

    def test_a_check_without_the_keys_keeps_the_driver_unknown(self) -> None:
        security = self.build_security("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true")
        self.assertEqual(security["nvidiaDriver"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
