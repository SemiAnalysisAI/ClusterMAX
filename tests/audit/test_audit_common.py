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


# The version policy grades against the generated minimum table, so these tests
# read the sample versions from that table instead of restating a minimum that a
# daily refresh can move.
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
            + "\nGPU_NODE_COUNT=3; GPU_NODE_NAMES='gpu-a gpu-b gpu-c'\n"
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
        self.assertEqual(selected["full"], set(run_checks.CHECK_PROFILES))

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
                    "printf 'cw-nvidia-gpu-operator'; fi"
                )
            },
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "cw-nvidia-gpu-operator")

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
                    {"metadata": {"name": "cw-nvidia-gpu-operator"}},
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
        self.assertEqual(run.stdout.strip(), "cw-nvidia-gpu-operator")

    def test_supplemental_checks_select_branded_gpu_operator_namespace(self) -> None:
        self.assertEqual(
            run_checks.select_gpu_operator_namespace(
                ["default", "cw-nvidia-gpu-operator", "kube-system"]
            ),
            "cw-nvidia-gpu-operator",
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
        self.assertEqual(profile["status"], "manual")
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


class SlurmGpuTargetingTests(unittest.TestCase):
    def test_gpu_checks_never_retry_without_gres(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()

        self.assertNotIn("retrying without GPU request", script)
        self.assertNotIn("Prolog runtime (no GPU req)", script)
        self.assertIn("--gres=gpu:1 --time=1:00", script)


class StepTmpdirContractTests(unittest.TestCase):
    """The audit container checks must honor CLUSTERMAX_STEP_TMPDIR.

    The bench launcher (bench/harnesses/slurm/default.sbatch) forwards the
    operator's CLUSTERMAX_STEP_TMPDIR as TMPDIR to every workload srun so
    enroot can extract images on clusters whose worker /tmp is an overlayfs pod
    root. The audit's enroot import check must apply the same knob, or it can
    report a broken container runtime that the campaign does not have.
    """

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

    def test_enroot_import_check_honors_step_tmpdir(self) -> None:
        check = (COMMON_PATH.parent / "container-check.sh").read_text()

        self.assertIn('export ENROOT_TEMP_PATH="$CLUSTERMAX_STEP_TMPDIR"', check)
        self.assertIn('export TMPDIR="$CLUSTERMAX_STEP_TMPDIR"', check)


class SlurmAuditParsingTests(unittest.TestCase):
    def test_ncu_version_parser_accepts_capitalized_version_output(self) -> None:
        workload_dir = COMMON_PATH.parent
        host_check = (workload_dir / "host-check.sh").read_text()
        slurm = (workload_dir / "cluster-audit-slurm.sh").read_text()

        expected = "grep -oiP 'version\\s+\\K[0-9.]+'"
        self.assertIn(expected, host_check)
        self.assertIn(expected, slurm)

    def test_dcgm_version_parser_ignores_leading_blank_line(self) -> None:
        host_check = (COMMON_PATH.parent / "host-check.sh").read_text()

        self.assertIn(
            "grep -m1 -v '^[[:space:]]*$'",
            host_check,
        )

    def test_ncu_live_counter_check_has_hard_timeout(self) -> None:
        workload_dir = COMMON_PATH.parent
        host_check = (workload_dir / "host-check.sh").read_text()
        slurm = (workload_dir / "cluster-audit-slurm.sh").read_text()

        self.assertIn('AUDIT_NCU_COUNTER_TIMEOUT_S:-60', host_check)
        self.assertIn('timeout -k 5 "$NCU_COUNTER_TIMEOUT_S"', host_check)
        self.assertIn('WORKER_NCU_COUNTER_ACCESS=timeout', host_check)
        self.assertIn('Hardware counters: TIMED OUT', slurm)

    def test_dcgm_slurm_integration_inspects_worker_health_plugins(self) -> None:
        workload_dir = COMMON_PATH.parent
        host_check = (workload_dir / "host-check.sh").read_text()
        slurm = (workload_dir / "cluster-audit-slurm.sh").read_text()

        self.assertIn('WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE', host_check)
        self.assertIn('find -L "$WORKER_HEALTH_PLUGIN_DIR"', host_check)
        self.assertIn('-type f -perm -u+x', host_check)
        self.assertIn('HealthCheckProgram plugin:', slurm)

    def test_nhc_detection_falls_back_to_worker_check(self) -> None:
        workload_dir = COMMON_PATH.parent
        host_check = (workload_dir / "host-check.sh").read_text()
        slurm = (workload_dir / "cluster-audit-slurm.sh").read_text()

        self.assertIn("WORKER_NHC_INSTALLED=", host_check)
        self.assertIn("WORKER_NHC_PATH=", host_check)
        self.assertIn("WORKER_NHC_CONF_CHECKS=", host_check)
        self.assertIn('"$WORKER_NHC_INSTALLED" == "true"', slurm)
        self.assertIn("compute node ${WORKER_HOSTNAME}; not on head node", slurm)

    def test_prolog_parser_accepts_indexed_slurm_25_keys(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()

        self.assertIn("/^Prolog(\\[[0-9]+\\])?$/", script)
        self.assertIn("/^Epilog(\\[[0-9]+\\])?$/", script)


class ContainerWorkerCheckTests(unittest.TestCase):
    def test_nerdctl_docker_compatibility_link_is_not_docker_engine(self) -> None:
        check = COMMON_PATH.parent / "container-check.sh"
        run = bashtest.run_bash(
            f'bash "{check}"',
            stubs={
                "docker": "printf 'nerdctl version 2.1.6\\n'",
                "find": "exit 0",
            },
            env={"CLUSTERMAX_CONTAINER_RUNTIME_SCOPE": "host"},
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_CONTAINER_DOCKER_INSTALLED=false", run.stdout)
        self.assertIn("WORKER_CONTAINER_SECURITY_DOCKER_VERSION=not-installed", run.stdout)
        self.assertNotIn("WORKER_CONTAINER_DOCKER_VERSION=2.1.6", run.stdout)

    def test_runtime_only_toolkit_is_installed_with_unknown_security_version(
        self,
    ) -> None:
        check = COMMON_PATH.parent / "container-check.sh"
        with tempfile.TemporaryDirectory() as tmp:
            mock_bin = Path(tmp)
            docker = mock_bin / "docker"
            docker.write_text(
                """#!/bin/bash
case "$1" in
    --version)
        echo "Docker version 29.4.3, build test"
        ;;
    info)
        printf '{"nvidia":{}}\\n'
        ;;
    version)
        echo "29.4.3"
        ;;
esac
"""
            )
            docker.chmod(0o755)
            for command in ("dpkg-query", "rpm"):
                stub = mock_bin / command
                stub.write_text("#!/bin/bash\nexit 1\n")
                stub.chmod(0o755)
            for command in ("grep", "head", "hostname"):
                system_command = shutil.which(command)
                self.assertIsNotNone(system_command)
                (mock_bin / command).symlink_to(system_command)

            env = os.environ.copy()
            env["PATH"] = str(mock_bin)
            env["CLUSTERMAX_CONTAINER_RUNTIME_SCOPE"] = "host"
            result = subprocess.run(
                ["/bin/bash", str(check)],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

        facts = dict(
            line.split("=", 1)
            for line in result.stdout.splitlines()
            if line.startswith("WORKER_CONTAINER_")
        )
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

    def test_runtime_scope_detection_fails_closed_without_findmnt(self) -> None:
        check = (COMMON_PATH.parent / "container-check.sh").read_text()
        standalone = (COMMON_PATH.parent / "cluster-audit-standalone.sh").read_text()

        self.assertIn('RUNTIME_SCOPE="nested-container"', check)
        self.assertIn('CONTAINER_RUNTIME_SCOPE="nested-container"', standalone)
        self.assertIn("systemd-detect-virt --container", check)
        self.assertIn("systemd-detect-virt --container", standalone)
        self.assertNotIn('ROOT_FS_TYPE=""', check)
        self.assertNotIn('ROOT_FS_TYPE=""', standalone)

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
        # The runc rung moves whenever upstream ships a fix, so read it from
        # the minimum table. `get` splits on dots, so the branch key is indexed
        # after the lookup.
        runc_minimum = minimum_versions.get("components.runc.ladder")["1.3"]
        docker_minimum = minimum_versions.get("components.docker.minimum")
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            f'build_security_version_audit "$3" 580.159.03 1.19.1 '
            f'{runc_minimum} {docker_minimum}'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["nvidiaDriver"]["status"], "pass")
        self.assertEqual(security["runc"]["status"], "pass")
        self.assertEqual(security["docker"]["status"], "pass")
        self.assertEqual(security["connectxFirmware"]["status"], "pass")
        self.assertEqual(len(security["connectxFirmware"]["devices"]), 1)

    def test_complete_non_nvidia_inventory_is_not_applicable(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NIC_PCI_VENDOR_efa_0=0x1d0f",
                "WORKER_SECURITY_NIC_FW_VER_efa_0=0.0.1",
            ]
        )
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" 580.159.03 1.19.1 1.3.3 29.4.3'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["connectxFirmware"]["status"], "not_applicable")

    def test_complete_empty_nic_inventory_is_not_applicable(self) -> None:
        check = "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true"
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" 580.159.03 1.19.1 1.3.3 29.4.3'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["connectxFirmware"]["status"], "not_applicable")

    def test_unknown_nic_vendor_requires_attestation(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true",
                "WORKER_SECURITY_NIC_PCI_VENDOR_mlx5_unknown=unknown",
                "WORKER_SECURITY_NIC_FW_VER_mlx5_unknown=40.47.2526",
            ]
        )
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" 580.159.03 1.19.1 1.3.3 29.4.3'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["connectxFirmware"]["status"], "unknown")
        self.assertEqual(
            security["connectxFirmware"]["devices"][0]["device"], "mlx5_unknown"
        )

    def test_truncated_non_nvidia_inventory_remains_unknown(self) -> None:
        check = "\n".join(
            [
                "WORKER_SECURITY_NIC_PCI_VENDOR_efa_0=0x1d0f",
                "WORKER_SECURITY_NIC_FW_VER_efa_0=0.0.1",
            ]
        )
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" 580.159.03 1.19.1 1.3.3 29.4.3'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["connectxFirmware"]["status"], "unknown")

    def test_incomplete_nic_inventory_flag_is_not_a_clean_host(self) -> None:
        # The other half of the host-check contract below: "false" must reach
        # the evaluator as no claim at all, exactly like a missing key, because
        # only a complete inventory may report not_applicable.
        check = "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false"
        command = (
            'source "$1"; WORKLOAD_DIR="$2"; '
            'build_security_version_audit "$3" 580.159.03 1.19.1 1.3.3 29.4.3'
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
        security = json.loads(result.stdout)
        self.assertEqual(security["connectxFirmware"]["status"], "unknown")


class HostCheckNicInventoryTests(unittest.TestCase):
    """The NIC firmware inventory block of host-check.sh, run for real.

    `WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true` is the only input that lets
    `aggregate_connectx` report not_applicable, which the security report
    renders as a pass. These tests drive the block against a fixture sysfs tree
    and a stub lspci, so the flag is asserted from behavior rather than from
    the source text.
    """

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
        # A PATH with no tools at all is how "lspci is not installed" is made
        # deterministic on a runner that has pciutils.
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

    def test_empty_rdma_tree_with_an_nvidia_nic_is_incomplete(self) -> None:
        # ib_core creates the directory as a dependency of the rdma-core stack
        # even when no HCA driver is bound, so a present but empty tree is what
        # an unloaded or blacklisted mlx5_ib looks like. The card and its
        # bulletin-covered firmware are still on the bus. Completing the
        # inventory here graded that host not_applicable, which reads as a pass.
        root = self.empty_tree_root()
        listing = "0000:03:00.0 0207: 15b3:a2dc (rev 01)\n"
        run = self.run_inventory(root, lspci=f"printf '%s' '{listing}'")
        self.assertNotIn("WORKER_SECURITY_NIC_FW_VER_", run.stdout)
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)
        self.assertNotIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def test_empty_rdma_tree_completes_on_a_clean_pci_listing(self) -> None:
        root = self.empty_tree_root()
        listing = "0000:00:1f.0 0601: 8086:a1c1\n0000:02:00.0 0200: 1af4:1041\n"
        run = self.run_inventory(root, lspci=f"printf '%s' '{listing}'")
        self.assertEqual(run.calls("lspci")[0], ["-n"])
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

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

    def test_absent_rdma_tree_with_an_nvidia_nic_is_incomplete(self) -> None:
        # The defect this guards: no /sys/class/infiniband is what an unloaded
        # ib_core looks like, and the card is still there with its firmware.
        # Reporting a complete inventory graded that host not_applicable, and
        # the report showed a pass for a NIC nobody read.
        root = self.sysfs_root()
        listing = (
            "0000:00:1f.0 0601: 8086:a1c1\n"
            "0000:03:00.0 0207: 15b3:a2dc (rev 01)\n"
        )
        run = self.run_inventory(root, lspci=f"printf '%s' '{listing}'")
        self.assertEqual(run.calls("lspci")[0], ["-n"])
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)
        self.assertNotIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def test_pci_listing_without_an_nvidia_device_completes(self) -> None:
        root = self.sysfs_root()
        listing = "0000:00:1f.0 0601: 8086:a1c1\n0000:02:00.0 0200: 1af4:1041\n"
        run = self.run_inventory(root, lspci=f"printf '%s' '{listing}'")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def test_unreadable_pci_listing_is_incomplete(self) -> None:
        root = self.sysfs_root()
        run = self.run_inventory(root, lspci="exit 1")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_absent_lspci_is_incomplete(self) -> None:
        root = self.sysfs_root()
        run = self.run_inventory(root, empty_path=True)
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_corroborated_empty_pci_listing_completes(self) -> None:
        # A VM with no PCI device at all: lspci exits cleanly with nothing to
        # print, and the kernel's own bus tree is readable and empty. Two
        # independent readers agreeing on zero devices is a read bus, and a
        # read bus with no device on it carries no bulletin-covered firmware.
        root = self.sysfs_root()
        (root / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true", run.stdout)

    def test_uncorroborated_empty_pci_listing_stays_incomplete(self) -> None:
        # Without the sysfs corroboration, an empty listing on its own is
        # indistinguishable from a broken lspci, so the bus stays unread.
        root = self.sysfs_root()
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_a_populated_sysfs_bus_contradicts_an_empty_listing(self) -> None:
        # sysfs holding a device while lspci printed nothing means lspci
        # failed to read the bus, not that the bus is empty.
        root = self.sysfs_root()
        device = root / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
        device.mkdir(parents=True)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_does_not_corroborate(self) -> None:
        # A directory that exists but cannot be listed produces the same blank
        # capture as an empty one; only a successful read that returned
        # nothing may claim the bus is empty.
        root = self.sysfs_root()
        bus = root / "sys" / "bus" / "pci" / "devices"
        bus.mkdir(parents=True)
        bus.chmod(0o000)
        self.addCleanup(bus.chmod, 0o755)
        run = self.run_inventory(root, lspci="exit 0")
        self.assertIn("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false", run.stdout)

    def test_container_security_check_never_uses_docker_cli_version(self) -> None:
        check = (COMMON_PATH.parent / "container-check.sh").read_text()
        self.assertIn(
            'SECURITY_DOCKER_VERSION="${DOCKER_SERVER_VERSION:-unknown}"', check
        )
        self.assertNotIn(
            'SECURITY_DOCKER_VERSION="${DOCKER_SERVER_VERSION:-${DOCKER_VERSION:-unknown}}"',
            check,
        )

    def test_standalone_security_check_uses_docker_server_version(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-standalone.sh").read_text()
        self.assertIn(
            "SECURITY_DOCKER_VERSION=$(docker version --format '{{.Server.Version}}'",
            script,
        )
        self.assertNotIn('SECURITY_DOCKER_VERSION="$DOCKER_VERSION"', script)

    def test_standalone_runtime_inventory_supports_rpm_packages(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-standalone.sh").read_text()
        check = (COMMON_PATH.parent / "container-check.sh").read_text()
        self.assertIn(
            "if RUNC_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' runc", script
        )
        self.assertIn(
            "if NCT_RPM=$(rpm -q --qf '%{VERSION}-%{RELEASE}' nvidia-container-toolkit",
            script,
        )
        self.assertNotIn("2>/dev/null || true)", "\n".join(
            line for line in check.splitlines() if "rpm -q --qf" in line
        ))

    def test_standalone_toolkit_presence_is_independent_of_operational_minimum(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-standalone.sh").read_text()
        version_assignment = script.index('NVIDIA_CT_VERSION="$NCT_VERSION_CMD"')
        installed_assignment = script.index(
            'NVIDIA_CONTAINER_TOOLKIT="true"', version_assignment
        )
        # version_meets_minimum replaced version_ge here so an unresolved minimum
        # from the generated table cannot pass every version; the ordering
        # guard is unchanged.
        version_check = script.index(
            'if version_meets_minimum "$NCT_VERSION_CMD" "$NVIDIA_CT_RECOMMENDED_MIN"',
            version_assignment,
        )
        self.assertLess(installed_assignment, version_check)

    def test_slurm_worker_checks_use_standard_input(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()

        # Checks are delivered over srun's stdin (bash -s), not staged to a file
        # under $HOME: Slurm-on-Kubernetes nodes are pods with their own
        # ephemeral overlay, so the login pod's $HOME is not the worker's. Guard
        # against the shared-$HOME staging regressing back.
        self.assertIn('bash -s < "$WORKLOAD_DIR/host-check.sh"', script)
        self.assertIn('bash -s < "$WORKLOAD_DIR/container-check.sh"', script)
        self.assertNotIn('mktemp "${HOME}/', script)
        self.assertIn('"workerCheckOk": ${CONTAINER_WORKER_CHECK_OK:-false}', COMMON_PATH.read_text())

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

    def test_slurm_security_driver_never_uses_head_node_fallback(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()
        self.assertIn('SECURITY_DRIVER_VERSION="unknown"', script)
        self.assertIn('SECURITY_DRIVER_VERSION="$WORKER_DRIVER_VERSION"', script)
        self.assertIn(
            '"$WORKER_CHECK_OUTPUT" "$SECURITY_DRIVER_VERSION"', script
        )
        self.assertNotIn(
            '"$WORKER_CHECK_OUTPUT" "$DRIVER_VERSION" "$SECURITY_NCT_VERSION"',
            script,
        )

    def test_k8s_chroots_into_a_worker_and_runs_a_gpu_container(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn(
            "chroot /host env CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host bash -s",
            script,
        )
        self.assertIn('"gpuRuntimeWorks": ${K8S_GPU_CONTAINER_RUNTIME_WORKS}', script)
        self.assertIn('GPU container runtime: PASS on ${node}', script)

    def test_k8s_security_driver_uses_only_live_worker_check(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn('K8S_SECURITY_DRIVER_VERSION="unknown"', script)
        self.assertIn('K8S_SECURITY_DRIVER_VERSION="$HP_DRIVER"', script)
        self.assertIn(
            '"$HOST_CHECK_OUT" "$K8S_SECURITY_DRIVER_VERSION"', script
        )
        self.assertNotIn('"$HOST_CHECK_OUT" "$DRIVER_VERSION"', script)

    def test_k8s_toolkit_tag_excludes_image_digest(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn(
            '_toolkit_image_without_digest="${_toolkit_image%@*}"', script
        )
        self.assertIn(
            '_toolkit_tag="${_toolkit_image_without_digest##*:}"', script
        )
        self.assertNotIn('_toolkit_tag="${_toolkit_image##*:}"', script)

    def test_k8s_missing_volcano_config_is_nonfatal(self) -> None:
        # The collector runs under set -e; a cluster without volcano must not
        # abort the audit. Execute the real assignment with a failing kubectl.
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

    def test_enroot_import_runs_even_without_timeout(self) -> None:
        check = (COMMON_PATH.parent / "container-check.sh").read_text()

        # The import must be attempted in both branches; a missing `timeout`
        # binary must not short-circuit the check into a false failure.
        self.assertIn(
            "enroot import -o \"$ENROOT_SQSH\" docker://hello-world >/dev/null 2>&1",
            check,
        )
        self.assertIn('ENROOT_IMPORT_RC=$?', check)
        self.assertNotIn('[[ "$?" -eq 124 ]]', check)

    def test_slurm_publishes_worker_check_runtime_and_singularity_version(self) -> None:
        common = COMMON_PATH.read_text()
        slurm = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()

        # Fields the shared check collects must reach the Slurm audit JSON.
        self.assertIn(
            '"dockerNvidiaRuntimeConfigured": ${DOCKER_NVIDIA_RUNTIME_CONFIGURED:-false}',
            common,
        )
        self.assertIn('"runtimeScope":', common)
        self.assertIn('"singularityVersion": "${SINGULARITY_VERSION:-unknown}"', common)
        self.assertIn(
            'DOCKER_NVIDIA_RUNTIME_CONFIGURED="${WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED:-false}"',
            slurm,
        )

    def test_slurm_head_toolkit_check_credits_configured_nvidia_runtime(
        self,
    ) -> None:
        slurm = (COMMON_PATH.parent / "cluster-audit-slurm.sh").read_text()
        start = slurm.index("# Head-vs-worker consistency for container runtimes")
        end = slurm.index("# Singularity / Apptainer", start)
        comparison = slurm[start:end]

        self.assertIn("NCT_HEAD_NVIDIA_RUNTIME_CONFIGURED", comparison)
        self.assertIn(
            "docker info --format '{{json .Runtimes}}'",
            comparison,
        )
        self.assertIn(
            '|| "$NCT_HEAD_NVIDIA_RUNTIME_CONFIGURED" == "true"',
            comparison,
        )


class UfmProfileIntegrationTests(unittest.TestCase):
    def test_all_collectors_run_the_shared_ufm_profile_audit(self) -> None:
        workload_dir = COMMON_PATH.parent
        for name in (
            "cluster-audit-slurm.sh",
            "cluster-audit-standalone.sh",
            "cluster-audit-k8s.sh",
        ):
            with self.subTest(collector=name):
                script = (workload_dir / name).read_text()
                self.assertIn('audit_ufm_secured_profile "$RDMA_TYPE"', script)

    def test_shared_and_k8s_json_include_the_ufm_profile_result(self) -> None:
        common = COMMON_PATH.read_text()
        k8s = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        expected = '"ufmSecuredBareMetalCloud": ${UFM_SECURED_PROFILE_JSON}'
        self.assertIn(expected, common)
        self.assertIn(expected, k8s)


class SecurityBulletinIntegrationTests(unittest.TestCase):
    def test_host_check_collects_non_destructive_security_evidence(self) -> None:
        check = (COMMON_PATH.parent / "host-check.sh").read_text()
        for key in (
            "WORKER_JANUSCAPE_EXPOSED",
            "WORKER_NVLINK_EXPOSED",
        ):
            self.assertIn(key, check)
        self.assertNotIn("insmod poc", check.lower())
        self.assertIn("WORKER_JANUSCAPE_EXPOSED=unknown", check)
        self.assertIn("WORKER_NVLINK_EXPOSED=unknown", check)
        self.assertIn("WORKER_NVLINK_TOPOLOGY_CHECKED=false", check)
        self.assertIn("nvidia-smi topo -m", check)
        self.assertIn("WORKER_GUEST_KERNEL_NEWER_INSTALLED", check)
        self.assertIn("/var/run/reboot-required", check)
        self.assertIn("command -v rpm", check)
        self.assertIn("WORKER_GUEST_KERNEL_FLAVOR", check)
        self.assertIn("s/^[0-9]+(\\.[0-9]+)*-[0-9]+-//", check)
        self.assertIn("WORKER_GUEST_KERNEL_OLDEST", check)
        self.assertIn("WORKER_FRAGNESIA_STATUS", check)
        # The Fragnesia ABI minimum moved out of the script and into the
        # generated table (minimum-versions.json). Executable coverage of the
        # comparison lives in test_minimum_versions_shell.py; the pin that
        # remains here is the incident pair, so a revert to a hardcoded minimum
        # fails even though the comparison itself cannot run from a source read.
        self.assertNotIn("WORKER_FRAGNESIA_ABI >= 124", check)
        self.assertIn("WORKER_FRAGNESIA_ABI >= WORKER_FRAGNESIA_ABI_FLOOR", check)

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

    def build_advisory_members(self, *args: str) -> dict:
        """Run the shared advisory builder and parse the members it emits."""
        quoted = " ".join(f"'{arg}'" for arg in args)
        result = subprocess.run(
            ["bash", "-c", f'source "$1"; build_security_advisory_json {quoted}',
             "bash", str(COMMON_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        # The builder emits object members with a trailing comma, meant to be
        # spliced into a "security" object that owns further members.
        return json.loads("{" + result.stdout + '"sentinel": true}')

    def test_all_audit_json_shapes_include_security_bulletins(self) -> None:
        """Both collector JSON shapes carry the advisory members from one source.

        The script-text assertions here are source pins on purpose. Both JSON
        shapes are single heredocs interpolating a few hundred collector
        variables gathered from a live cluster; neither can execute in CI, and
        an unset numeric field expands to empty and yields invalid JSON, so
        there is nothing runnable to assert against. The executable half of the
        contract is the builder run below, and in test_minimum_versions_shell.py.

        The assertions keep the shared source for the two advisory members that
        the release report uses. They also prevent hardcoded minimums from
        returning to either collector.
        """
        common = COMMON_PATH.read_text()
        k8s = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()
        for script in (common, k8s):
            self.assertIn('\n  "security": {', script)
            self.assertIn('"guestKernel": {', script)
            self.assertIn("build_security_advisory_json", script)
            self.assertNotIn('"cve": "CVE-2026-46300"', script)
            self.assertNotIn('"ubuntuNoblePackageMinimum": "6.8.0-124.124"', script)

        members = self.build_advisory_members()

        self.assertTrue({"fragnesia", "januscape"}.issubset(members))

    def collector_januscape_exposed(self, collector: str, check_value: str):
        """Run one collector's real advisory wiring and return `exposed`.

        Executes the whole chain rather than pinning its text: the collector's
        own check variable, through json_bool_or_unknown, into the shared
        builder's --januscape-exposed argument, out as emitted JSON. Each
        collector names the check fact differently, so both are driven here.
        """
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
        # Missing check evidence must never serialize as a negative finding:
        # that would turn an unverified host boundary into a false pass.
        for collector in ("common", "k8s"):
            with self.subTest(collector=collector):
                self.assertEqual(
                    self.collector_januscape_exposed(collector, ""), "unknown"
                )
                self.assertIsNot(
                    self.collector_januscape_exposed(collector, ""), False
                )
                self.assertIs(
                    self.collector_januscape_exposed(collector, "true"), True
                )
                self.assertIs(
                    self.collector_januscape_exposed(collector, "false"), False
                )

    def test_security_version_default_does_not_append_an_extra_brace(self) -> None:
        common = COMMON_PATH.read_text()
        self.assertIn(
            'local security_version_audit_json="${SECURITY_VERSION_AUDIT_JSON:-}"',
            common,
        )
        self.assertIn('security_version_audit_json="{}"', common)
        self.assertIn(
            '"securityVersions": ${security_version_audit_json}',
            common,
        )
        self.assertNotIn('${SECURITY_VERSION_AUDIT_JSON:-{}}', common)

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
            snippet = function + """
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

    def test_gpu_dra_inventory_and_check_use_claims_when_opted_in(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn("DRA_GPU_COUNTS=", script)
        self.assertIn('.status.capacity["nvidia.com/gpu"]', script)
        self.assertIn("and $ready", script)
        self.assertIn(".spec.unschedulable", script)
        self.assertIn("k8s_ensure_gpu_dra_claim_template 1", script)
        self.assertIn("resourceClaimTemplateName: ${claim_template}", script)
        self.assertIn("kubernetes.io/hostname: ${node}", script)

    def test_shared_check_namespace_is_not_swept_or_removed(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn(
            'K8S_AUDIT_CHECK_NS="${CLUSTERMAX_AUDIT_K8S_NAMESPACE:-clustermax-audit}"',
            script,
        )
        self.assertNotIn(
            'kubectl delete pods -n "$K8S_AUDIT_CHECK_NS" -l app.kubernetes.io/name=clustermax-audit',
            script,
        )
        self.assertNotIn('kubectl delete namespace "$K8S_AUDIT_CHECK_NS"', script)
        self.assertIn('cleanup_audit_check_pod "$ns" "$pod"', script)

    def test_privileged_host_check_mounts_worker_proc_inside_chroot(self) -> None:
        script = self.K8S_SCRIPT.read_text()

        self.assertIn("mountPath: /host/proc", script)
        self.assertIn("path: /proc", script)

    def test_check_deadline_preserves_a_piped_check_script(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn('timeout "$secs" "$@"', script)
        self.assertIn('"$@" <&0 &', script)
        self.assertNotIn('timeout "$secs" "$@" 0<&3', script)
        self.assertNotIn('"$@" 0<&3 &', script)
        self.assertNotIn('} 3<&0', script)

    def test_k8s_gpu_promotion_keeps_its_regression_ratchets(self) -> None:
        # Slim ratchet set distilled from the former inventory mirror. Each
        # assertNotIn bans an old bug shape in the primary-GPU-profile
        # promotion; the behavior itself is owned by test_gpu_profiles.py and
        # test_merge_audit.py. The positive enumeration pins were deleted:
        # the emitted JSON shape is guarded by the ingest schemas.
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        # An empty primary profile must never silently default to {}.
        self.assertNotIn('${PRIMARY_GPU_PROFILE_JSON:-{}}', script)
        # Facts must come from the primary profile, not unscoped node labels.
        self.assertNotIn('GPU_MODEL_LABEL=$(primary_gpu_label', script)
        self.assertNotIn('GKE_ACCEL=$(primary_gpu_label', script)
        self.assertNotIn('|| echo \'{"primary":null,"profiles":[]}\'', script)
        self.assertNotIn('($primary | length) == 0 or', script)
        self.assertIn('select(($primary | index($node)) != null)', script)
        self.assertIn(
            'GPU profile inventory failed; refusing to promote unscoped GPU metadata',
            script,
        )
        self.assertIn(
            'GPU resources exist but no valid primary GPU profile was selected',
            script,
        )

class K8sTopologyCheckTests(unittest.TestCase):
    def test_aks_and_azure_file_csi_detection_are_present(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertNotIn('startswith("azure://")', script)
        self.assertIn('has("kubernetes.azure.com/cluster")', script)
        self.assertIn('PROVIDER="Azure AKS"', script)
        self.assertIn('PROVIDER_TYPE="managed"', script)
        self.assertIn('"file.csi.azure.com"', script)

    def test_optional_scheduler_checks_fail_open(self) -> None:
        script = (COMMON_PATH.parent / "cluster-audit-k8s.sh").read_text()

        self.assertIn(
            "KUEUE_TOPO_CRD=$(kubectl api-resources --api-group=kueue.x-k8s.io",
            script,
        )
        self.assertIn(
            "| awk '$1==\"topologies\"{print $1}' | head -1 || true)",
            script,
        )

class HostCheckVirtualizationTests(unittest.TestCase):
    """Run the virtualization detection that supports Januscape."""

    ANCHORS = (
        "# --- Hypervisor security bulletins (read-only, never triggers a PoC) ---",
        'echo "WORKER_IOMMU_GROUPS=${WORKER_IOMMU_GROUPS}"',
    )
    # Every external tool the extracted block reaches. The absent-tool cases run
    # on a PATH trimmed to the stub dir plus these symlinks, which is the only
    # way to make "systemd-detect-virt is not installed" deterministic on a
    # runner that has systemd.
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
            # Keep the stub dir, which bashtest puts first on PATH, and replace
            # the inherited entries with only the tools the block needs, so no
            # real systemd-detect-virt can answer.
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
        # Installed but unusable, for example exit 2 with a diagnostic on
        # stderr. That is not the bare-metal exit, so it settles nothing.
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
        # Every Januscape prerequisite this check can read is present and only
        # the platform is unclassified, so "not exposed" would be a confident
        # claim resting on the unread fact.
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
        # A read that returns 0 is a real read, so it still rules the
        # prerequisites out even when the platform is unclassified.
        root = self.make_root(
            cpuinfo="flags\t: fpu vme vmx lm\n", kvm_device=True, nested="0"
        )
        facts = self.run_virt(root)
        self.assertEqual(facts["WORKER_NESTED_ENABLED"], "false")
        self.assertEqual(facts["WORKER_JANUSCAPE_EXPOSED"], "false")


class HostCheckGpuInventoryTests(unittest.TestCase):
    """The NVIDIA GPU presence block of host-check.sh, run for real.

    These keys are the only input that lets build_security_version_audit pass
    ``--nvidia-gpu-absent``, which grades the driver minimum not_applicable
    and renders as a skip, so the absence claim is asserted from behavior
    against a stub lspci and a fixture sysfs tree. The local inventory runs
    before the scale-out gate, so it remains active for standalone audits.
    """

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

    def test_a_listed_nvidia_device_is_present(self) -> None:
        listing = "0000:00:1f.0 0601: 8086:a1c1\n0000:07:00.0 0302: 10de:2901\n"
        facts = self.facts(
            self.run_inventory(self.make_root(), lspci=f"printf '%s' '{listing}'")
        )
        self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "true")
        self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "true")

    def test_a_read_bus_with_no_nvidia_device_is_absent(self) -> None:
        listing = "0000:00:1f.0 0601: 8086:a1c1\n0000:02:00.0 0200: 1af4:1041\n"
        facts = self.facts(
            self.run_inventory(self.make_root(), lspci=f"printf '%s' '{listing}'")
        )
        self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "true")
        self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "false")

    def test_corroborated_empty_bus_is_absent(self) -> None:
        # The 20260827-134338 sandbox shape: lspci exits 0 with nothing to
        # print and /sys/bus/pci/devices is readable and empty.
        facts = self.facts(
            self.run_inventory(self.make_root(empty_pci_bus=True), lspci="exit 0")
        )
        self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "true")
        self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "false")

    def test_uncorroborated_empty_listing_stays_unknown(self) -> None:
        facts = self.facts(self.run_inventory(self.make_root(), lspci="exit 0"))
        self.assertEqual(facts["WORKER_SECURITY_GPU_INVENTORY_COMPLETE"], "false")
        self.assertEqual(facts["WORKER_SECURITY_NVIDIA_GPU_PRESENT"], "unknown")

    @unittest.skipIf(os.geteuid() == 0, "root can list any directory")
    def test_an_unreadable_sysfs_bus_stays_unknown(self) -> None:
        # An unreadable directory blanks the ls capture just like an empty
        # one; it must not corroborate absence, or a permissions problem
        # would skip the NVIDIA driver minimum on a host that has the GPU.
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
    """Only a unanimous positive absence claim reaches the evaluator."""

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
        # A fleet where one worker read its bus and another could not: the
        # unread host may carry the GPU, so the claim never leaves the shell.
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
        # An older host-check that never emitted the GPU inventory keys makes
        # no claim, and the evaluator keeps asking for attestation.
        security = self.build_security("WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true")
        self.assertEqual(security["nvidiaDriver"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
