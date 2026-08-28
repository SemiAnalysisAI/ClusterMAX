"""Behavioral test for the worker CUDA device-assignment observation."""

from __future__ import annotations

import sys
from pathlib import Path

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = AUDIT_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
K8S_COLLECTOR = WORKLOAD / "cluster-audit-k8s.sh"
sys.path.insert(0, str(AUDIT_DIR))
import bashtest


CHECK = bashtest.extract_block(
    WORKLOAD / "host-check.sh",
    'echo "WORKER_CUDA_VISIBLE_DEVICES=',
    'MPIRUN_P=""',
)


def test_cuda_visible_devices_is_recorded_from_worker_environment() -> None:
    run = bashtest.run_bash(
        CHECK,
        env={
            "CUDA_VISIBLE_DEVICES": "GPU-a,GPU-b",
            "NVIDIA_VISIBLE_DEVICES": "GPU-a,GPU-b",
        },
    )

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=GPU-a,GPU-b" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=GPU-a,GPU-b" in run.stdout


def test_unassigned_cuda_devices_are_recorded_as_unset() -> None:
    run = bashtest.run_bash(CHECK)

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=unset" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=unset" in run.stdout


def test_k8s_gpu_check_records_the_assigned_devices() -> None:
    function = bashtest.extract_function(K8S_COLLECTOR, "run_gpu_smi_check")
    run = bashtest.run_bash(
        function
        + """
K8S_AUDIT_CHECK_NS=clustermax-audit
K8S_AUDIT_GPU_CHECK_IMAGE=cuda-image
apply_gpu_check_pod() { echo gpu-check-pod; }
cleanup_audit_check_pod() { :; }
check_deadline() { shift; "$@"; }
run_gpu_smi_check worker-0
""",
        stubs={
            "kubectl": bashtest.exec_from("bash"),
            "nvidia-smi": """
case "$*" in
  *--query-gpu=driver_version*) echo 590.48.01 ;;
  *--query-gpu=name*) echo "NVIDIA H100" ;;
  *--query-gpu=memory.total*) echo 81559 ;;
  *) echo "CUDA Version: 13.0" ;;
esac
""",
        },
        env={
            "CUDA_VISIBLE_DEVICES": "GPU-a",
            "NVIDIA_VISIBLE_DEVICES": "GPU-a",
        },
    )

    assert run.returncode == 0, run.stderr
    assert "WORKER_CUDA_VISIBLE_DEVICES=GPU-a" in run.stdout
    assert "WORKER_NVIDIA_VISIBLE_DEVICES=GPU-a" in run.stdout
