"""Behavioral tests for the k8s collector's RDMA / EFA detection cascade.

Executes the real detection block from cluster-audit-k8s.sh (plus the real
quantity-summing helpers from audit-common.sh) against synthetic node JSON,
one extended-resource spelling per case. Guarded incidents:

- A fixture exposes schedulable RDMA under the deployment-specific rdma/rdma_nic
  name, which the cascade must classify via the generic inventory instead of
  reporting "none".
- The NVIDIA Network Operator advertises vendor-namespaced nvidia.com/rdma_ib
  and nvidia.com/rdma_roce instead of the rdma/* prefix; a Network Operator
  cluster must not be reported as RDMA "none".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = (
    Path(__file__).resolve().parents[2]
    / "cmax" / "scripts" / "1-audit"
)

import pytest

AUDIT_DIR = Path(__file__).resolve().parent
WORKLOAD = SCRIPT_DIR
SCRIPT = WORKLOAD / "cluster-audit-k8s.sh"
AUDIT_COMMON = WORKLOAD / "audit-common.sh"
sys.path.insert(0, str(AUDIT_DIR.parents[1] / "shared"))
import bashtest

# print_* and audit_ufm_secured_profile are shell functions in the full
# collector; stub them as executables so the extracted block runs standalone
# and every call is recorded for assertion.
FUNCTION_STUBS = {
    "print_section": "",
    "print_info": "",
    "print_warn": "",
    "print_detail": "",
    "audit_ufm_secured_profile": "",
}


def detection_snippet() -> str:
    """The real RDMA / EFA cascade with the real quantity summers in scope."""
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


def run_detection(
    resources: dict[str, str], sriov_config: dict | None = None, namespace: str = ""
) -> bashtest.BashRun:
    node = {
        "status": {"capacity": resources, "allocatable": resources},
        "metadata": {"labels": {}},
    }
    return bashtest.run_bash(
        detection_snippet(),
        stubs={
            **FUNCTION_STUBS,
            "kubectl": 'printf "%s\\n" "$CMAX_SRIOV_CONFIG"',
        },
        env={
            "NODES_JSON": json.dumps({"items": [node]}),
            "CMAX_SRIOV_CONFIG": json.dumps(sriov_config or {}),
            "NETWORK_NS": namespace,
        },
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
    # The detected type is handed to the UFM secured-profile applicability
    # check, which keys its InfiniBand-only guidance off this value.
    assert run.calls("audit_ufm_secured_profile") == [[expected_type]]


def test_generic_rdma_resource_reports_devices_and_names() -> None:
    # A healthy rdma/rdma_nic extended resource must not be reported
    # as absent merely because its suffix is new to ClusterMAX.
    run = run_detection({"rdma/rdma_nic": "8"})
    assert run.returncode == 0, run.stderr
    assert "TYPE=rdma" in run.stdout
    lines = info_lines(run)
    assert "Type: RDMA (generic extended resource)" in lines
    assert "RDMA devices: 8" in lines
    details = [call[0] for call in run.calls("print_detail")]
    assert "Resource(s): rdma/rdma_nic" in details


@pytest.mark.parametrize("selector", [{"isRdma": True}, [{"isRdma": True}]])
@pytest.mark.parametrize("namespace", ["", "mellanox"])
def test_sriov_hostdev_resource_requires_an_rdma_selector(selector, namespace) -> None:
    config = {
        "resourceList": [
            {
                "resourcePrefix": "nvidia.com",
                "resourceName": "hostdev",
                "selectors": selector,
            }
        ]
    }
    run = run_detection({"nvidia.com/hostdev": "10"}, config, namespace)
    assert run.returncode == 0, run.stderr
    assert "TYPE=rdma" in run.stdout
    assert "RDMA devices: 10" in info_lines(run)
    assert "Resource(s): nvidia.com/hostdev" in [
        call[0] for call in run.calls("print_detail")
    ]
    assert run.calls("kubectl") == [[
        "-n", namespace or "nvidia-network-operator", "get", "configmap",
        "network-operator-sriovdp-config", "-o", "jsonpath={.data.config\\.json}",
    ]]

    for invalid in ({"isRdma": False}, None):
        config["resourceList"][0]["selectors"] = invalid
        unsupported = run_detection({"nvidia.com/hostdev": "10"}, config)
        assert unsupported.returncode == 0, unsupported.stderr
        assert "TYPE=none" in unsupported.stdout


def test_no_rdma_resources_reports_none() -> None:
    run = run_detection({})
    assert run.returncode == 0, run.stderr
    assert "TYPE=none" in run.stdout
    assert "No RDMA resources (using TCP)" in [
        call[0] for call in run.calls("print_warn")
    ]
    assert run.calls("audit_ufm_secured_profile") == [["none"]]
