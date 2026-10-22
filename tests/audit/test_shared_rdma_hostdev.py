import json
from pathlib import Path
import pytest
import bashtest

SCRIPT = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/k8s-control.sh"


@pytest.mark.parametrize("is_rdma,expected", [(True, "nvidia.com/hostdev"), (False, "")])
@pytest.mark.parametrize("array_selectors", [False, True])
@pytest.mark.parametrize("namespace", ["nvidia-network-operator", "network-operator", "mellanox"])
@pytest.mark.parametrize("shared_key", [None, "rdma/shared", "nvidia.com/rdma_shared_device_a"])
def test_shared_rdma_helper_uses_sriov_configuration(is_rdma, expected, array_selectors, namespace, shared_key):
    text = SCRIPT.read_text()
    function = text.split("k8s_detect_shared_rdma_resource() {", 1)[1].split("# List the Multus", 1)[0]
    selectors = {"isRdma": is_rdma}
    config = {"data": {"config.json": json.dumps({"resourceList": [
        {"resourcePrefix": "nvidia.com", "resourceName": "hostdev",
         "selectors": [selectors] if array_selectors else selectors}
    ]})}}
    nodes = {"items": [{"status": {"allocatable": {"nvidia.com/hostdev": "8"}}}]}
    if shared_key:
        nodes["items"][0]["status"]["allocatable"][shared_key] = "8"
        expected = shared_key
    run = bashtest.run_bash(
        "k8s_detect_shared_rdma_resource() {" + function + "\nk8s_detect_shared_rdma_resource",
        env={"TEST_CONFIG": json.dumps(config), "TEST_NODES": json.dumps(nodes), "TEST_NAMESPACE": namespace},
        stubs={"kubectl": 'if [[ "$2" == configmap ]]; then [[ "$5" == "$TEST_NAMESPACE" ]] || exit 1; printf "%s" "$TEST_CONFIG"; else printf "%s" "$TEST_NODES"; fi'},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected


@pytest.mark.parametrize("prefix", [None, "intel.com", "synthetic.example", "nvidia.com"])
@pytest.mark.parametrize("array_selectors", [False, True])
def test_workload_and_inventory_agree_on_hostdev_prefix(prefix, array_selectors):
    from test_k8s_rdma_configured_resources import run_detection

    resource = {
        "resourceName": "hostdev",
        "selectors": [{"isRdma": True}] if array_selectors else {"isRdma": True},
    }
    if prefix is not None:
        resource["resourcePrefix"] = prefix
    config = {"resourceList": [resource]}
    function = "k8s_detect_shared_rdma_resource() {" + SCRIPT.read_text().split(
        "k8s_detect_shared_rdma_resource() {", 1,
    )[1].split("# List the Multus", 1)[0]
    helper = bashtest.run_bash(
        function + "\nk8s_detect_shared_rdma_resource",
        env={
            "TEST_CONFIG": json.dumps({"data": {"config.json": json.dumps(config)}}),
            "TEST_NODES": json.dumps({"items": [{"status": {
                "allocatable": {"nvidia.com/hostdev": "3"},
            }}]}),
        },
        stubs={"kubectl": (
            'if [[ "$2" == configmap ]]; then printf "%s" "$TEST_CONFIG"; '
            'else printf "%s" "$TEST_NODES"; fi'
        )},
    )
    inventory = run_detection({"nvidia.com/hostdev": "3"}, config)
    assert helper.returncode == inventory.returncode == 0
    if prefix == "nvidia.com":
        assert helper.stdout.strip() == "nvidia.com/hostdev"
        assert "TYPE=rdma" in inventory.stdout
    else:
        assert helper.stdout.strip() == ""
        assert "TYPE=none" in inventory.stdout
