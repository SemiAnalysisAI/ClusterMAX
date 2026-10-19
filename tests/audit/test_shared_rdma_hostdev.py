import json
from pathlib import Path
import pytest
import bashtest

SCRIPT = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/k8s-control.sh"


@pytest.mark.parametrize("is_rdma,expected", [(True, "nvidia.com/hostdev"), (False, "")])
def test_shared_rdma_helper_uses_sriov_configuration(is_rdma, expected):
    text = SCRIPT.read_text()
    function = text.split("k8s_detect_shared_rdma_resource() {", 1)[1].split("# List the Multus", 1)[0]
    config = {"data": {"config.json": json.dumps({"resourceList": [
        {"resourceName": "hostdev", "selectors": {"isRdma": is_rdma}}
    ]})}}
    nodes = {"items": [{"status": {"allocatable": {"nvidia.com/hostdev": "8"}}}]}
    run = bashtest.run_bash(
        "k8s_detect_shared_rdma_resource() {" + function + "\nk8s_detect_shared_rdma_resource",
        env={"TEST_CONFIG": json.dumps(config), "TEST_NODES": json.dumps(nodes)},
        stubs={"kubectl": 'if [[ "$2" == configmap ]]; then printf "%s" "$TEST_CONFIG"; else printf "%s" "$TEST_NODES"; fi'},
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == expected
