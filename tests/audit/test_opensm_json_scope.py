import json
from pathlib import Path
import pytest
import bashtest

COMMON = Path(__file__).resolve().parents[2] / "cmax/scripts/1-audit/audit-common.sh"


@pytest.mark.parametrize("state,expected", [("", "unknown"), ("unknown", "unknown"), ("false", False), ("true", True)])
def test_opensm_json_preserves_missing_evidence(state, expected):
    source = COMMON.read_text()
    begin = source.index('    "ibControlPlane": {')
    end = source.index("\n    },", begin) + len("\n    },")
    block = source[begin:end]
    run = bashtest.run_bash(
        bashtest.extract_function(COMMON, "json_bool_or_unknown")
        + "\ncat <<EOF\n{" + block + '\n"sentinel": null}\nEOF',
        env={"WORKER_OPENSM_RUNNING": state},
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["ibControlPlane"]["opensmOnCheckedWorker"] == expected
