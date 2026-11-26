"""`cmax audit` and `cmax audit security` must agree on every security check.

Both commands run the same collector (see test_audit_pipeline). This test
checks the other half: one audit JSON graded under the full profile and under
the security profile gives the same status and observed value for each check
that the security profile reports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cmax import audit_report, runtime_paths

ROOT = runtime_paths.package_runtime_root()
FIXTURES = Path(__file__).resolve().parent / "fixtures"

FLEET_AUDIT = {
    "audit_data": {
        "audit": {"type": "slurm"},
        "gpus": {"total": 8, "driverVersion": "580.159.03", "cudaVersion": "13.1"},
        "securityVersions": {
            "docker": {"status": "pass", "version": "29.9.3",
                       "fleet": {"hostsChecked": 2, "hostsTotal": 2}},
        },
        "security": {
            "kvmSvm": {"status": "coverage-incomplete", "scope": "fleet",
                       "reason": "Control plane hosts were not read."},
            "januscape": {"status": "fail", "exposed": True, "scope": "fleet"},
            "pwnescape": {"status": "pass", "scope": "fleet"},
            "pciePassthrough": {"guestIommuGroupCount": 0, "inventoryComplete": True,
                                "vfioDevices": 0, "unsafeGroups": 0,
                                "scope": "sampled-worker-host",
                                "hostVerificationRequired": True},
            "virtualization": {"type": "none", "guest": False},
        },
    }
}


def _cases():
    yield "fleet", FLEET_AUDIT
    for path in sorted(FIXTURES.glob("*.json")):
        data = json.loads(path.read_text())
        if isinstance(data, dict) and ("audit_data" in data or "security" in data):
            yield path.stem, data if "audit_data" in data else {"audit_data": data}


@pytest.mark.parametrize("harness", ["slurm", "k8s", "standalone"])
@pytest.mark.parametrize("name,values", list(_cases()))
def test_security_profile_matches_full_profile(name, values, harness):
    full = {
        check.key: (check.status, json.dumps(check.observed, sort_keys=True, default=str))
        for check in audit_report.evaluate(values, ROOT, harness=harness)
    }
    scoped = audit_report.evaluate(values, ROOT, category="security", harness=harness)
    assert scoped, "the security profile reported no checks"
    for check in scoped:
        assert check.key in full, f"{name}: {check.key} is missing from the full profile"
        assert full[check.key] == (
            check.status, json.dumps(check.observed, sort_keys=True, default=str)
        ), f"{name}: {check.key} differs between the full and security profiles"
