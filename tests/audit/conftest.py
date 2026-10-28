import os

import pytest

from cmax import host_role


@pytest.fixture(autouse=True)
def _unknown_host_role(monkeypatch):
    """Keep target tests independent of the cluster role of the test host."""
    monkeypatch.setattr(
        host_role, "detect", lambda environ=None: host_role.HostRole(host_role.UNKNOWN)
    )


# Variables a Slurm job step or Kubernetes pod sets. Dropping them lets the
# suite run under srun or in a pod with the same environment as CI; a test
# that needs one sets it itself.
HOST_ENV_PREFIXES = ("SLURM_", "SLURMD_", "KUBERNETES_")


@pytest.fixture(autouse=True)
def _no_job_environment(monkeypatch):
    """Keep tests independent of the Slurm job or pod they run in."""
    for key in list(os.environ):
        if key.startswith(HOST_ENV_PREFIXES):
            monkeypatch.delenv(key)
