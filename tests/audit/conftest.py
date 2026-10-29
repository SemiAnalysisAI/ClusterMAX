import pytest

from cmax import host_role


@pytest.fixture(autouse=True)
def _unknown_host_role(monkeypatch):
    """Keep target tests independent of the cluster role of the test host."""
    monkeypatch.setattr(
        host_role, "detect", lambda environ=None: host_role.HostRole(host_role.UNKNOWN)
    )
