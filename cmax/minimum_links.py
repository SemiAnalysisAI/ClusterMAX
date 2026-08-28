"""Stable links from audit checks to the published minimum-version table."""

from __future__ import annotations

from collections.abc import Iterable


MINIMUM_VERSIONS_URL = "https://www.clustermax.ai/minimum-versions"
MINIMUM_VERSIONS_JSON_URL = "https://www.clustermax.ai/minimum-versions.json"
REFERENCE_LABEL = "ClusterMAX minimum versions"

_COMPONENT_ANCHORS = frozenset(
    {
        "nvidiaDriver",
        "nvidiaContainerToolkit",
        "cudaToolkit",
        "connectxFirmware",
        "virtioNetBluefield",
        "runc",
        "docker",
        "rocm",
        "dcgm",
        "dcgmExporter",
        "ubuntuNoble",
    }
)

_SECURITY_CHECK_COMPONENTS = {
    "nvidia-driver": "nvidiaDriver",
    "nvidia-container-toolkit": "nvidiaContainerToolkit",
    "cuda-toolkit": "cudaToolkit",
    "runc": "runc",
    "docker": "docker",
    "connectx-firmware": "connectxFirmware",
    "virtio-net-bluefield": "virtioNetBluefield",
    "fragnesia": "ubuntuNoble",
}

_AUDIT_CHECK_COMPONENTS = {
    "containers.nvidiaContainerToolkitVersionOk": "nvidiaContainerToolkit",
    "containers.dockerVersionOk": "docker",
    "security.nvidiaMay2026.patched": "nvidiaDriver",
    "security.fragnesia.status": "ubuntuNoble",
}


def component_url(component: str) -> str | None:
    """Return the stable website row for one minimum-version component."""
    if component not in _COMPONENT_ANCHORS:
        return None
    return f"{MINIMUM_VERSIONS_URL}#{component}"


def security_check_url(check_id: str) -> str | None:
    """Return the website row used by a focused security check."""
    component = _SECURITY_CHECK_COMPONENTS.get(check_id)
    return component_url(component) if component else None


def audit_check_url(check_key: str) -> str | None:
    """Return the website row used by a full-audit finding key."""
    component = _AUDIT_CHECK_COMPONENTS.get(check_key)
    if component is None and check_key.startswith("securityVersions."):
        parts = check_key.split(".")
        if len(parts) >= 3 and parts[-1] == "status":
            component = parts[1]
    return component_url(component) if component else None


def canonical_references(
    references: Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    """Use the website row as the sole public reference when one is present.

    The minimum-version page owns the upstream advisory links. Repeating those
    links in the CLI bypasses that canonical page and can leave installed
    clients pointing at a stale advisory after the website has been refreshed.
    Checks without a minimum-version row retain their direct references.
    """
    values = tuple(references)
    website = tuple(reference for reference in values if reference[0] == REFERENCE_LABEL)
    return website or values
