"""Make every test independent of the host that runs the suite.

These fixtures apply to every test directory, so tests for a new or ported
module get them without code of their own. The suite then behaves the same
on a laptop, a CI runner, a Slurm login node, a GPU compute node under srun,
and a Kubernetes pod. A test that needs one of these tools or variables
stubs it or sets it itself.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from cmax import host_role

# Cluster, container, GPU, and fabric tools that a real cluster host has on
# PATH and a CI runner may not. They are hidden from every test.
HOST_TOOLS = frozenset({
    # Slurm clients
    "sacct", "sacctmgr", "salloc", "sattach", "sbatch", "sbcast", "scancel",
    "scontrol", "scrontab", "sdiag", "sinfo", "sprio", "squeue", "sreport",
    "srun", "sshare", "sstat", "strigger", "sview",
    # Kubernetes and container runtimes
    "kubectl", "helm", "crictl", "ctr", "docker", "podman", "nerdctl",
    "containerd", "runc", "crun", "enroot", "apptainer", "singularity",
    # GPU tools
    "nvidia-smi", "nvidia-ctk", "nvidia-container-cli",
    "nvidia-container-runtime", "nvidia-container-toolkit", "dcgmi",
    "nv-hostengine", "rocm-smi", "amd-smi", "rocminfo",
    # InfiniBand and RDMA tools
    "ibstat", "ibstatus", "ibv_devinfo", "ibv_devices", "mlxlink", "mst",
})

# Variables that a Slurm job step or a Kubernetes pod sets.
HOST_ENV_PREFIXES = ("SLURM_", "SLURMD_", "KUBERNETES_")

_path_cache: dict[str, str] = {}
_path_root: Path | None = None


def _without_host_tools(path: str) -> str:
    """Return path with HOST_TOOLS removed.

    Each PATH entry that holds one of the tools is replaced by a cached
    directory of symlinks to everything else in it, so the rest of the host
    inventory stays available.
    """
    global _path_root
    if path in _path_cache:
        return _path_cache[path]
    entries = []
    for entry in path.split(os.pathsep):
        directory = Path(entry)
        try:
            names = {child.name for child in directory.iterdir()}
        except OSError:
            entries.append(entry)
            continue
        if not names & HOST_TOOLS:
            entries.append(entry)
            continue
        if _path_root is None:
            _path_root = Path(tempfile.mkdtemp(prefix="cmax-tests-path-"))
            atexit.register(shutil.rmtree, _path_root, True)
        farm = _path_root / str(len(list(_path_root.iterdir())))
        farm.mkdir()
        for name in sorted(names - HOST_TOOLS):
            (farm / name).symlink_to(directory / name)
        entries.append(str(farm))
    _path_cache[path] = os.pathsep.join(entries)
    return _path_cache[path]


@pytest.fixture(autouse=True)
def _independent_of_the_host(monkeypatch, tmp_path_factory):
    """Hide the host's cluster tools, job variables, and cluster role."""
    for key in list(os.environ):
        if key.startswith(HOST_ENV_PREFIXES):
            monkeypatch.delenv(key)
    monkeypatch.setenv("PATH", _without_host_tools(os.environ.get("PATH", "")))
    # A GPU Operator host keeps a real NVIDIA toolkit here.
    monkeypatch.setenv(
        "CLUSTERMAX_NVIDIA_TOOLKIT_DIR",
        str(tmp_path_factory.getbasetemp() / "no-nvidia-toolkit"),
    )
    monkeypatch.setattr(
        host_role, "detect", lambda environ=None: host_role.HostRole(host_role.UNKNOWN)
    )
