"""tests/conftest.py makes every test independent of the host."""

from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

from cmax import host_role

_spec = importlib.util.spec_from_file_location(
    "cmax_tests_conftest", Path(__file__).with_name("conftest.py")
)
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)


def test_job_and_pod_variables_are_removed() -> None:
    assert not [key for key in os.environ if key.startswith(conftest.HOST_ENV_PREFIXES)]


def test_host_cluster_tools_are_hidden() -> None:
    for name in ("sinfo", "scontrol", "srun", "kubectl", "nvidia-smi", "docker"):
        assert shutil.which(name) is None, name


def test_hiding_keeps_the_other_tools_in_the_same_directory(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("sinfo", "kubectl", "grep"):
        tool = bin_dir / name
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
    other = tmp_path / "other"
    other.mkdir()

    path = conftest._without_host_tools(f"{bin_dir}{os.pathsep}{other}")

    assert shutil.which("sinfo", path=path) is None
    assert shutil.which("kubectl", path=path) is None
    assert Path(shutil.which("grep", path=path)).resolve() == bin_dir / "grep"
    assert path.split(os.pathsep)[1] == str(other)


def test_the_gpu_operator_toolkit_dir_is_empty() -> None:
    assert not Path(os.environ["CLUSTERMAX_NVIDIA_TOOLKIT_DIR"]).exists()


def test_the_host_role_is_unknown() -> None:
    assert host_role.detect().kind == host_role.UNKNOWN
