"""HPC SDK collection, MPI detection, and OFED inventory."""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest

TEST_DIR = Path(__file__).resolve().parent

WORKLOAD_DIR = TEST_DIR.parents[1] / "cmax" / "scripts" / "1-audit"

HOST_CHECK = WORKLOAD_DIR / "host-check.sh"

SLURM_AUDIT = WORKLOAD_DIR / "cluster-audit-slurm.sh"

AUDIT_COMMON = WORKLOAD_DIR / "audit-common.sh"

# NVIDIA HPC SDK collection and grading
COLLECTOR = bashtest.extract_block(
    HOST_CHECK,
    "# --- NVIDIA HPC SDK ---",
    "# --- HPC-X install tree under /opt",
)

GRADER = bashtest.extract_block(
    SLURM_AUDIT,
    'print_section "NVIDIA HPC SDK (on compute node)"',
    "# Head-vs-worker consistency",
)

VERSION_GE = bashtest.extract_function(AUDIT_COMMON, "version_ge")

class NvhpcCollectorTests(unittest.TestCase):
    def _sdk_tree(
        self, root: Path, version: str = "26.5", machine: str = "x86_64"
    ) -> Path:
        release = root / f"Linux_{machine}" / version
        compiler_bin = release / "compilers" / "bin"
        compiler_bin.mkdir(parents=True)
        for compiler in ("nvc", "nvc++", "nvfortran"):
            path = compiler_bin / compiler
            path.write_text(f"#!/bin/sh\necho '{compiler} {version}-0'\n")
            path.chmod(0o755)

        components = release / "component-fixtures"
        components.mkdir()
        names = [
            "libnccl.so.2",
            "libnvshmem_host.so.3",
            "libcublas.so.13",
            "libcufft.so.12",
            "libcurand.so.10",
            "libcusolver.so.12",
            "libcusparse.so.12",
            "libcutensor.so.2",
            "libscalapack.so.2",
            "nsys",
            "cuda-gdb",
        ]
        if machine == "aarch64":

            names += ["libnvpl_blas_lp64_gomp.so.0", "libnvpl_lapack_lp64_gomp.so.0"]
            headers = release / "compilers" / "include" / "openblas" / "lp64"
            headers.mkdir(parents=True)
            (headers / "openblas_config.h").touch()
        else:
            names.append("libopenblas.so.0")
        for name in names:
            (components / name).touch()

        (components / "ncu-target").touch()
        (components / "ncu").symlink_to("ncu-target")
        for name in ("hpcx-2.50", "thrust", "cub"):
            (components / name).mkdir()
        return release

    def _collect(self, root: Path, machine: str = "x86_64") -> bashtest.BashRun:

        return bashtest.run_bash(
            COLLECTOR,
            stubs={
                "uname": (
                    f'if [ "$1" = "-m" ]; then echo {machine}; '
                    'else exec /bin/uname "$@"; fi'
                )
            },
            env={"CLUSTERMAX_NVHPC_ROOT": str(root)},
        )

    def test_collects_matching_compilers_and_complete_bundle(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "hpc_sdk"
            self._sdk_tree(root)
            run = self._collect(root)

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_NVHPC_VERSION=26.5", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPILERS_OK=true", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_OK=true", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_MISSING=none", run.stdout)

    def test_names_a_missing_hpcx_payload(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "hpc_sdk"
            release = self._sdk_tree(root)
            shutil.rmtree(release / "component-fixtures" / "hpcx-2.50")
            run = self._collect(root)

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_NVHPC_COMPONENTS_OK=false", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_MISSING=hpcx", run.stdout)

    def test_aarch64_bundle_with_nvpl_and_no_openblas_is_complete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "hpc_sdk"
            self._sdk_tree(root, machine="aarch64")
            run = self._collect(root, machine="aarch64")

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_NVHPC_COMPONENTS_OK=true", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_MISSING=none", run.stdout)

@pytest.mark.parametrize(
    "machine,pattern,missing",
    [("aarch64", "libnvpl*", "nvpl"), ("x86_64", "libopenblas.so.0", "openblas")],
)
def test_architecture_specific_missing_component(tmp_path, machine, pattern, missing):
    sdk = NvhpcCollectorTests()
    root = tmp_path / "hpc_sdk"
    release = sdk._sdk_tree(root, machine=machine)
    for library in (release / "component-fixtures").glob(pattern):
        library.unlink()
    run = sdk._collect(root, machine=machine)
    assert run.returncode == 0, run.stderr
    assert "WORKER_NVHPC_COMPONENTS_OK=false" in run.stdout
    assert f"WORKER_NVHPC_COMPONENTS_MISSING={missing}" in run.stdout

class NvhpcGradingTests(unittest.TestCase):
    def _grade(
        self,
        *,
        version: str = "26.5",
        minimum: str = "26.3",
        current: str = "26.5",
        compilers_ok: str = "true",
        components_ok: str = "true",
        missing: str = "none",
    ) -> bashtest.BashRun:
        prelude = f"""
WORKER_CHECK_OK=true
WORKER_HOSTNAME=worker-0
WORKER_NVHPC_INSTALLED=true
WORKER_NVHPC_PATH=/opt/nvidia/hpc_sdk
WORKER_NVHPC_VERSION={version}
WORKER_NVHPC_NVC_VERSION={version}
WORKER_NVHPC_NVCXX_VERSION={version}
WORKER_NVHPC_NVFORTRAN_VERSION={version}
WORKER_NVHPC_COMPILERS_OK={compilers_ok}
WORKER_NVHPC_COMPONENTS_OK={components_ok}
WORKER_NVHPC_COMPONENTS_MISSING={missing}
print_section() {{ :; }}
print_info() {{ :; }}
print_detail() {{ :; }}
print_warn() {{ :; }}
print_error() {{ :; }}
minimum_version() {{
    case "$1" in
        components.nvhpc.minimum) printf '%s\\n' {minimum} ;;
        components.nvhpc.current) printf '%s\\n' {current} ;;
    esac
}}
"""
        return bashtest.run_bash(
            VERSION_GE + prelude + GRADER + '\nprintf "RESULT=%s\\n" "$NVHPC_STATUS"\n'
        )

    def test_current_and_previous_releases_pass(self) -> None:
        for version in ("26.3", "26.5"):
            with self.subTest(version=version):
                run = self._grade(version=version)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("RESULT=pass", run.stdout)

    def test_release_outside_window_fails(self) -> None:
        for version in ("26.1", "26.7"):
            with self.subTest(version=version):
                run = self._grade(version=version)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("RESULT=fail", run.stdout)

    def test_compiler_mismatch_or_missing_component_fails(self) -> None:
        compiler_run = self._grade(compilers_ok="false")
        component_run = self._grade(components_ok="false", missing="hpcx")

        self.assertIn("RESULT=fail", compiler_run.stdout)
        self.assertIn("RESULT=fail", component_run.stdout)

    def test_unknown_release_window_does_not_hide_incomplete_payload(self) -> None:
        run = self._grade(
            minimum="unknown",
            current="unknown",
            components_ok="false",
            missing="hpcx",
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("RESULT=fail", run.stdout)

# MPI MCA detection
DETECT_CHAIN = bashtest.extract_block(
    WORKLOAD_DIR / "host-check.sh",
    "MPI_VER=$(mpirun --version",
    "    fi",
)

HPCX_OMPI_INFO = (
    "                 Package: Open MPI\n"
    "                Open MPI: 4.1.9a1\n"
    "                MCA coll: hcoll (MCA v2.1.0, Component v4.1.9)\n"
    "                 MCA pml: ucx (MCA v2.1.0, Component v4.1.9)\n"
)

GENERIC_OMPI_INFO = (
    "                 Package: Open MPI\n"
    "                Open MPI: 4.1.6\n"
    "                MCA coll: basic (MCA v2.1.0, Component v4.1.6)\n"
    "                 MCA pml: ob1 (MCA v2.1.0, Component v4.1.6)\n"
)

def detect(mpirun_path: str, mpi_version_line: str, ompi_info_out: str) -> str:
    stubs = {
        "mpirun": f'echo "{mpi_version_line}"',
        "ompi_info": (
            'if [ "$1" = "--version" ]; then\n'
            f'  printf "%s\\n" "{mpi_version_line}"\n'
            "else\n"
            f'  printf %s {shquote(ompi_info_out)}\n'
            "fi"
        ),
    }
    prelude = f'MPIRUN_P="{mpirun_path}"\n'
    run = bashtest.run_bash(prelude + DETECT_CHAIN, stubs=stubs)
    assert run.returncode == 0, run.stderr
    for line in run.stdout.splitlines():
        if line.startswith("WORKER_HPCX_DETECTED="):
            return line.split("=", 1)[1]
    raise AssertionError(f"no WORKER_HPCX_DETECTED in output: {run.stdout!r}")

def shquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"

@pytest.mark.parametrize(
    "path,version,components,expected",
    [
        ("/usr/mpi/gcc/openmpi-4.1.9a1/bin/mpirun", "mpirun (Open MPI) 4.1.9a1",
         HPCX_OMPI_INFO, "true"),
        ("/usr/bin/mpirun", "mpirun (Open MPI) 4.1.6", GENERIC_OMPI_INFO, "false"),
        ("/opt/hpcx/ompi/bin/mpirun", "mpirun (Open MPI) 4.1.9a1 (HPC-X)",
         HPCX_OMPI_INFO, "true"),
    ],
    ids=["mca-detection", "generic-openmpi", "explicit-hpcx"],
)
def test_hpcx_detection(path, version, components, expected):
    assert detect(path, version, components) == expected

# Installed HPC-X severity and PMIx guidance
REPORT_BLOCK = bashtest.extract_block(
    WORKLOAD_DIR / "cluster-audit-slurm.sh",
    'if [[ -n "$HPCX_OPT_PATH" ]]; then',
    "# srun --mpi=list / PMIx integration",
)

PRINT_STUBS = {"print_info": "", "print_warn": "", "print_detail": ""}

def run_block(hpcx_opt_path: str, hpcx_in_path: str) -> bashtest.BashRun:
    prelude = f'HPCX_OPT_PATH="{hpcx_opt_path}"\nHPCX_IN_PATH="{hpcx_in_path}"\n'
    return bashtest.run_bash(prelude + REPORT_BLOCK, stubs=PRINT_STUBS)

def all_print_args(run: bashtest.BashRun) -> str:
    joined = []
    for stub in PRINT_STUBS:
        for call in run.calls(stub):
            joined.append(" ".join(call))
    return "\n".join(joined)

@pytest.mark.parametrize(
    "install_path,on_path",
    [("/opt/hpcx-v2.26", "false"), ("/opt/hpcx-v2.26", "true"), ("", "false")],
    ids=["installed-off-path", "installed-on-path", "absent"],
)
def test_hpcx_installation_severity(install_path, on_path):
    run = run_block(install_path, on_path)
    if install_path:
        assert run.calls("print_info")
        assert not run.calls("print_warn")
        if on_path == "false":
            text = all_print_args(run)
            assert "FAIL" not in text
            assert "srun --mpi=pmix" in text
    else:
        assert run.calls("print_warn")

# MOFED and DOCA inventory
DETECT_BLOCK = (
    bashtest.extract_function(WORKLOAD_DIR / "host-check.sh", "scale_out_checks_enabled")
    + bashtest.extract_block(
        WORKLOAD_DIR / "host-check.sh",
        '_mofed_mlx5_path="${CLUSTERMAX_MLX5_VERSION_PATH',
        'echo "WORKER_MLX5_DRIVER_VERSION=',
    )
)

def run_detect(rdma_core_version: str, env: dict[str, str] | None = None) -> dict[str, str]:
    # Keep the host's sysfs and /opt installations out of the fixture.

    base_env = {
        "CLUSTERMAX_MLX5_VERSION_PATH": "/nonexistent/mlx5/version",
        "CLUSTERMAX_OPT_MELLANOX_DIR": "/nonexistent/opt/mellanox",
    }
    base_env.update(env or {})
    stubs = {"dpkg-query": f'echo "{rdma_core_version}"'}
    run = bashtest.run_bash(DETECT_BLOCK, stubs=stubs, env=base_env)
    assert run.returncode == 0, run.stderr
    out: dict[str, str] = {}
    for line in run.stdout.splitlines():
        if line.startswith("WORKER_") and "=" in line:
            key, val = line.split("=", 1)
            out[key] = val
    return out

def test_doca_ofed_rdma_core_is_detected() -> None:
    out = run_detect("2507mlnx58-1.2507097")
    assert out["WORKER_MOFED_FLAVOR"] == "doca-ofed"
    assert "DOCA-OFED rdma-core 2507mlnx58-1.2507097" == out["WORKER_MOFED_VERSION"]

def test_plain_rdma_core_without_mellanox_is_not_claimed_as_mofed() -> None:

    out = run_detect("50.0-2ubuntu1")
    assert out["WORKER_MOFED_FLAVOR"] == "none"
    assert out["WORKER_MOFED_VERSION"] == "none"

def test_doca_ofed_via_opt_mellanox_and_driver_version(tmp_path) -> None:

    mlx5 = tmp_path / "version"
    mlx5.write_text("25.07-0.9.7\n")
    opt = tmp_path / "mellanox"
    opt.mkdir()
    out = run_detect(
        "50.0-2ubuntu1",
        env={
            "CLUSTERMAX_MLX5_VERSION_PATH": str(mlx5),
            "CLUSTERMAX_OPT_MELLANOX_DIR": str(opt),
        },
    )
    assert out["WORKER_MOFED_FLAVOR"] == "doca-ofed"
    assert out["WORKER_MLX5_DRIVER_VERSION"] == "25.07-0.9.7"
    assert "DOCA-OFED mlx5_core 25.07-0.9.7" == out["WORKER_MOFED_VERSION"]
