#!/usr/bin/env python3
"""Behavioral tests for NVIDIA HPC SDK collection and grading."""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
import bashtest  # noqa: E402


WORKLOAD_DIR = TEST_DIR.parents[1] / "cmax" / "scripts" / "1-audit"
HOST_CHECK = WORKLOAD_DIR / "host-check.sh"
SLURM_AUDIT = WORKLOAD_DIR / "cluster-audit-slurm.sh"
AUDIT_COMMON = WORKLOAD_DIR / "audit-common.sh"

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
            # The aarch64 SDK ships NVPL for BLAS and LAPACK. Of OpenBLAS it
            # keeps only the headers and the licence.
            names += ["libnvpl_blas_lp64_gomp.so.0", "libnvpl_lapack_lp64_gomp.so.0"]
            headers = release / "compilers" / "include" / "openblas" / "lp64"
            headers.mkdir(parents=True)
            (headers / "openblas_config.h").touch()
        else:
            names.append("libopenblas.so.0")
        for name in names:
            (components / name).touch()
        # Executable payloads are commonly symlinks inside an SDK release.
        (components / "ncu-target").touch()
        (components / "ncu").symlink_to("ncu-target")
        for name in ("hpcx-2.50", "thrust", "cub"):
            (components / name).mkdir()
        return release

    def _collect(self, root: Path, machine: str = "x86_64") -> bashtest.BashRun:
        # Pin the architecture, so the result does not depend on the test host.
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

    def test_aarch64_bundle_without_nvpl_names_nvpl(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "hpc_sdk"
            release = self._sdk_tree(root, machine="aarch64")
            for lib in (release / "component-fixtures").glob("libnvpl*"):
                lib.unlink()
            run = self._collect(root, machine="aarch64")

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_NVHPC_COMPONENTS_OK=false", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_MISSING=nvpl", run.stdout)

    def test_x86_64_bundle_without_openblas_names_openblas(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "hpc_sdk"
            release = self._sdk_tree(root)
            (release / "component-fixtures" / "libopenblas.so.0").unlink()
            run = self._collect(root)

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_NVHPC_COMPONENTS_OK=false", run.stdout)
        self.assertIn("WORKER_NVHPC_COMPONENTS_MISSING=openblas", run.stdout)


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


if __name__ == "__main__":
    unittest.main()
