"""Canonical paths for the audit runtime that ships with ClusterMAX."""

from importlib import resources
from pathlib import Path


AUDIT_RELATIVE = Path("scripts/1-audit")
AUDIT_RUNNER_RELATIVE = AUDIT_RELATIVE / "run.sh"
AUDIT_FINDINGS_RELATIVE = AUDIT_RELATIVE / "audit_findings.py"
MINIMUMS_READER_RELATIVE = AUDIT_RELATIVE / "minimum_versions.py"
MINIMUMS_TABLE_RELATIVE = AUDIT_RELATIVE / "minimum-versions.json"


def package_runtime_root() -> Path:
    """Return the runtime directory that is stored inside the package."""
    root = resources.files("cmax")
    if not isinstance(root, Path):
        raise RuntimeError("the ClusterMAX package resources are not filesystem paths")
    return root.resolve()


def audit_directory(runtime_root: Path) -> Path:
    """Return the directory that contains the installed audit scripts."""
    return runtime_root / AUDIT_RELATIVE


def audit_runner(runtime_root: Path) -> Path:
    """Return the entry point for the installed audit scripts."""
    return runtime_root / AUDIT_RUNNER_RELATIVE
