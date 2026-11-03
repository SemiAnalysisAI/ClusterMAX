"""Executable test for the installed-kernel inventory in host-check.sh."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


ROOT = Path(__file__).resolve().parents[2]
HOST_CHECK = ROOT / "cmax" / "scripts" / "1-audit" / "host-check.sh"
_TRAILING_GUARD = 'if [[ "$WORKER_GUEST_KERNEL_RUNNING" != unknown \\\n'
INVENTORY_BLOCK = bashtest.extract_block(
    HOST_CHECK,
    'if command -v dpkg-query >/dev/null 2>&1; then\n'
    '    WORKER_GUEST_KERNEL_NEWEST_INSTALLED=$(',
    "\nfi\n",
)
assert INVENTORY_BLOCK.endswith(_TRAILING_GUARD), INVENTORY_BLOCK
# extract_block runs to the next line break after a newline-terminated anchor,
# so drop the partial guard line that follows the closing fi.
INVENTORY_BLOCK = INVENTORY_BLOCK[: -len(_TRAILING_GUARD)]


def inventory(dpkg_rows: str) -> str:
    run = bashtest.run_bash(
        INVENTORY_BLOCK
        + 'printf "%s\\n" "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED"',
        stubs={"dpkg-query": f"printf '{dpkg_rows}'"},
        env={"WORKER_GUEST_KERNEL_FLAVOR": "nvidia-64k"},
    )
    assert run.returncode == 0, run.stderr
    return run.stdout.strip()


def test_held_vendor_kernel_counts_as_installed():
    assert inventory(
        "hi linux-image-6.17.0-1021-nvidia-64k\n"
        "un linux-image-generic"
    ) == "6.17.0-1021-nvidia-64k"


def test_uninstalled_and_other_flavors_do_not_count():
    assert inventory(
        "un linux-image-6.17.0-1021-nvidia-64k\n"
        "ii linux-image-6.8.0-147-generic"
    ) == "unknown"
