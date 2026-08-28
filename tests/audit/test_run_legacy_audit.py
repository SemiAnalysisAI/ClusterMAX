#!/usr/bin/env python3
"""Unit tests for legacy audit execution."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


AUDIT_SCRIPTS = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
RUN_LEGACY_PATH = AUDIT_SCRIPTS / "run_legacy_audit.py"


def load_run_legacy_module():
    spec = importlib.util.spec_from_file_location("run_legacy_audit_under_test", RUN_LEGACY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_legacy_audit = load_run_legacy_module()


class RunLegacyAuditTests(unittest.TestCase):
    def test_packaged_security_collectors_exist_for_every_harness(self) -> None:
        for harness in ("slurm", "standalone", "k8s"):
            with self.subTest(harness=harness):
                full = AUDIT_SCRIPTS / f"cluster-audit-{harness}.sh"
                focused = run_legacy_audit.scoped_audit_script(full, "security")
                self.assertEqual(
                    focused,
                    AUDIT_SCRIPTS / f"cluster-audit-{harness}-security.sh",
                )
                self.assertTrue(focused.is_file())
                self.assertTrue(focused.stat().st_mode & 0o111)

    def test_security_scope_selects_the_focused_collector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            full = root / "cluster-audit-slurm.sh"
            focused = root / "cluster-audit-slurm-security.sh"
            full.write_text("full\n")
            focused.write_text("security\n")

            self.assertEqual(
                run_legacy_audit.scoped_audit_script(full, "security"), focused
            )
            self.assertEqual(run_legacy_audit.scoped_audit_script(full, "full"), full)
            self.assertEqual(
                run_legacy_audit.scoped_audit_script(full, "hardware"), full
            )

    def test_uses_ephemeral_shared_cwd_for_legacy_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            audit_root = root / "cmax" / "scripts" / "1-audit"
            audit_root.mkdir(parents=True)
            audit_script = audit_root / "00-cluster-audit.sh"
            audit_script.write_text(
                "#!/bin/bash\n"
                "set -euo pipefail\n"
                "out=''\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    --output-dir) out=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "touch nvvs.log\n"
                "printf '{}\\n' > \"$out/audit.json\"\n"
            )
            audit_script.chmod(0o755)
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            legacy_cwd = tmpdir / "legacy-cwd"
            audit_json_path = root / "raw.path"

            with patch.dict(
                run_legacy_audit.os.environ,
                {"CLUSTERMAX_AUDIT_LEGACY_CWD": str(legacy_cwd)},
                clear=True,
            ):
                rc = run_legacy_audit.main(
                    [
                        "run_legacy_audit.py",
                        str(audit_root),
                        str(audit_script),
                        "cluster",
                        str(tmpdir),
                        str(audit_json_path),
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertEqual(audit_json_path.read_text().strip(), str(tmpdir / "audit.json"))
            self.assertTrue((legacy_cwd / "nvvs.log").exists())
            self.assertFalse((root / "runs" / "cluster" / "ts" / "audit" / ".legacy-cwd").exists())
            self.assertFalse((audit_root / "nvvs.log").exists())

    def test_driver_keeps_legacy_cwd_out_of_run_dir(self) -> None:
        driver = (AUDIT_SCRIPTS / "run.sh").read_text()

        self.assertIn('LEGACY_CWD="$TMPDIR_AUDIT/legacy-cwd"', driver)
        self.assertNotIn('LEGACY_CWD="$OUT_DIR/.legacy-cwd"', driver)
        self.assertIn(
            'CLUSTERMAX_VIRTIO_NET_CHECK_CACHE="$TMPDIR_AUDIT/virtio-net-check.json"',
            driver,
        )
        self.assertIn("INT TERM HUP", driver)


if __name__ == "__main__":
    unittest.main()
