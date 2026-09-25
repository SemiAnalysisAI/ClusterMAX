"""Request diagnostics must preserve fail-closed behavior and keep secrets out."""

import io
import os
import re
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cmax import minimum_refresh as fr


class FetchLoggingTests(unittest.TestCase):
    def test_json_fetch_logs_url_and_duration_without_credentials(self):
        url = "https://api.github.com/repos/example/releases"
        with (
            mock.patch.dict(fr.os.environ, {"GITHUB_TOKEN": "private-test-token"}),
            mock.patch.object(fr.SAFE_OPENER, "open", return_value=io.BytesIO(b"{}")),
            self.assertLogs(fr.__name__, level="INFO") as logs,
        ):
            self.assertEqual(fr.Fetcher().get_json(url), {})
        output = "\n".join(logs.output)
        self.assertIn("fetch GET " + url, output)
        self.assertIn("finished " + url + " after ", output)
        self.assertNotIn("private-test-token", output)
        self.assertNotIn("Authorization", output)

    def test_failed_request_logs_duration_and_still_raises(self):
        url = "https://example.com/feed"
        with (
            mock.patch.object(fr.SAFE_OPENER, "open", side_effect=TimeoutError("timed out")),
            self.assertLogs(fr.__name__, level="INFO") as logs,
            self.assertRaisesRegex(fr.MinimumRefreshError, "timed out"),
        ):
            fr.Fetcher().get_text(url)
        self.assertIn("finished " + url, "\n".join(logs.output))


class UbuntuConcurrencyTests(unittest.TestCase):
    def test_packages_run_concurrently_and_keep_input_order(self):
        barrier = threading.Barrier(4, timeout=5)
        specs = [
            {"key": str(n), "cve": str(n), "package": "package"}
            for n in range(4)
        ]

        def entry(cve, *args, **kwargs):
            barrier.wait()
            return {"fixed": cve}

        with mock.patch.object(fr, "ubuntu_entry", side_effect=entry):
            result = fr.ubuntu_minimums(specs=specs)
        self.assertEqual(list(result["packages"]), ["0", "1", "2", "3"])
        self.assertEqual(result["packages"]["2"]["fixed"], "2")

    def test_a_failed_package_still_stops_the_build(self):
        with (
            mock.patch.object(
                fr, "ubuntu_entry", side_effect=fr.MinimumRefreshError("feed unavailable")
            ),
            self.assertRaisesRegex(fr.MinimumRefreshError, "feed unavailable"),
        ):
            fr.ubuntu_minimums(specs=[{"key": "x", "cve": "x", "package": "x"}])


class BulletinShellTests(unittest.TestCase):
    def test_scan_exit_codes_under_github_errexit(self):
        import yaml

        path = Path(__file__).resolve().parents[2] / ".github/workflows/minimum-versions-refresh.yml"
        steps = yaml.safe_load(path.read_text())["jobs"]["refresh"]["steps"]
        script = next(s["run"] for s in steps if s.get("id") == "bulletins")
        for code, found, attempts in ((0, "false", 1), (3, "true", 1), (2, None, 3)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                stub = (
                    '(printf "attempt\\n" >> "$RUNNER_TEMP/attempts"; '
                    f'exit {code}) > "$report" 2>&1'
                )
                run, replacements = re.subn(
                    r'python3[^\n]+> "\$report" 2>&1', lambda _: stub, script
                )
                self.assertEqual(replacements, 1)
                result = subprocess.run(
                    ["bash", "-e", "-c", "sleep() { :; }\n" + run],
                    env={**os.environ, "RUNNER_TEMP": directory, "GITHUB_OUTPUT": str(output)},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0 if found else 1)
                self.assertEqual(
                    (Path(directory) / "attempts").read_text().splitlines(),
                    ["attempt"] * attempts,
                )
                if found:
                    self.assertEqual(output.read_text(), f"found={found}\n")
                else:
                    self.assertFalse(output.exists())
