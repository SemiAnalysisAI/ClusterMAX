"""Request diagnostics must preserve fail-closed behavior and keep secrets out."""

import io
import unittest
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
