"""Offline tests for the published minimum version table fetch.

Every test drives `cmax.minimum_sync` through a stub `urlopen`, so the suite
never touches the network. No test reads the live table at
`cmax/scripts/1-audit/minimum-versions.json`, because the daily refresh
workflow rewrites that file and an assertion against it would fail on a correct
refresh.

Each test redirects the cache directory to a temporary directory through
`XDG_CACHE_HOME`, so no test writes to the home directory of the user who runs
the suite.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cmax import cli, minimum_sync, security

_MINIMUM_ENV = "CLUSTERMAX_MINIMUM_VERSIONS"
NOW = datetime(2026, 8, 20, 7, 32, 9, tzinfo=timezone.utc)


def table(generated: datetime = NOW) -> dict:
    """Return a small table with the shape the reader accepts."""
    return {
        "schemaVersion": 1,
        "generated": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "maxAgeDays": 10,
        "gracePeriodDays": 3,
        "components": {
            "docker": {
                "kind": "minimum",
                "minimum": "29.7.0",
                "source": {"feed": "docker-release-notes"},
            }
        },
    }


def body(payload: dict | str) -> bytes:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return text.encode("utf-8")


class FakeResponse:
    """The part of an HTTP response that `minimum_sync.fetch` reads."""

    def __init__(
        self,
        payload: bytes,
        headers: dict[str, str] | None = None,
        url: str = minimum_sync.DEFAULT_URL,
    ) -> None:
        self._payload = payload
        self.headers = headers or {}
        self._url = url

    def read(self, amount: int | None = None) -> bytes:
        return self._payload if amount is None else self._payload[:amount]

    def geturl(self) -> str:
        """The address the body came from, after any redirect."""
        return self._url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class MinimumSyncTestCase(unittest.TestCase):
    """Shared cache isolation for every fetch test."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache_home = Path(self.tmp.name) / "cache"
        patcher = mock.patch.dict(
            os.environ, {"XDG_CACHE_HOME": str(self.cache_home), _MINIMUM_ENV: ""}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @contextlib.contextmanager
    def server(self, *answers: object):
        """Answer each request with the next queued response or exception."""
        queue = list(answers)
        self.requests: list[object] = []

        def fake_urlopen(request, timeout=None):  # noqa: ANN001
            self.requests.append(request)
            answer = queue.pop(0) if queue else FakeResponse(body(table()))
            if isinstance(answer, Exception):
                raise answer
            return answer

        with mock.patch.object(minimum_sync.urllib.request, "urlopen", fake_urlopen):
            yield


class FetchTests(MinimumSyncTestCase):
    """One HTTPS GET request, one validated table, one cached file."""

    def test_a_valid_table_is_cached_and_reported_as_updated(self) -> None:
        payload = body(table())
        with self.server(FakeResponse(payload, {"ETag": '"abc"'})):
            result = minimum_sync.sync()
        self.assertTrue(result.ok)
        self.assertTrue(result.updated)
        self.assertEqual(result.path, minimum_sync.cache_path())
        self.assertEqual(result.generated, "2026-08-20T07:32:09Z")
        # The cached file holds the published bytes, so the reader parses the
        # same document the website served.
        self.assertEqual(minimum_sync.cache_path().read_bytes(), payload)
        self.assertEqual(minimum_sync.read_state(), {"etag": '"abc"'})

    def test_the_second_run_sends_the_stored_validators(self) -> None:
        with self.server(
            FakeResponse(body(table()), {"ETag": '"abc"', "Last-Modified": "Thu, 20 Aug 2026 07:40:00 GMT"})
        ):
            minimum_sync.sync()
        with self.server(urllib.error.HTTPError("u", 304, "Not Modified", {}, None)):
            result = minimum_sync.sync()
            request = self.requests[0]
        self.assertEqual(request.get_header("If-none-match"), '"abc"')
        self.assertEqual(
            request.get_header("If-modified-since"), "Thu, 20 Aug 2026 07:40:00 GMT"
        )
        # 304 means the cached table is the published table. The run reports no
        # change, and it stays usable.
        self.assertTrue(result.ok)
        self.assertFalse(result.updated)
        self.assertEqual(result.generated, "2026-08-20T07:32:09Z")
        self.assertIn("unchanged", result.message)

    def test_a_changed_address_starts_a_full_fetch(self) -> None:
        with self.server(FakeResponse(body(table()), {"ETag": '"abc"'})):
            minimum_sync.sync()
        with mock.patch.dict(
            os.environ, {minimum_sync.URL_ENV: "https://example.test/minimums.json"}
        ):
            self.assertEqual(minimum_sync.read_state(), {})

    def test_a_server_error_keeps_the_installed_table(self) -> None:
        with self.server(urllib.error.HTTPError("u", 503, "Service Unavailable", {}, None)):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIn("HTTP 503", result.message)
        self.assertFalse(minimum_sync.cache_path().exists())

    def test_an_unreachable_server_keeps_the_installed_table(self) -> None:
        with self.server(urllib.error.URLError("no outbound network")):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIn("could not be read", result.message)
        self.assertFalse(minimum_sync.cache_path().exists())

    def test_a_plain_http_address_is_refused(self) -> None:
        with mock.patch.dict(
            os.environ, {minimum_sync.URL_ENV: "http://www.clustermax.ai/minimum-versions.json"}
        ):
            with self.server():
                result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIn("must use https", result.message)

    def test_a_redirect_off_https_is_refused(self) -> None:
        # urllib follows a redirect across schemes. A body that arrives over
        # plain HTTP carries no server authentication, and it decides pass and
        # fail results, so the fetch must fail loudly instead of caching it.
        with self.server(
            FakeResponse(body(table()), url="http://mirror.test/minimum-versions.json")
        ):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIn("not https", result.message)
        self.assertFalse(minimum_sync.cache_path().exists())

    def test_a_body_over_the_limit_is_refused(self) -> None:
        oversize = b"x" * (minimum_sync.MAX_BYTES + 1)
        with self.server(FakeResponse(oversize)):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIn("bytes", result.message)
        self.assertFalse(minimum_sync.cache_path().exists())


class ValidationTests(MinimumSyncTestCase):
    """The audit grades against this data, so a wrong document never caches."""

    def _reject(self, payload: dict | str) -> str:
        with self.server(FakeResponse(body(payload))):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertFalse(minimum_sync.cache_path().exists())
        return result.message

    def test_text_that_is_not_json_is_refused(self) -> None:
        self.assertIn("not valid JSON", self._reject("{ this is not json"))

    def test_an_unknown_schema_version_is_refused(self) -> None:
        document = table()
        document["schemaVersion"] = 2
        message = self._reject(document)
        self.assertIn("schema version 2", message)
        self.assertIn("Update clustermax", message)

    def test_a_table_with_no_components_is_refused(self) -> None:
        document = table()
        document["components"] = {}
        self.assertIn("no components", self._reject(document))

    def test_a_table_with_no_timestamp_is_refused(self) -> None:
        document = table()
        document["generated"] = "not a date"
        self.assertIn("generated timestamp", self._reject(document))

    def test_an_older_published_table_is_refused(self) -> None:
        # A published file that regressed must never retire a newer minimum.
        published = table(NOW - timedelta(days=30))
        with self.server(FakeResponse(body(published))):
            result = minimum_sync.sync(
                installed_generated=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        self.assertFalse(result.ok)
        self.assertIn("older", result.message)
        self.assertIn("Keeping the installed table", result.message)
        self.assertFalse(minimum_sync.cache_path().exists())

    def test_a_newer_published_table_is_accepted(self) -> None:
        published = table(NOW + timedelta(days=1))
        with self.server(FakeResponse(body(published))):
            result = minimum_sync.sync(
                installed_generated=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        self.assertTrue(result.updated)


class SecurityIntegrationTests(MinimumSyncTestCase):
    """`sync_minimum_table` points the audit at the fetched table."""

    def _installed(self, generated: datetime) -> Path:
        path = Path(self.tmp.name) / "installed" / "minimum-versions.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(table(generated)))
        return path

    def _sync(self, *answers: object) -> tuple[bool, str]:
        output = io.StringIO()
        with self.server(*answers):
            with contextlib.redirect_stdout(output):
                changed = security.sync_minimum_table()
        return changed, output.getvalue()

    def test_a_fetched_table_becomes_the_table_for_this_run(self) -> None:
        installed = self._installed(NOW - timedelta(days=20))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(FakeResponse(body(table())))
        self.assertTrue(changed)
        # The collector runs as a subprocess and inherits this variable, so the
        # command line and the collector grade against the same table.
        self.assertEqual(os.environ[_MINIMUM_ENV], str(minimum_sync.cache_path()))
        self.assertIn("minimum fetch:", output)
        self.assertIn("minimum table in use:", output)

    def test_a_failed_fetch_leaves_the_installed_table_in_place(self) -> None:
        installed = self._installed(NOW)
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(urllib.error.URLError("no outbound network"))
        self.assertFalse(changed)
        self.assertEqual(os.environ.get(_MINIMUM_ENV, ""), "")
        self.assertIn("no outbound network", output)
        # The warning names the age of the table the audit grades against.
        self.assertIn("Grading against the installed table (generated", output)
        self.assertIn("2026-08-20", output)

    def test_a_failed_fetch_falls_back_to_the_cached_table(self) -> None:
        # One earlier launch with a working network filled the cache.
        with self.server(FakeResponse(body(table()))):
            minimum_sync.sync()
        installed = self._installed(NOW - timedelta(days=20))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(urllib.error.URLError("no outbound network"))
        self.assertTrue(changed)
        self.assertEqual(os.environ[_MINIMUM_ENV], str(minimum_sync.cache_path()))
        self.assertIn("Grading against the last fetched table", output)
        self.assertIn("generated 2026-08-20", output)

    def test_a_failed_fetch_ignores_a_cached_table_older_than_installed(self) -> None:
        # The cache holds an old fetch, and a new release shipped a newer table.
        with self.server(FakeResponse(body(table(NOW - timedelta(days=30))))):
            minimum_sync.sync()
        installed = self._installed(NOW)
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(urllib.error.URLError("no outbound network"))
        self.assertFalse(changed)
        self.assertEqual(os.environ.get(_MINIMUM_ENV, ""), "")
        self.assertIn("Grading against the installed table (generated", output)

    def test_a_rejected_older_publication_keeps_the_installed_table(self) -> None:
        # A published regression is a decision, not a failure. The cache holds
        # a newer copy here, and it still must not override that decision.
        with self.server(FakeResponse(body(table()))):
            minimum_sync.sync()
        installed = self._installed(NOW - timedelta(days=10))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(
                FakeResponse(body(table(NOW - timedelta(days=30))))
            )
        self.assertFalse(changed)
        self.assertEqual(os.environ.get(_MINIMUM_ENV, ""), "")
        self.assertIn("Keeping the installed table", output)
        self.assertNotIn("last fetched table", output)

    def test_an_explicit_table_path_is_not_replaced(self) -> None:
        pinned = self._installed(NOW - timedelta(days=40))
        with mock.patch.dict(os.environ, {_MINIMUM_ENV: str(pinned)}):
            changed, output = self._sync(FakeResponse(body(table())))
            self.assertEqual(os.environ[_MINIMUM_ENV], str(pinned))
        self.assertFalse(changed)
        self.assertIn("pins the minimum table", output)

    def test_a_cached_table_older_than_the_installed_table_is_not_used(self) -> None:
        # A new release can ship a newer table than the last fetch.
        with self.server(FakeResponse(body(table(NOW - timedelta(days=30))))):
            minimum_sync.sync()
        installed = self._installed(NOW)
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(
                urllib.error.HTTPError("u", 304, "Not Modified", {}, None)
            )
        self.assertFalse(changed)
        self.assertEqual(os.environ.get(_MINIMUM_ENV, ""), "")
        self.assertIn("older than the installed table", output)


class CommandLineTests(MinimumSyncTestCase):
    """The fetch is on by default, and it belongs to the security profile."""

    def test_the_audit_fetches_by_default(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0):
                with mock.patch.object(security, "sync_minimum_table") as fetch:
                    result = cli.main(["audit", "security", "--vm"])
        self.assertEqual(result, 0)
        fetch.assert_called_once()

    def test_the_opt_out_flag_skips_the_fetch(self) -> None:
        target = security.SecurityTarget("standalone", "vm", True)
        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", return_value=0):
                with mock.patch.object(security, "sync_minimum_table") as fetch:
                    result = cli.main(
                        ["audit", "security", "--vm", "--no-fetch-minimums"]
                    )
        self.assertEqual(result, 0)
        fetch.assert_not_called()

    def test_the_default_fetch_runs_before_the_audit(self) -> None:
        order: list[str] = []
        target = security.SecurityTarget("standalone", "vm", True)

        def fake_fetch(**kwargs):  # noqa: ANN003
            order.append("fetch")
            return True

        def fake_audit(*args, **kwargs):  # noqa: ANN002, ANN003
            order.append("audit")
            return 0

        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch("cmax.audit_runner.run", side_effect=fake_audit):
                with mock.patch.object(
                    security, "sync_minimum_table", side_effect=fake_fetch
                ):
                    result = cli.main(["audit", "security", "--vm"])
        self.assertEqual(result, 0)
        self.assertEqual(order, ["fetch", "audit"])

    def test_the_refresh_runs_before_the_fetch(self) -> None:
        # The refresh resolves its write target through
        # CLUSTERMAX_MINIMUM_VERSIONS, which a completed fetch points at the
        # cache. Refreshing first keeps the locally rebuilt table out of the
        # cache, so the cached bytes and the stored validators stay the
        # published ones.
        order: list[str] = []
        target = security.SecurityTarget("standalone", "vm", True)

        with mock.patch.object(security, "detect_target", return_value=target):
            with mock.patch(
                "cmax.audit_runner.run",
                side_effect=lambda *a, **k: order.append("audit") or 0,
            ):
                with mock.patch.object(
                    security,
                    "refresh_minimum_table",
                    side_effect=lambda **k: order.append("refresh"),
                ):
                    with mock.patch.object(
                        security,
                        "sync_minimum_table",
                        side_effect=lambda **k: order.append("fetch") or True,
                    ):
                        result = cli.main(
                            [
                                "audit",
                                "security",
                                "--vm",
                                "--refresh-minimums",
                            ]
                        )
        self.assertEqual(result, 0)
        self.assertEqual(order, ["refresh", "fetch", "audit"])

    def test_the_opt_out_is_rejected_outside_the_security_subcommand(self) -> None:
        # The flag belongs to `cmax audit security`. On this branch the plain
        # `cmax audit` parser does not carry it, so argparse rejects it.
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit):
                cli.main(["audit", "--no-fetch-minimums"])
        self.assertIn("--no-fetch-minimums", stderr.getvalue())

    def test_the_module_reports_the_outcome_on_the_command_line(self) -> None:
        output = io.StringIO()
        with self.server(FakeResponse(body(table()))):
            with contextlib.redirect_stdout(output):
                code = minimum_sync.main([])
        self.assertEqual(code, 0)
        self.assertIn("fetched the published minimum table", output.getvalue())

    def test_the_module_exits_non_zero_for_a_failed_fetch(self) -> None:
        output = io.StringIO()
        with self.server(urllib.error.URLError("no outbound network")):
            with contextlib.redirect_stdout(output):
                code = minimum_sync.main([])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
