"""Offline sync tests use stub HTTP responses and an isolated XDG cache."""

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
        return self._url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class MinimumSyncTestCase(unittest.TestCase):
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
    def test_a_valid_table_is_cached_and_reported_as_updated(self) -> None:
        payload = body(table())
        with self.server(FakeResponse(payload, {"ETag": '"abc"'})):
            result = minimum_sync.sync()
        self.assertTrue(result.ok)
        self.assertTrue(result.updated)
        self.assertEqual(result.path, minimum_sync.cache_path())
        self.assertEqual(result.generated, "2026-08-20T07:32:09Z")
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
        self.assertTrue(result.ok)
        self.assertFalse(result.updated)
        self.assertEqual(result.generated, "2026-08-20T07:32:09Z")
        self.assertIn("unchanged", result.message)

    def test_a_not_modified_response_rejects_an_unusable_cached_table(self) -> None:
        """A 304 response has no body, so the cached file must pass validation."""
        with self.server(FakeResponse(body(table()), {"ETag": '"abc"'})):
            minimum_sync.sync()
        minimum_sync.cache_path().write_text('{"generated":"2026-08-20T07:32:09Z"}\n')
        with self.server(urllib.error.HTTPError("u", 304, "Not Modified", {}, None)):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertIsNone(result.path)
        self.assertIn("could not be read", result.message)
        self.assertIsNone(minimum_sync.cached_table())
        self.assertEqual(minimum_sync.read_state(), {})

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
        # Check the final response URL: HTTPS can redirect to unauthenticated HTTP.
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
    def _reject(self, payload: dict | str) -> str:
        with self.server(FakeResponse(body(payload))):
            result = minimum_sync.sync()
        self.assertFalse(result.ok)
        self.assertFalse(minimum_sync.cache_path().exists())
        return result.message

    def test_invalid_tables_are_refused(self) -> None:
        for name, overrides, expected in (
            ("json", None, ("not valid JSON",)),
            ("schema", {"schemaVersion": 2}, ("schema version 2", "Update clustermax")),
            ("components", {"components": {}}, ("no components",)),
            ("timestamp", {"generated": "not a date"}, ("generated timestamp",)),
        ):
            with self.subTest(case=name):
                document: dict | str = "{ this is not json"
                if overrides is not None:
                    document = {**table(), **overrides}
                message = self._reject(document)
                for text in expected:
                    self.assertIn(text, message)

    def test_an_older_published_table_is_refused(self) -> None:
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
        # The subprocess collector must inherit the selected table path.
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
        self.assertIn("Grading against the installed table (generated", output)
        self.assertIn("2026-08-20", output)

    def test_a_failed_fetch_falls_back_to_the_cached_table(self) -> None:
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
        with self.server(FakeResponse(body(table(NOW - timedelta(days=30))))):
            minimum_sync.sync()
        installed = self._installed(NOW)
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(urllib.error.URLError("no outbound network"))
        self.assertFalse(changed)
        self.assertEqual(os.environ.get(_MINIMUM_ENV, ""), "")
        self.assertIn("Grading against the installed table (generated", output)

    def test_a_rejected_older_publication_keeps_the_installed_table(self) -> None:
        # A rejected publication must not trigger cache fallback.
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


class StalenessTests(MinimumSyncTestCase):
    def _installed(self, data: dict) -> Path:
        path = Path(self.tmp.name) / "installed" / "minimum-versions.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        return path

    def _sync(self, now: datetime, *answers: object) -> tuple[bool, str]:
        output = io.StringIO()
        real = minimum_sync.stale_warning

        def at_now(refreshed, **kwargs):  # noqa: ANN001, ANN003
            return real(refreshed, now=now, **kwargs)

        with self.server(*answers), mock.patch.object(
            minimum_sync, "stale_warning", at_now
        ), contextlib.redirect_stdout(output):
            changed = security.sync_minimum_table()
        return changed, output.getvalue()

    def test_refreshed_is_preferred_over_generated(self) -> None:
        data = {**table(NOW - timedelta(days=30)), "refreshed": "2026-08-19T07:00:00Z"}
        self.assertEqual(minimum_sync.refreshed_stamp(data), "2026-08-19T07:00:00Z")
        self.assertEqual(
            minimum_sync.refreshed_stamp(table(NOW)), "2026-08-20T07:32:09Z"
        )

    def test_the_warning_starts_after_seven_days(self) -> None:
        stamp = "2026-08-20T07:32:09Z"
        self.assertIsNone(minimum_sync.stale_warning(stamp, now=NOW + timedelta(days=7)))
        warning = minimum_sync.stale_warning(stamp, now=NOW + timedelta(days=8))
        self.assertIsNotNone(warning)
        self.assertIn("8 days ago", warning)
        self.assertIsNotNone(minimum_sync.stale_warning(None, now=NOW))

    def test_a_failed_fetch_warns_for_a_stale_installed_table(self) -> None:
        installed = self._installed(table(NOW - timedelta(days=9)))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            _, output = self._sync(NOW, urllib.error.URLError("no outbound network"))
        self.assertIn("Grading against the installed table", output)
        self.assertIn("last refreshed 2026-08-11T07:32:09Z (9 days ago)", output)

    def test_a_failed_fetch_does_not_warn_for_a_fresh_installed_table(self) -> None:
        installed = self._installed(table(NOW - timedelta(days=2)))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            _, output = self._sync(NOW, urllib.error.URLError("no outbound network"))
        self.assertNotIn("last refreshed", output)

    def test_the_cached_refreshed_stamp_decides_and_not_generated(self) -> None:
        # The content is old, but the daily publish refreshed it yesterday.
        published = {**table(NOW - timedelta(days=20)), "refreshed": "2026-08-19T07:30:00Z"}
        with self.server(FakeResponse(body(published))):
            minimum_sync.sync()
        installed = self._installed(table(NOW - timedelta(days=30)))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            changed, output = self._sync(NOW, urllib.error.URLError("no outbound network"))
        self.assertTrue(changed)
        self.assertIn("Grading against the last fetched table", output)
        self.assertNotIn("last refreshed", output)
        # Ten days later the same cache is stale.
        os.environ[_MINIMUM_ENV] = ""
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            _, output = self._sync(
                NOW + timedelta(days=10), urllib.error.URLError("no outbound network")
            )
        self.assertIn("last refreshed 2026-08-19T07:30:00Z", output)

    def test_a_successful_fetch_does_not_warn(self) -> None:
        installed = self._installed(table(NOW - timedelta(days=30)))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            _, output = self._sync(
                NOW + timedelta(days=30), FakeResponse(body(table(NOW)))
            )
        self.assertIn("minimum table in use:", output)
        self.assertNotIn("last refreshed", output)

    def test_a_rejected_older_publication_does_not_warn(self) -> None:
        installed = self._installed(table(NOW - timedelta(days=10)))
        with mock.patch.object(security, "minimum_table_path", return_value=installed):
            _, output = self._sync(NOW, FakeResponse(body(table(NOW - timedelta(days=30)))))
        self.assertIn("Keeping the installed table", output)
        self.assertNotIn("last refreshed", output)


class CommandLineTests(MinimumSyncTestCase):
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
        # Refresh before fetch redirects the table path, preserving cached bytes and validators.
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
