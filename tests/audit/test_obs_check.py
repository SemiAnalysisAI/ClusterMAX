"""Unit tests for the bundled observability-backend isolation check."""

from __future__ import annotations

import base64
import json
import shutil
import ssl
import subprocess
import tempfile
from http.client import BadStatusLine, IncompleteRead
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest
from unittest.mock import patch

from cmax import audit_report, obs_check, obs_discovery, runtime_paths, security


def _routes(targets, credentials):
    return {target.rstrip("/"): credentials for target in targets}


def grafana_metadata(url, datasources=2):
    if url.endswith(obs_check.GRAFANA_HEALTH):
        return 200, json.dumps({"database": "ok", "version": "12.3.6"}), {}
    if url.endswith(obs_check.GRAFANA_DATASOURCES):
        return 200, json.dumps([
            {"id": index + 1, "type": "prometheus"} for index in range(datasources)
        ]), {}
    return None


def guarded_metrics(accepted, accounts=("acme", "globex")):
    def get(url, header):
        if url.endswith(obs_check.GRAFANA_HEALTH) or header not in accepted:
            return 401, "", {"www-authenticate": 'Basic realm="prom"'}
        if "/label/account/values" in url:
            return 200, json.dumps({"status": "success", "data": accounts}), {}
        if "/label/" in url:
            return 200, json.dumps({"status": "success", "data": ["default"]}), {}
        return 404, "", {}
    return get


class RequestDrivenClock:
    def __init__(self) -> None:
        self.now = 0.0

    def read(self) -> float:
        return self.now

    def spend(self, seconds: float) -> None:
        self.now += seconds


class TransportSafetyTests(unittest.TestCase):
    def test_malformed_http_responses_are_missing_evidence(self) -> None:
        for error in (BadStatusLine("not HTTP"), IncompleteRead(b"partial")):
            with mock.patch.object(obs_check._OPENER, "open", side_effect=error):
                self.assertEqual(obs_check._get("http://wrong-protocol.example", ""), (None, "", {}))

    def test_unreachable_endpoint_does_not_check_the_admin_path(self) -> None:
        requested: list[str] = []

        def no_response(url: str, header: str):
            requested.append(url)
            return (None, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=no_response):
            result = obs_check.check_endpoint(
                "https://prom.example",
                "",
                [100, obs_check.MAX_UNANSWERED_PER_TARGET_MS],
            )

        self.assertFalse(result["reachable"])
        self.assertEqual(result["requests"], obs_check.DEAD_DIRECT_PATH_REQUESTS)
        self.assertFalse(any(url.endswith(obs_check.ADMIN) for url in requested))
        self.assertEqual(sum("/label/" in url for url in requested), 1)

class PureFunctionTests(unittest.TestCase):
    def test_auth_header(self) -> None:
        self.assertEqual(obs_check.auth_header(token="abc"), "Bearer abc")
        expected = "Basic " + base64.b64encode(b"u:p").decode("ascii")
        self.assertEqual(obs_check.auth_header(basic="u:p"), expected)
        self.assertEqual(obs_check.auth_header(token="t", basic="u:p"), "Bearer t")
        self.assertEqual(obs_check.auth_header(), "")

    def test_is_grafana_health(self) -> None:
        ok = json.dumps({"commit": "x", "database": "ok", "version": "12.3.6"})
        self.assertTrue(obs_check.is_grafana_health(200, ok))
        self.assertFalse(obs_check.is_grafana_health(200, "Prometheus is Healthy."))
        self.assertFalse(obs_check.is_grafana_health(404, ""))

    def test_parse_datasources(self) -> None:
        body = json.dumps([{"id": 1, "type": "prometheus", "url": "http://x:9090"}])
        self.assertEqual(obs_check.parse_datasources(200, body), [{"id": 1, "type": "prometheus"}])
        self.assertEqual(obs_check.parse_datasources(401, ""), [])

    def test_extract_label_values(self) -> None:
        body = json.dumps({"status": "success", "data": ["a", "b", ""]})
        self.assertEqual(obs_check.extract_label_values(200, body), {"a", "b"})
        self.assertEqual(obs_check.extract_label_values(403, ""), set())

    def test_check_reports_live_progress_for_each_target(self) -> None:
        messages: list[str] = []
        unreachable = {"reachable": False, "requests": 4, "labels": {}}
        answered = {
            "reachable": True,
            "query_ok": True,
            "requests": 3,
            "labels": {},
        }
        with mock.patch.object(
            obs_check,
            "check_endpoint",
            side_effect=(unreachable, answered),
        ):
            obs_check.check(
                ["https://10.0.0.1:9090/path", "https://prom.example"],
                progress=messages.append,
            )

        self.assertIn("backend 1/2: checking https://10.0.0.1:9090", messages)
        self.assertTrue(
            any(
                "backend 1/2: no response; 4 request(s)" in line
                for line in messages
            )
        )
        self.assertIn("backend 2/2: checking https://prom.example", messages)
        self.assertTrue(
            any(
                "backend 2/2: query answered; 3 request(s)" in line
                for line in messages
            )
        )

    def test_tenant_labels_exclude_own_namespace_infrastructure_and_placeholders(self) -> None:
        cases = [
            ({"account": {"tenant-a", "tenant-b", "tenant-c"}}, True, {"account": 3}),
            ({"account": {"tenant-a"}}, False, {}),
            ({"namespace": {"default", "kube-system", "monitoring"}}, False, {}),
            ({"namespace": {"default", "acme", "globex"}}, True, {"namespace": 2}),
            ({"account": {"(null)", "tenant-a"}}, False, {}),
        ]
        for labels, cross, counts in cases:
            with self.subTest(labels=labels):
                self.assertEqual(obs_check.classify_cross_tenant(labels, "default"), (cross, counts))


class AuthSchemeTests(unittest.TestCase):
    def test_auth_scheme_distinguishes_guards_redirects_and_unreachable_targets(self) -> None:
        for status, headers, expected in (
            (401, {"www-authenticate": 'Basic realm="prom"'}, "basic"),
            (401, {"www-authenticate": "Bearer"}, "bearer"),
            (401, {}, "challenge"),
            (302, {"location": "/oauth2/start?rd=%2F"}, "oauth-proxy"),
            (302, {"location": "https://sso/login"}, "login-redirect"),
            (200, {}, "none"),
            (None, {}, "unreachable"),
            (403, {}, "forbidden"),
        ):
            with self.subTest(status=status, headers=headers):
                self.assertEqual(obs_check.detect_auth_scheme(status, headers), expected)


class _RedirectHandler(BaseHTTPRequestHandler):
    LOGIN_PATH = "/oauth2/start"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.startswith(self.LOGIN_PATH):
            body = b"<html><body>Sign in</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(302)
        self.send_header("Location", f"{self.LOGIN_PATH}?rd=%2F")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # keep the test output clean
        return


class RealRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_sso_redirect_is_reported_and_not_followed(self) -> None:
        status, _body, headers = obs_check._get(f"{self.base}/api/health", "")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("location"), "/oauth2/start?rd=%2F")
        self.assertEqual(obs_check.detect_auth_scheme(status, headers), "oauth-proxy")
        summary = obs_check.check([self.base], own_namespace="default")
        self.assertTrue(summary["auth_required"])
        self.assertEqual(summary["auth_schemes"], {"oauth-proxy": 1})
        self.assertFalse(summary["unauth_query_ok"])
        self.assertFalse(summary["cross_tenant_series_visible"])


@pytest.mark.skipif(shutil.which("openssl") is None, reason="local TLS fixture needs openssl")
def test_https_rejects_an_untrusted_local_certificate() -> None:
    assert obs_check._TLS_CTX.check_hostname
    with tempfile.TemporaryDirectory() as directory:
        key, certificate = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=localhost", "-days", "1",
                "-keyout", str(key), "-out", str(certificate),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = obs_check._get(
                f"https://localhost:{server.server_port}/login", ""
            )
            assert status is None
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class SchemeUpgradeTests(unittest.TestCase):
    def test_https_upgrade_preserves_the_target_host_path_and_service_port(self) -> None:
        explicit = "http://prom:9090/api/health"
        for origin, location, expected in (
            (explicit, "https://prom:9090/api/health", "https://prom:9090/api/health"),
            ("http://prom/api/health", "https://prom/api/health", "https://prom/api/health"),
            *[(explicit, location, "") for location in (
                "https://other:9090/api/health", "https://prom:9090/login",
                "http://prom:9090/api/health", "/oauth2/start", "",
                "https://prom/api/health", "https://prom:8443/api/health",
                "https://prom:99999/api/health", "https://prom:notaport/api/health",
                "https://prom:-1/api/health",
            )],
        ):
            with self.subTest(origin=origin, location=location):
                self.assertEqual(obs_check._scheme_upgrade(origin, location), expected)


class PlatformFingerprintTests(unittest.TestCase):
    def test_backend_fingerprints_and_health_fallback(self) -> None:
        for body, expected in (
            ({"application": "Grafana Mimir", "version": "2.14"}, "mimir"),
            ({"version": "0.36.1", "branch": "thanos"}, "thanos"),
            ({"version": "3.1.0", "revision": "abc", "goVersion": "go1.23"}, "prometheus"),
        ):
            with self.subTest(product=expected):
                self.assertEqual(
                    obs_check.classify_buildinfo(200, json.dumps({"status": "success", "data": body})),
                    expected,
                )
        self.assertEqual(obs_check.classify_buildinfo(404, ""), "")
        for body, expected in (
            ("Prometheus Server is Healthy.", "prometheus"),
            ("VictoriaMetrics", "victoriametrics"),
            ("OK", ""),
        ):
            with self.subTest(health=body):
                self.assertEqual(obs_check.classify_health_body(200, body), expected)


class CheckSanitizationTests(unittest.TestCase):
    def test_separate_single_tenant_backends_do_not_form_a_leak(self) -> None:
        with mock.patch.object(obs_check, "check_endpoint", side_effect=[
            {"reachable": True, "query_ok": True, "labels": {"account": {"tenant-a"}}},
            {"reachable": True, "query_ok": True, "labels": {"account": {"tenant-b"}}},
        ]):
            result = obs_check.check(["https://first.example", "https://second.example"])
        self.assertFalse(result["cross_tenant_series_visible"])
        self.assertEqual(result["foreign_tenant_counts"], {})

    def test_isolated_grafana_sources_are_classified_separately(self) -> None:
        def get(url, header):
            metadata = grafana_metadata(url, 2)
            if metadata is not None:
                return metadata
            values = []
            if "/label/account/values" in url:
                values = ["tenant-a" if "/proxy/1/" in url else "tenant-b"]
            return 200, json.dumps({"status": "success", "data": values}), {}
        with mock.patch.object(obs_check, "_get", side_effect=get):
            result = obs_check.check(["https://grafana.example"])
        self.assertFalse(result["cross_tenant_series_visible"])
        self.assertEqual(result["foreign_tenant_counts"], {})
    def test_check_returns_counts_only_never_rosters(self) -> None:
        health = (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
        datasources = (200, json.dumps([{"id": 1, "type": "prometheus"}]), {})

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return health
            if url.endswith("/api/datasources"):
                return datasources if header else (401, "", {"www-authenticate": "Basic"})
            if "/label/account/values" in url:
                if not header:
                    return (401, "", {"www-authenticate": "Basic"})
                return (200, json.dumps({"status": "success", "data": ["semi", "acme", "globex"]}), {})
            if "/label/" in url:
                if not header:
                    return (401, "", {"www-authenticate": "Basic"})
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://grafana.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://grafana.example"],
                    [("env", obs_check.auth_header(basic="u:p"))],
                ),
            )

        self.assertTrue(summary["configured"])
        self.assertTrue(summary["authenticated"])
        self.assertEqual(summary["backends_reachable"], 1)
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertTrue(summary["grafana_datasources_listable"])
        self.assertEqual(summary["foreign_tenant_counts"]["account"], 3)
        self.assertEqual(summary["backend_platforms"], {"grafana": 1})
        blob = json.dumps(summary)
        for name in ("acme", "globex", "semi"):
            self.assertNotIn(name, blob)

    def test_check_clean_backend_passes(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (404, "", {})  # not grafana -> prometheus path
            if url.endswith("/api/v1/status/buildinfo"):
                body = json.dumps(
                    {"status": "success", "data": {"version": "3.1.0", "revision": "a", "goVersion": "go1.23"}}
                )
                return (200, body, {})
            if "/label/" in url:
                if not header:
                    return (401, "", {"www-authenticate": "Bearer"})
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://prom.example"],
                    [("env", obs_check.auth_header(token="t"))],
                ),
            )
        self.assertFalse(summary["cross_tenant_series_visible"])
        self.assertFalse(summary["unauth_query_ok"])  # a token was supplied
        self.assertEqual(summary["foreign_tenant_counts"], {})
        self.assertEqual(summary["backend_platforms"], {"prometheus": 1})
        self.assertEqual(summary["auth_schemes"], {"bearer": 1})
        self.assertTrue(summary["auth_required"])

    def test_guarded_backends_never_claim_open_or_cross_tenant_access(self) -> None:
        credential = [("default", obs_check.credential_header("basic", "admin:admin"))]
        for status, headers, scheme, credentials in (
            (401, {"www-authenticate": "Basic"}, "basic", []),
            (401, {"www-authenticate": "Bearer"}, "bearer", []),
            (401, {}, "challenge", []),
            (403, {}, "forbidden", []),
            (302, {"location": "/oauth2/start"}, "oauth-proxy", []),
            (302, {"location": "/login"}, "login-redirect", []),
            (403, {}, "forbidden", credential),
        ):
            with self.subTest(scheme=scheme, credentials=bool(credentials)):
                with mock.patch.object(obs_check, "_get", return_value=(status, "", headers)):
                    summary = obs_check.check(
                        ["https://prom.example"],
                        credentials_by_target=_routes(["https://prom.example"], credentials),
                    )
                self.assertEqual(summary["auth_schemes"], {scheme: 1})
                self.assertTrue(summary["auth_required"])
                self.assertFalse(summary["unauth_query_ok"])
                self.assertFalse(summary["cross_tenant_series_visible"])
                self.assertEqual(summary["credential_sources_accepted"], {})
                self.assertEqual(summary["credentials_offered"], len(credentials))

    def test_a_guard_already_found_is_never_downgraded(self) -> None:
        result = {"auth_scheme": "basic"}
        obs_check.merge_auth_scheme(result, 200, {})
        self.assertEqual(result["auth_scheme"], "basic")
        fresh: dict = {"auth_scheme": ""}
        obs_check.merge_auth_scheme(fresh, 200, {})
        self.assertEqual(fresh["auth_scheme"], "none")
        obs_check.merge_auth_scheme(fresh, 401, {"www-authenticate": "Bearer"})
        self.assertEqual(fresh["auth_scheme"], "bearer")
        for stale in ("unreachable", "redirect", "unknown", "none"):
            result = {"auth_scheme": stale}
            obs_check.merge_auth_scheme(result, 403, {})
            self.assertEqual(result["auth_scheme"], "forbidden", stale)
    def test_credential_escalation_stops_at_the_first_credential_that_reads(self) -> None:
        accepted = obs_check.credential_header("basic", "admin:prom-operator")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header != accepted:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["a", "b", "c"]}), {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [
            ("service-account", obs_check.credential_header("bearer", "wrong")),
            ("default", accepted),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(summary["foreign_tenant_counts"]["account"], 3)
        self.assertEqual(summary["credential_sources_accepted"], {"default": 1})
        self.assertTrue(summary["authenticated"])
        self.assertEqual(summary["auth_schemes"], {"basic": 1})
        self.assertFalse(summary["unauth_query_ok"])
        blob = json.dumps(summary)
        for secret in ("prom-operator", "admin:admin", "wrong", accepted):
            self.assertNotIn(secret, blob)

    def test_non_tenant_reads_do_not_hide_a_later_tenant_credential(self) -> None:
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")
        for source in (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.PROCESS_ENV_CREDENTIAL_SOURCE):
            non_tenant = obs_check.credential_header("bearer", "non-tenant-secret")
            credentials = [(source, non_tenant), ("kubernetes-secret", tenant)]
            with self.subTest(source=source), mock.patch.object(
                obs_check, "_get", side_effect=guarded_metrics((non_tenant, tenant))
            ), mock.patch.object(
                obs_check, "select_credentials", lambda pairs, **_: list(pairs)
            ):
                summary = obs_check.check(
                    ["https://prom.example"],
                    credentials_by_target=_routes(["https://prom.example"], credentials),
                )
            self.assertTrue(summary["cross_tenant_series_visible"])
            self.assertEqual(summary["credential_sources_accepted"], {"kubernetes-secret": 1})
            self.assertEqual(summary["cross_tenant_credential_sources"], {"kubernetes-secret": 1})
            for secret in (non_tenant, tenant, "non-tenant-secret", "tenant-secret"):
                self.assertNotIn(secret, json.dumps(summary))

    def test_fallback_reads_keep_the_finding_and_the_correct_attribution(self) -> None:
        operator = obs_check.credential_header("bearer", "operator-secret")
        shell = obs_check.credential_header("bearer", "shell-secret")
        cases = [
            ([(obs_check.OPERATOR_CREDENTIAL_SOURCE, operator), ("default", "Basic rejected")],
             (operator,), obs_check.OPERATOR_CREDENTIAL_SOURCE, {}),
            ([(obs_check.PROCESS_ENV_CREDENTIAL_SOURCE, shell)],
             (shell,), obs_check.PROCESS_ENV_CREDENTIAL_SOURCE,
             {obs_check.PROCESS_ENV_CREDENTIAL_SOURCE: 1}),
            ([(obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
              (obs_check.PROCESS_ENV_CREDENTIAL_SOURCE, shell)],
             (operator, shell), obs_check.PROCESS_ENV_CREDENTIAL_SOURCE,
             {obs_check.PROCESS_ENV_CREDENTIAL_SOURCE: 1}),
        ]
        for credentials, accepted, source, attributed in cases:
            with self.subTest(sources=[pair[0] for pair in credentials]), mock.patch.object(
                obs_check, "_get", side_effect=guarded_metrics(accepted)
            ):
                summary = obs_check.check(
                    ["https://prom.example"],
                    credentials_by_target=_routes(["https://prom.example"], credentials),
                )
            self.assertTrue(summary["cross_tenant_series_visible"])
            self.assertEqual(summary["queries_answered"], 1)
            self.assertEqual(summary["credential_sources_accepted"], {source: 1})
            self.assertEqual(summary["cross_tenant_credential_sources"], attributed)

    def test_the_budget_covers_the_worst_case_sweep_on_every_target(self) -> None:
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")

        def fake_get(url: str, header: str):
            metadata = grafana_metadata(url, 2)
            if metadata is not None:
                return metadata
            if header not in (operator, tenant):
                return (403, "", {})  # the proxy refuses anonymous and both decoys
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
            return (200, json.dumps({"status": "success", "data": ["default"]}), {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("grafana-ini", obs_check.credential_header("basic", "decoy:one")),
            ("grafana-provisioning", obs_check.credential_header("basic", "decoy:two")),
            ("kubernetes-secret", tenant),
        ]
        targets = [f"https://grafana-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
        self.assertEqual(
            summary["cross_tenant_credential_sources"],
            {"kubernetes-secret": obs_check.MAX_TARGETS},
        )
        self.assertLessEqual(summary["request_count"], obs_check.MAX_REQUESTS)

    def test_a_dead_provisioned_backend_exceeds_the_budget_and_says_so(self) -> None:
        def fake_get(url: str, header: str):
            metadata = grafana_metadata(url, 2)
            if metadata is not None:
                return metadata
            return (502, "", {})  # the datasource behind the proxy is gone

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.credential_header("bearer", "op")),
            ("kubernetes-secret", obs_check.credential_header("basic", "prom:secret")),
            ("default", obs_check.credential_header("basic", "admin:admin")),
            ("process-env", obs_check.credential_header("basic", "decoy:one")),
        ]
        targets = [f"https://grafana-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_REQUESTS", 240
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertGreater(summary["targets_skipped"], 0)
        self.assertLessEqual(summary["request_count"], 240)
        self.assertEqual(summary["queries_answered"], 0)
        self.assertFalse(summary["cross_tenant_series_visible"])

    def test_a_half_swept_target_is_counted_as_skipped(self) -> None:
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")

        def fake_get(url: str, header: str):
            metadata = grafana_metadata(url, 2)
            if metadata is not None:
                return metadata
            if header not in (operator, tenant):
                return (403, "", {})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("kubernetes-secret", tenant),
        ]
        budget = [15]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://grafana.example", credentials, budget
            )
        self.assertEqual(result["credential_source"], obs_check.OPERATOR_CREDENTIAL_SOURCE)
        self.assertTrue(result["budget_exhausted"])
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            complete = obs_check.check_endpoint_escalating(
                "https://grafana.example", credentials, [obs_check.MAX_REQUESTS]
            )
        self.assertEqual(complete["credential_source"], "kubernetes-secret")
        self.assertFalse(complete.get("budget_exhausted"))

    def test_a_complete_pass_that_spends_the_last_request_is_not_called_incomplete(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"status": "success", "data": {"version": "2.51.0"}}), {})
            return (401, "", {"www-authenticate": "Basic realm=x"})

        def run(limit: int, credentials: list) -> tuple[int, dict]:
            seen: list[str] = []

            def counting_get(url: str, header: str):
                seen.append(url)
                return fake_get(url, header)

            with mock.patch.object(obs_check, "_get", side_effect=counting_get):
                result = obs_check.check_endpoint_escalating(
                    "https://prom.example", credentials, [limit]
                )
            return len(seen), result

        one = [("kubernetes-secret", obs_check.credential_header("basic", "prom:secret"))]
        unbounded_requests, unbounded = run(obs_check.MAX_REQUESTS, one)
        self.assertFalse(unbounded.get("budget_exhausted"))
        exact_requests, exact = run(unbounded_requests, one)
        self.assertEqual(exact_requests, unbounded_requests)
        self.assertFalse(exact.get("budget_exhausted"))
        _short_requests, short = run(unbounded_requests - 1, one)
        self.assertTrue(short["budget_exhausted"])
        two = one + [("grafana-ini", obs_check.credential_header("basic", "admin:admin"))]
        _two_requests, two_result = run(unbounded_requests, two)
        self.assertTrue(two_result["budget_exhausted"])

    def test_a_backend_that_answers_nothing_is_stopped_before_it_spends_the_budget(self) -> None:
        calls: list[str] = []
        def fake_get(url: str, header: str):
            calls.append(url)
            metadata = grafana_metadata(url, 2)
            if metadata is not None:
                return metadata
            return (None, "", {})  # the proxy never answers

        targets = [f"https://grafana-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.credential_header("bearer", "op")),
            ("kubernetes-secret", obs_check.credential_header("basic", "prom:secret")),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_UNANSWERED_MS", -1
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertEqual(summary["targets_skipped"], obs_check.MAX_TARGETS)
        self.assertEqual(summary["queries_answered"], 0)
        self.assertFalse(summary["cross_tenant_series_visible"])
        self.assertEqual(calls, [])

    def test_the_allowance_can_run_out_inside_one_label_sweep(self) -> None:
        clock = RequestDrivenClock()

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.GRAFANA_HEALTH):
                clock.spend(0.1)
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                clock.spend(0.1)
                return (200, json.dumps({"version": "2.53.0", "revision": "a", "goVersion": "1"}), {})
            clock.spend(obs_check.REQUEST_TIMEOUT_S)  # every label read hangs
            return (None, "", {})

        allowance = 2 * int(obs_check.REQUEST_TIMEOUT_S * 1000)
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_UNANSWERED_MS", allowance
        ), mock.patch.object(obs_check.time, "monotonic", clock.read):
            budget = [obs_check.MAX_REQUESTS, allowance]
            result = obs_check.check_endpoint("https://prom.example", "", budget)
        self.assertEqual(list(result["labels"]), ["account", "org_id"])
        self.assertLess(len(result["labels"]), len(obs_check.TENANT_LABEL_KEYS))
        self.assertTrue(obs_check.out_of_budget(budget))
        self.assertGreater(budget[0], 0)
        self.assertTrue(result["budget_exhausted"])

    def test_an_operator_read_cut_short_inside_its_own_sweep_still_says_so(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            if not header:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (200, json.dumps({"status": "success", "data": ["acme"]}), {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.credential_header("bearer", "op"))
        ]
        budget = [8]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://prom.example", credentials, budget
            )
        self.assertEqual(result["credential_source"], obs_check.OPERATOR_CREDENTIAL_SOURCE)
        self.assertLess(len(result["labels"]), len(obs_check.TENANT_LABEL_KEYS))
        self.assertTrue(result["budget_exhausted"])

    def test_a_hanging_proxy_cannot_be_kept_alive_by_the_passes_that_answer(self) -> None:
        clock = RequestDrivenClock()

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.GRAFANA_HEALTH):
                clock.spend(0.05)
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith(obs_check.GRAFANA_DATASOURCES):
                clock.spend(0.05)
                return (
                    200,
                    json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]),
                    {},
                )
            clock.spend(obs_check.REQUEST_TIMEOUT_S)  # the proxy holds the connection
            return (None, "", {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.credential_header("bearer", "op")),
            ("kubernetes-secret", obs_check.credential_header("basic", "p:s")),
            ("grafana-ini", obs_check.credential_header("basic", "a:b")),
            ("process-env", obs_check.credential_header("bearer", "c")),
        ]
        targets = [f"https://grafana-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        allowed = obs_check.MAX_UNANSWERED_MS / 1000 + obs_check.REQUEST_TIMEOUT_S
        self.assertLess(clock.now, allowed * 2)
        self.assertLess(summary["request_count"], obs_check.MAX_REQUESTS // 4)
        self.assertEqual(summary["targets_skipped"], obs_check.MAX_TARGETS)

    def test_one_hanging_backend_does_not_spend_the_coverage_of_the_targets_behind_it(
        self,
    ) -> None:
        clock = RequestDrivenClock()
        hanging = "https://grafana-0.example"

        def fake_get(url: str, header: str):
            if url.startswith(hanging):
                if url.endswith(obs_check.GRAFANA_HEALTH):
                    return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
                if url.endswith(obs_check.GRAFANA_DATASOURCES):
                    return (
                        200,
                        json.dumps(
                            [{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]
                        ),
                        {},
                    )
                clock.spend(obs_check.REQUEST_TIMEOUT_S)  # the proxy never answers
                return (None, "", {})
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            if not header:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        credentials = [
            ("kubernetes-secret", obs_check.credential_header("basic", "p:s")),
            ("grafana-ini", obs_check.credential_header("basic", "a:b")),
            ("process-env", obs_check.credential_header("bearer", "c")),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        targets = [hanging] + [f"https://prom-{i}.example" for i in range(1, obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertEqual(summary["targets_skipped"], 1)
        self.assertEqual(summary["queries_answered"], obs_check.MAX_TARGETS - 1)
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(
            summary["cross_tenant_credential_sources"],
            {"kubernetes-secret": obs_check.MAX_TARGETS - 1},
        )
        self.assertLessEqual(clock.now * 1000, obs_check.MAX_UNANSWERED_PER_TARGET_MS)
        self.assertTrue(summary["grafana_datasources_listable"])

    def test_firewalled_targets_are_fully_assessed_without_credential_retries(self) -> None:
        credentials = [
            ("kubernetes-secret", obs_check.credential_header("basic", "p:s")),
            ("grafana-ini", obs_check.credential_header("basic", "a:b")),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        targets = [f"https://prom-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        for escalation in (False, True):
            clock = RequestDrivenClock()
            headers = []
            overhead = obs_check.REQUEST_TIMEOUT_S * 0.25

            def get(url, header):
                headers.append(header)
                clock.spend(obs_check.REQUEST_TIMEOUT_S + overhead)
                return None, "", {}

            with self.subTest(escalation=escalation), mock.patch.object(
                obs_check, "_get", side_effect=get
            ), mock.patch.object(obs_check.time, "monotonic", clock.read):
                summary = obs_check.check(
                    targets,
                    credentials_by_target=_routes(targets, credentials if escalation else []),
                )
            self.assertEqual(summary["targets_skipped"], 0)
            self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
            self.assertEqual(summary["backends_reachable"], 0)
            self.assertEqual(summary["queries_answered"], 0)
            self.assertEqual(summary["credential_sources_accepted"], {})
            self.assertEqual(set(headers), {""})
            dead_requests = obs_check.MAX_TARGETS * obs_check.DEAD_DIRECT_PATH_REQUESTS
            self.assertEqual(clock.now, dead_requests * (obs_check.REQUEST_TIMEOUT_S + overhead))
            self.assertGreater(clock.now, dead_requests * obs_check.REQUEST_TIMEOUT_S)
            self.assertLess(clock.now * 1000, obs_check.MAX_UNANSWERED_MS)

    def test_credential_selection_reserves_tenant_and_default_tries(self) -> None:
        rich = [
            ("env", "Bearer operator"), ("grafana-ini", "Basic a"),
            ("grafana-provisioning", "Basic b"), ("process-env", "Bearer c"),
            ("default", "Basic admin"), ("default", "Basic prom"),
        ]
        two_operators = [rich[0], ("env", "Basic operator"), *rich[1:]]
        cases = [
            ("rich", rich, ["env", "grafana-ini", "grafana-provisioning", "default"]),
            ("no-operator", rich[1:], ["grafana-ini", "grafana-provisioning", "default", "default"]),
            ("no-defaults", rich[:-2], ["env", "grafana-ini", "grafana-provisioning", "process-env"]),
            ("shell-cannot-displace-tenant", [
                ("service-account", "Bearer sa"), ("process-env", "Bearer shell"),
                ("kubernetes-secret", "Basic k8s"), *rich[-2:],
            ], ["service-account", "kubernetes-secret", "default", "default"]),
            ("shell-uses-spare-slot", [
                ("process-env", "Bearer shell"), ("kubernetes-secret", "Basic k8s"), *rich[-2:],
            ], ["kubernetes-secret", "default", "default", "process-env"]),
            ("two-operators-no-defaults", two_operators[:-2],
             ["env", "env", "grafana-ini", "grafana-provisioning"]),
            ("two-operators-with-defaults", two_operators,
             ["env", "grafana-ini", "grafana-provisioning", "default"]),
            ("only-operators-and-defaults", [*two_operators[:2], *rich[-2:]],
             ["env", "env", "default", "default"]),
        ]
        for label, credentials, expected in cases:
            with self.subTest(case=label):
                chosen = obs_check.select_credentials(credentials)
                self.assertEqual([source for source, _ in chosen], expected)
                self.assertLessEqual(len(chosen), obs_check.MAX_CREDENTIALS_PER_TARGET)
        for cap in (0, 1, 2, 3):
            with self.subTest(cap=cap):
                self.assertLessEqual(len(obs_check.select_credentials(rich, cap=cap)), cap)


    def test_the_vendor_defaults_are_still_tried_on_a_credential_rich_host(self) -> None:
        works = obs_check.credential_header("basic", "admin:admin")

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            if header != works:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        credentials = [
            ("service-account", obs_check.credential_header("bearer", "sa")),
            ("grafana-ini", obs_check.credential_header("basic", "a:b")),
            ("grafana-provisioning", obs_check.credential_header("basic", "c:d")),
            ("process-env", obs_check.credential_header("bearer", "e")),
            ("kubernetes-secret", obs_check.credential_header("basic", "f:g")),
            ("default", works),
            ("default", obs_check.credential_header("basic", "admin:prom-operator")),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://prom.example", credentials, [obs_check.MAX_REQUESTS]
            )
        self.assertTrue(result["query_ok"])
        self.assertEqual(result["credential_source"], "default")
        self.assertEqual(
            len(obs_check.select_credentials(credentials)),
            obs_check.MAX_CREDENTIALS_PER_TARGET,
        )

    def test_admin_probe_is_anonymous_with_tenant_or_operator_credentials(self) -> None:
        for source in ("kubernetes-secret", obs_check.OPERATOR_CREDENTIAL_SOURCE):
            admin_headers, label_headers = [], []
            credential = obs_check.credential_header("bearer", "test-token")

            def get(url, header):
                if url.endswith(obs_check.ADMIN):
                    admin_headers.append(header)
                    return 405, "", {}
                if url.endswith(obs_check.GRAFANA_HEALTH):
                    return 404, "", {}
                if url.endswith(obs_check.BUILDINFO):
                    return 200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {}
                label_headers.append(header)
                if not header:
                    return 401, "", {"www-authenticate": "Bearer"}
                return 200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {}

            with self.subTest(source=source), mock.patch.object(obs_check, "_get", side_effect=get):
                summary = obs_check.check(
                    ["https://prom.example"],
                    credentials_by_target=_routes(["https://prom.example"], [(source, credential)]),
                )
            self.assertEqual(admin_headers, [""])
            self.assertTrue(summary["admin_api_exposed"])
            self.assertEqual(summary["credential_sources_accepted"], {source: 1})
            self.assertEqual(set(label_headers), {"", credential})


    def test_a_target_cut_short_inside_its_sweep_is_counted_as_skipped(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            return (None, "", {})  # every label read hangs

        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_REQUESTS", 4
        ):
            summary = obs_check.check(
                ["https://prom-a.example", "https://prom-b.example"],
                own_namespace="default",
            )
        self.assertEqual(summary["targets_checked"], 2)
        self.assertEqual(summary["targets_skipped"], 2)
        self.assertEqual(summary["queries_answered"], 0)

    def test_a_slow_backend_that_answers_is_never_cut_short(self) -> None:
        clock = RequestDrivenClock()
        per_request = obs_check.REQUEST_TIMEOUT_S * 0.99

        def fake_get(url: str, header: str):
            clock.spend(per_request)
            return (200, json.dumps({"status": "success", "data": ["acme"]}), {})

        targets = [f"https://prom-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(targets, own_namespace="default")
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
        self.assertGreater(clock.now * 1000, obs_check.MAX_UNANSWERED_MS)

    def test_a_budget_with_no_time_allowance_is_untouched(self) -> None:
        result: dict = {}
        for budget in ([obs_check.MAX_REQUESTS], [obs_check.MAX_REQUESTS, None]):
            self.assertTrue(obs_check.want_request(result, budget))
            with mock.patch.object(obs_check, "_get", return_value=(None, "", {})):
                obs_check.spend_request(budget, "https://prom.example", "")
            self.assertEqual(budget[0], obs_check.MAX_REQUESTS - 1)
        self.assertNotIn("budget_exhausted", result)

    def test_an_open_backend_is_never_offered_a_credential(self) -> None:
        calls: list[str] = []

        def fake_get(url: str, header: str):
            calls.append(header)
            if url.endswith("/api/health"):
                return (404, "", {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://prom.example"],
                    [("default", obs_check.credential_header("basic", "admin:admin"))],
                ),
            )
        self.assertTrue(summary["unauth_query_ok"])
        self.assertEqual(summary["credential_sources_accepted"], {})
        self.assertEqual(set(calls), {""})

    def test_credentials_offered_counts_routes_across_all_targets(self) -> None:
        with mock.patch.object(obs_check, "_get", return_value=(403, "", {})):
            summary = obs_check.check(
                ["https://prom-a.example", "https://prom-b.example"],
                credentials_by_target={
                    "https://prom-a.example": [("env", "Bearer a")],
                    "https://prom-b.example": [("env", "Bearer b")],
                },
            )
        self.assertEqual(summary["credentials_offered"], 2)

    def test_escalation_respects_the_request_budget(self) -> None:
        def fake_get(url: str, header: str):
            return (401, "", {"www-authenticate": "Basic"})

        many = [("default", obs_check.credential_header("basic", f"u{i}:p")) for i in range(12)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], many),
            )
        self.assertLessEqual(summary["request_count"], obs_check.MAX_REQUESTS)


    def test_a_check_that_fails_before_a_refusal_still_reports_the_guard(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith("/api/v1/status/buildinfo"):
                body = json.dumps(
                    {"status": "success", "data": {"version": "3", "revision": "a", "goVersion": "g"}}
                )
                return (200, body, {})
            if "/api/v1/label/account/" in url:
                return (None, "", {})
            if "/api/v1/label/" in url:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (None, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertEqual(summary["auth_schemes"], {"basic": 1})
        self.assertTrue(summary["auth_required"])
    def test_a_guarded_admin_api_that_accepts_our_credential_is_not_a_finding(self) -> None:
        accepted = obs_check.credential_header("basic", "admin:prom-operator")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": "Basic"})
            if not header:
                return (401, "", {"www-authenticate": "Basic"})
            if url.endswith(obs_check.ADMIN):
                return (405, "", {})  # authorized, POST-only
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://prom.example"], [("default", accepted)]
                ),
            )
        self.assertEqual(summary["credential_sources_accepted"], {"default": 1})
        self.assertFalse(summary["admin_api_exposed"])
        self.assertFalse(summary["cross_tenant_series_visible"])

    def test_an_unauthenticated_admin_api_is_still_reported(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (404, "", {})
            if url.endswith(obs_check.ADMIN):
                return (405, "", {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertTrue(summary["admin_api_exposed"])

    def test_refused_label_passes_stop_cheaply_for_direct_and_grafana_backends(self) -> None:
        for grafana, refusal, credentials, count in (
            (False, (401, "", {"www-authenticate": "Basic"}), [], 1),
            (False, (302, "", {"location": "/oauth2/start?rd=%2F"}), [], 1),
            (True, (302, "", {"location": "/login"}), [], 1),
            (True, (403, "", {}), [
                ("default", obs_check.credential_header("basic", f"u{i}:p")) for i in range(4)
            ], obs_check.MAX_TARGETS),
        ):
            calls = {}

            def get(url, header):
                metadata = grafana_metadata(url, 1) if grafana else None
                if metadata is not None:
                    return metadata
                if "/label/" in url:
                    target = url.split("/api/", 1)[0]
                    calls[target, header] = calls.get((target, header), 0) + 1
                return refusal

            targets = [f"https://metrics-{i}.example" for i in range(count)]
            with self.subTest(grafana=grafana, status=refusal[0]), mock.patch.object(
                obs_check, "_get", side_effect=get
            ):
                summary = obs_check.check(
                    targets, credentials_by_target=_routes(targets, credentials)
                )
            self.assertTrue(calls)
            self.assertEqual(set(calls.values()), {1})
            self.assertEqual(summary["targets_skipped"], 0)
            self.assertLessEqual(summary["request_count"], obs_check.MAX_REQUESTS)
            self.assertTrue(summary["auth_required"])
            self.assertEqual(summary["queries_answered"], 0)
            self.assertFalse(summary["unauth_query_ok"])
            if grafana:
                self.assertTrue(summary["grafana_datasources_listable"])

    def test_one_transport_failure_does_not_end_the_label_sweep(self) -> None:
        asked: list[str] = []

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (404, "", {})
            if url.endswith("/api/v1/status/buildinfo"):
                body = json.dumps(
                    {"status": "success", "data": {"version": "3", "revision": "a", "goVersion": "g"}}
                )
                return (200, body, {})
            if "/label/" in url:
                key = url.rsplit("/label/", 1)[1].split("/")[0]
                asked.append(key)
                if key == "account":
                    return (None, "", {})  # one flaky request
                if key == "namespace":
                    return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertIn("namespace", asked)
        self.assertTrue(summary["cross_tenant_series_visible"])

    def test_a_target_the_budget_never_reached_is_counted_and_blocks_a_pass(self) -> None:
        def fake_get(url: str, header: str):
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        targets = [f"https://prom{index}.example" for index in range(8)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            with mock.patch.object(obs_check, "MAX_REQUESTS", 20):
                summary = obs_check.check(targets, own_namespace="default")
        self.assertGreater(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], 8)

    def test_unauthenticated_grafana_proxy_read_is_a_finding(self) -> None:
        def fake_get(url: str, header: str):
            metadata = grafana_metadata(url, 1)
            if metadata is not None:
                return metadata
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://grafana.example"], own_namespace="default")
        self.assertTrue(summary["unauth_query_ok"])


def test_non_kubernetes_audit_does_not_discover_other_kube_contexts():
    values = {}
    with patch.object(obs_discovery, "discover", return_value=obs_discovery.Discovery((), (), ())) as discover:
        security._inject_observability(values, target=security.SecurityTarget("slurm", "bare-metal"))
    assert discover.call_args.kwargs["services"] == {}


def test_captured_cross_tenant_result_reaches_both_reports(monkeypatch):
    monkeypatch.setenv("CLUSTERMAX_OBS_TARGETS", "https://metrics.example")
    summary = {
        "configured": True, "backends_reachable": 1, "read_open": True,
        "cross_tenant_series_visible": True, "foreign_tenant_counts": {"namespace": 2},
    }
    values = {}
    with patch.object(obs_check, "check", return_value=summary) as check:
        security._inject_observability(values, target=security.SecurityTarget("standalone", "bare-metal"))
    assert "credentials_by_target" not in check.call_args.kwargs
    assert next(c for c in security.evaluate_security(values)
                if c.id == "observability-isolation").status == security.CRITICAL
    rows = audit_report.evaluate(values, runtime_paths.package_runtime_root())
    assert next(c for c in rows if c.key == "observability-isolation").status == audit_report.FAIL


def test_missing_observability_evidence_is_not_a_pass():
    rows = security.evaluate_security({})
    assert next(c for c in rows if c.id == "observability-isolation").status == security.WARNING


@pytest.mark.parametrize("discovered", [False, True])
@pytest.mark.parametrize("exposure", [False, True])
def test_target_cap_preserves_incomplete_coverage_and_exposure(monkeypatch, discovered, exposure):
    targets = [f"http://metrics-{i}:9090" for i in range(obs_check.MAX_TARGETS + 2)]
    values = {}
    if discovered:
        monkeypatch.delenv("CLUSTERMAX_OBS_TARGETS", raising=False)
        monkeypatch.setenv("CLUSTERMAX_OBS_DISCOVER", "1")
        values = {"audit_data": {"healthChecks": {"monitoringStack": {
            "endpoints": [target.removeprefix("http://") for target in targets],
        }}}}
    else:
        monkeypatch.setenv("CLUSTERMAX_OBS_TARGETS", ",".join(targets + [targets[0] + "/"]))
    messages = []
    with patch.object(obs_discovery, "collect_local_sockets", return_value=""), \
         patch.object(obs_discovery, "collect_local_processes", return_value=""), \
         patch.object(obs_check, "check_endpoint", return_value={
             "reachable": True, "query_ok": True, "requests": 1,
             "unauth_query_ok": exposure,
         }) as endpoint:
        security._inject_observability(
            values, progress=messages.append,
            target=security.SecurityTarget("slurm", "bare-metal"),
        )
    summary = values["audit_data"]["security"]["observability"]
    assert summary["targets_found"] == len(targets)
    assert summary["targets_checked"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == 2
    assert endpoint.call_count == obs_check.MAX_TARGETS
    assert any("2 target(s) skipped" in message for message in messages)
    result = next(c for c in security.evaluate_security(values) if c.id == "observability-isolation")
    assert result.status == (security.CRITICAL if exposure else security.WARNING)


def test_target_cap_and_budget_skips_are_added():
    with patch.object(obs_check, "check_endpoint", return_value={"budget_exhausted": True}):
        summary = obs_check.check(
            [f"http://metrics-{i}:9090" for i in range(obs_check.MAX_TARGETS + 2)],
            own_namespace="default",
        )
    assert summary["targets_checked"] == obs_check.MAX_TARGETS
    assert summary["targets_skipped"] == obs_check.MAX_TARGETS + 2
