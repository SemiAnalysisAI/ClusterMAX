"""Unit tests for the bundled observability-backend isolation check."""

from __future__ import annotations

import base64
import json
from http.client import BadStatusLine, IncompleteRead
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from cmax import obs_check


def _routes(targets, credentials):
    return {target.rstrip("/"): credentials for target in targets}


class RequestDrivenClock:
    """A `time.monotonic` stub whose time advances only when a request is made.

    A stubbed clock keeps the unanswered-time tests instant. Time must advance per
    REQUEST rather than per clock READ, because the number of reads depends on the
    accounting under test: `spend_request` reads the clock twice for a request that
    answers nothing and, through its early return, not at all for one that answers.
    A read-driven stub would therefore change its own premise as soon as that
    accounting changed, and would pin nothing.
    """

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
    def test_https_verifies_the_server_certificate_and_hostname(self) -> None:
        self.assertTrue(obs_check._TLS_CTX.check_hostname)
        self.assertEqual(obs_check._TLS_CTX.verify_mode, ssl.CERT_REQUIRED)

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

    def test_classify_cross_tenant_multi_account_is_a_finding(self) -> None:
        cross, counts = obs_check.classify_cross_tenant(
            {"account": {"semi", "cloudstack", "pipeshift"}}, "default"
        )
        self.assertTrue(cross)
        self.assertEqual(counts["account"], 3)

    def test_classify_single_account_is_clean(self) -> None:
        cross, counts = obs_check.classify_cross_tenant({"account": {"semi"}}, "default")
        self.assertFalse(cross)
        self.assertEqual(counts, {})

    def test_classify_namespace_excludes_own_and_infra(self) -> None:
        cross, _ = obs_check.classify_cross_tenant(
            {"namespace": {"default", "kube-system", "monitoring"}}, "default"
        )
        self.assertFalse(cross)
        cross, counts = obs_check.classify_cross_tenant(
            {"namespace": {"default", "acme", "globex"}}, "default"
        )
        self.assertTrue(cross)
        self.assertEqual(counts["namespace"], 2)

    def test_classify_ignores_null_placeholder(self) -> None:
        cross, _ = obs_check.classify_cross_tenant({"account": {"(null)", "semi"}}, "default")
        self.assertFalse(cross)


class AuthSchemeTests(unittest.TestCase):
    """The scheme names the credential an operator needs to reproduce a finding."""

    def test_basic_and_bearer_come_from_the_challenge_header(self) -> None:
        self.assertEqual(
            obs_check.detect_auth_scheme(401, {"www-authenticate": 'Basic realm="prom"'}),
            "basic",
        )
        self.assertEqual(
            obs_check.detect_auth_scheme(401, {"www-authenticate": "Bearer"}), "bearer"
        )

    def test_401_without_a_usable_challenge_is_still_reported_as_guarded(self) -> None:
        self.assertEqual(obs_check.detect_auth_scheme(401, {}), "challenge")

    def test_single_sign_on_proxy_is_detected_from_the_redirect(self) -> None:
        self.assertEqual(
            obs_check.detect_auth_scheme(302, {"location": "/oauth2/start?rd=%2F"}),
            "oauth-proxy",
        )
        self.assertEqual(
            obs_check.detect_auth_scheme(302, {"location": "https://sso/login"}),
            "login-redirect",
        )

    def test_open_and_unreachable_endpoints_are_distinguished(self) -> None:
        self.assertEqual(obs_check.detect_auth_scheme(200, {}), "none")
        self.assertEqual(obs_check.detect_auth_scheme(None, {}), "unreachable")
        self.assertEqual(obs_check.detect_auth_scheme(403, {}), "forbidden")


class _RedirectHandler(BaseHTTPRequestHandler):
    """A single-sign-on proxy in front of a metrics backend.

    Every backend path answers `302` to the proxy's own login path, and that
    login path answers `200` with a login page. This is the real shape, and it is
    what makes the test able to fail: a client that follows the redirect reads a
    `200` and concludes the endpoint needs no authentication.
    """

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
    """Exercise the real HTTP path, because mocking `_get` cannot catch this.

    Incident: `_get` used `urllib.request.urlopen`, which FOLLOWS redirects. A
    single-sign-on-guarded backend answered `302` to its login path, urllib
    followed it, and the check saw a `200`. The endpoint was then reported as
    `auth none` with `auth_required` false, which is the opposite of the truth.
    """

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

    def test_check_marks_an_sso_guarded_backend_as_guarded(self) -> None:
        summary = obs_check.check([self.base], own_namespace="default")
        self.assertTrue(summary["auth_required"])
        self.assertEqual(summary["auth_schemes"], {"oauth-proxy": 1})
        self.assertFalse(summary["unauth_query_ok"])
        self.assertFalse(summary["cross_tenant_series_visible"])


class SchemeUpgradeTests(unittest.TestCase):
    """A plain https upgrade carries no authentication meaning, so it is followed."""

    def test_same_host_https_upgrade_is_accepted(self) -> None:
        self.assertEqual(
            obs_check._scheme_upgrade("http://prom:9090/api/health", "https://prom:9090/api/health"),
            "https://prom:9090/api/health",
        )

    def test_a_different_host_or_path_is_not_an_upgrade(self) -> None:
        for location in (
            "https://other:9090/api/health",
            "https://prom:9090/login",
            "http://prom:9090/api/health",
            "/oauth2/start",
            "",
        ):
            self.assertEqual(
                obs_check._scheme_upgrade("http://prom:9090/api/health", location), "", location
            )

    def test_a_redirect_that_changes_the_port_is_not_an_upgrade(self) -> None:
        # Dropping :9090 lands on 443, which is a different service. Following it
        # would attribute another endpoint's answers to this target.
        self.assertEqual(
            obs_check._scheme_upgrade(
                "http://prom:9090/api/health", "https://prom/api/health"
            ),
            "",
        )
        self.assertEqual(
            obs_check._scheme_upgrade(
                "http://prom:9090/api/health", "https://prom:8443/api/health"
            ),
            "",
        )

    def test_a_malformed_port_in_a_server_location_does_not_raise(self) -> None:
        # `Location` is attacker- or bug-controlled, and `.port` raises on an
        # out-of-range value. This runs inside the HTTPError handler, so an
        # exception here would end the whole audit with a traceback.
        for location in (
            "https://prom:99999/api/health",
            "https://prom:notaport/api/health",
            "https://prom:-1/api/health",
        ):
            self.assertEqual(
                obs_check._scheme_upgrade("http://prom:9090/api/health", location),
                "",
                location,
            )

    def test_the_ordinary_default_port_upgrade_is_accepted(self) -> None:
        # Both ports implicit is the plain 80-to-443 upgrade of one service.
        self.assertEqual(
            obs_check._scheme_upgrade("http://prom/api/health", "https://prom/api/health"),
            "https://prom/api/health",
        )


class PlatformFingerprintTests(unittest.TestCase):
    def test_prometheus_api_forks_are_not_all_called_prometheus(self) -> None:
        mimir = json.dumps({"status": "success", "data": {"application": "Grafana Mimir", "version": "2.14"}})
        self.assertEqual(obs_check.classify_buildinfo(200, mimir), "mimir")
        thanos = json.dumps({"status": "success", "data": {"version": "0.36.1", "branch": "thanos"}})
        self.assertEqual(obs_check.classify_buildinfo(200, thanos), "thanos")

    def test_prometheus_is_identified_by_its_buildinfo_key_shape(self) -> None:
        body = json.dumps(
            {
                "status": "success",
                "data": {"version": "3.1.0", "revision": "abc", "goVersion": "go1.23"},
            }
        )
        self.assertEqual(obs_check.classify_buildinfo(200, body), "prometheus")

    def test_unusable_buildinfo_falls_back_to_the_health_body(self) -> None:
        self.assertEqual(obs_check.classify_buildinfo(404, ""), "")
        self.assertEqual(
            obs_check.classify_health_body(200, "Prometheus Server is Healthy."),
            "prometheus",
        )
        self.assertEqual(obs_check.classify_health_body(200, "VictoriaMetrics"), "victoriametrics")
        self.assertEqual(obs_check.classify_health_body(200, "OK"), "")


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
            if url.endswith("/api/health"):
                return 200, json.dumps({"database": "ok", "version": "12.3.6"}), {}
            if url.endswith("/api/datasources"):
                return 200, json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]), {}
            values = []
            if "/label/account/values" in url:
                values = ["tenant-a" if "/proxy/1/" in url else "tenant-b"]
            return 200, json.dumps({"status": "success", "data": values}), {}
        with mock.patch.object(obs_check, "_get", side_effect=get):
            result = obs_check.check(["https://grafana.example"])
        self.assertFalse(result["cross_tenant_series_visible"])
        self.assertEqual(result["foreign_tenant_counts"], {})
    def test_check_returns_counts_only_never_rosters(self) -> None:
        # Simulate a Grafana pivot exposing several foreign accounts.
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
        # Sanitization: the summary must not carry any tenant identity string.
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

    def test_guarded_backend_reports_the_scheme_and_no_finding(self) -> None:
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="x"'})
            return (401, "", {"www-authenticate": 'Basic realm="x"'})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertTrue(summary["auth_required"])
        self.assertEqual(summary["auth_schemes"], {"basic": 1})
        self.assertFalse(summary["unauth_query_ok"])
        self.assertFalse(summary["cross_tenant_series_visible"])

    def test_an_open_datasource_list_with_a_guarded_proxy_reports_the_guard(self) -> None:
        # Grafana can list its datasources without a credential and still refuse
        # the proxy read that queries the store. Taking the scheme only from the
        # listing reported `none` while every tenancy query was refused.
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (200, json.dumps([{"id": 1, "type": "prometheus"}]), {})
            return (403, "", {})  # the proxy refuses every query

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://grafana.example"], own_namespace="default")
        self.assertTrue(summary["grafana_datasources_listable"])
        self.assertEqual(summary["auth_schemes"], {"forbidden": 1})
        # The summary must agree with itself: a recorded guard means guarded.
        self.assertTrue(summary["auth_required"])
        self.assertEqual(summary["queries_answered"], 0)
        self.assertFalse(summary["unauth_query_ok"])

    def test_auth_required_follows_the_shared_guard_set(self) -> None:
        # A hardcoded list here drifted from GUARDED_SCHEMES and left
        # `auth_schemes: {"forbidden": 1}` beside `auth_required: false` in the
        # same committed summary.
        # Keep known protocol cases independent of the production set so
        # dropping a guard cannot silently remove its test case.
        known_guards = {
            "basic", "bearer", "forbidden", "oauth-proxy",
            "login-redirect", "challenge",
        }
        for scheme in sorted(known_guards | obs_check.GUARDED_SCHEMES):

            def fake_get(url: str, header: str, scheme=scheme):
                if scheme == "forbidden":
                    return (403, "", {})
                if scheme == "oauth-proxy":
                    return (302, "", {"location": "/oauth2/start"})
                if scheme == "login-redirect":
                    return (302, "", {"location": "/login"})
                if scheme == "challenge":
                    return (401, "", {})
                return (401, "", {"www-authenticate": scheme})

            with mock.patch.object(obs_check, "_get", side_effect=fake_get):
                summary = obs_check.check(["https://prom.example"], own_namespace="default")
            self.assertEqual(list(summary["auth_schemes"]), [scheme], scheme)
            self.assertTrue(summary["auth_required"], scheme)

    def test_a_guard_already_found_is_never_downgraded(self) -> None:
        result = {"auth_scheme": "basic"}
        obs_check.merge_auth_scheme(result, 200, {})
        self.assertEqual(result["auth_scheme"], "basic")
        # An empty scheme takes whatever comes first.
        fresh: dict = {"auth_scheme": ""}
        obs_check.merge_auth_scheme(fresh, 200, {})
        self.assertEqual(fresh["auth_scheme"], "none")
        # "none" is upgraded by a later refusal, which is the incident.
        obs_check.merge_auth_scheme(fresh, 401, {"www-authenticate": "Bearer"})
        self.assertEqual(fresh["auth_scheme"], "bearer")
    def test_credential_escalation_stops_at_the_first_credential_that_reads(self) -> None:
        # The common real exposure: the query path is guarded, and the tenant's
        # own credential reads every tenant's series.
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
        # The guard came from the anonymous pass, and an authenticated read is
        # never recorded as an unauthenticated one.
        self.assertEqual(summary["auth_schemes"], {"basic": 1})
        self.assertFalse(summary["unauth_query_ok"])
        # Sanitization: no credential value reaches the summary.
        blob = json.dumps(summary)
        for secret in ("prom-operator", "admin:admin", "wrong", accepted):
            self.assertNotIn(secret, blob)

    def test_an_operator_read_does_not_end_the_sweep(self) -> None:
        # `env` is excluded from attribution AND is tried first. Returning on it
        # left every tenant-owned credential untried, so
        # `cross_tenant_credential_sources` was unreachable whenever an operator
        # set CLUSTERMAX_OBS_TOKEN alongside the harvest flag: the report then
        # dropped the ordinary-tenant sentence on a cluster where an ordinary
        # tenant could in fact read.
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")
        cross_tenant = json.dumps({"status": "success", "data": ["acme", "globex"]})

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header not in (operator, tenant):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, cross_tenant, {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("kubernetes-secret", tenant),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        # The tenant-owned source is the one recorded and the one attributed.
        self.assertEqual(summary["credential_sources_accepted"], {"kubernetes-secret": 1})
        self.assertEqual(summary["cross_tenant_credential_sources"], {"kubernetes-secret": 1})
        self.assertTrue(summary["cross_tenant_series_visible"])
        blob = json.dumps(summary)
        for secret in ("operator-admin-token", "tenant-secret", operator, tenant):
            self.assertNotIn(secret, blob)

    def test_an_operator_only_read_is_still_reported_as_a_finding(self) -> None:
        # The other half of holding the operator read: when nothing lower in the
        # trust order reads, that read must still be returned. Dropping it would
        # lose the cross-tenant finding entirely and report the target as merely
        # guarded.
        operator = obs_check.credential_header("bearer", "operator-admin-token")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header != operator:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(summary["queries_answered"], 1)
        self.assertEqual(
            summary["credential_sources_accepted"],
            {obs_check.OPERATOR_CREDENTIAL_SOURCE: 1},
        )
        # Attribution stays empty, because an administrator credential the
        # provider handed over says nothing about ordinary tenant access.
        self.assertEqual(summary["cross_tenant_credential_sources"], {})

    def test_a_shell_credential_does_not_end_the_sweep_either(self) -> None:
        # `process-env` is not tenant evidence, for the reason it is gated opt-in
        # during collection: the value comes from the shell that launched the audit.
        # Stopping the sweep on it attributed the finding to that source while the
        # assessment declined to treat it as tenant-held access, and left every
        # tenant-owned credential untried.
        shell = obs_check.credential_header("bearer", "unrelated-grafana-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")
        cross_tenant = json.dumps({"status": "success", "data": ["acme", "globex"]})

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header not in (shell, tenant):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, cross_tenant, {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [
            (obs_check.PROCESS_ENV_CREDENTIAL_SOURCE, shell),
            ("kubernetes-secret", tenant),
        ]
        # `select_credentials` is patched to identity order. It appends the shell
        # credential LAST, so through the real selection this branch can never see a
        # tenant-owned credential behind a shell one, and the assertion below would
        # hold whatever the branch did. The two rules are separate units: the ordering
        # is pinned by `test_the_shell_credential_never_displaces_a_tenant_owned_try`,
        # and this pins that a shell read keeps the sweep going, so a future ordering
        # change cannot silently attribute the finding to the operator's own shell.
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "select_credentials", lambda pairs, **_: list(pairs)
        ):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        self.assertEqual(summary["credential_sources_accepted"], {"kubernetes-secret": 1})
        self.assertEqual(
            summary["cross_tenant_credential_sources"], {"kubernetes-secret": 1}
        )
        blob = json.dumps(summary)
        for secret in ("unrelated-grafana-token", "tenant-secret", shell, tenant):
            self.assertNotIn(secret, blob)

    def test_a_shell_only_read_is_reported_and_stays_out_of_the_tenant_claim(self) -> None:
        # The other half. When nothing tenant-owned reads, the held `process-env`
        # read is still returned, so the exposure is not lost, and it IS recorded in
        # the attribution dict. `security.py` needs it there to emit its own
        # sentence; excluding it here would delete the finding instead of re-wording
        # it. This is the one place the two check copies differ on purpose: the
        # diagnostic reports a single boolean with no source label beside it, so it
        # excludes `process-env` at this step.
        shell = obs_check.credential_header("bearer", "unrelated-grafana-token")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header != shell:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [(obs_check.PROCESS_ENV_CREDENTIAL_SOURCE, shell)]
        # `select_credentials` is patched to identity order. It appends the shell
        # credential LAST, so through the real selection this branch can never see a
        # tenant-owned credential behind a shell one, and the assertion below would
        # hold whatever the branch did. The two rules are separate units: the ordering
        # is pinned by `test_the_shell_credential_never_displaces_a_tenant_owned_try`,
        # and this pins that a shell read keeps the sweep going, so a future ordering
        # change cannot silently attribute the finding to the operator's own shell.
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "select_credentials", lambda pairs, **_: list(pairs)
        ):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(summary["queries_answered"], 1)
        self.assertEqual(
            summary["cross_tenant_credential_sources"],
            {obs_check.PROCESS_ENV_CREDENTIAL_SOURCE: 1},
        )

    def test_the_shell_read_is_held_over_the_operator_read(self) -> None:
        # Both non-tenant sources read and nothing tenant-owned does. Holding `env`
        # reports no source at all, because attribution drops it, so the report
        # would carry the CRITICAL with no credential sentence. `process-env` has a
        # sentence, so it is the read worth keeping.
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        shell = obs_check.credential_header("bearer", "unrelated-grafana-token")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if header not in (operator, shell):
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            (obs_check.PROCESS_ENV_CREDENTIAL_SOURCE, shell),
        ]
        # `select_credentials` is patched to identity order. It appends the shell
        # credential LAST, so through the real selection this branch can never see a
        # tenant-owned credential behind a shell one, and the assertion below would
        # hold whatever the branch did. The two rules are separate units: the ordering
        # is pinned by `test_the_shell_credential_never_displaces_a_tenant_owned_try`,
        # and this pins that a shell read keeps the sweep going, so a future ordering
        # change cannot silently attribute the finding to the operator's own shell.
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "select_credentials", lambda pairs, **_: list(pairs)
        ):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(["https://prom.example"], credentials),
            )
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(
            summary["credential_sources_accepted"],
            {obs_check.PROCESS_ENV_CREDENTIAL_SOURCE: 1},
        )
        self.assertEqual(
            summary["cross_tenant_credential_sources"],
            {obs_check.PROCESS_ENV_CREDENTIAL_SOURCE: 1},
        )

    def test_the_budget_covers_the_worst_case_sweep_on_every_target(self) -> None:
        # Sweeping past an operator read costs one more full-price pass per
        # target. This pins that the request budget absorbs it on all
        # MAX_TARGETS at once, because a budget that ran out here would skip
        # later targets and report `targets_skipped` instead of a result.
        # Grafana is the expensive shape: a datasource listing plus a label
        # sweep per datasource.
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (
                    200,
                    json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]),
                    {},
                )
            if header not in (operator, tenant):
                return (403, "", {})  # the proxy refuses anonymous and both decoys
            if "/label/account/values" in url:
                return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})
            return (200, json.dumps({"status": "success", "data": ["default"]}), {})

        # Four credentials are tried per target, which is MAX_CREDENTIALS_PER_TARGET:
        # the operator read (held, full price), two refusals, then the tenant read.
        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("grafana-ini", obs_check.credential_header("basic", "decoy:one")),
            # Both decoys are tenant-owned, so all four passes run. A `process-env`
            # decoy here stopped costing anything once `select_credentials` moved that
            # source behind the tenant-owned quota: it was reordered to slot four, the
            # tenant read landed in slot three, and the sweep stopped a pass early at
            # 256 requests. The worst case this pins is four passes, whatever fills
            # them.
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
        # The exact figures the MAX_REQUESTS comment cites. A bare
        # `<= MAX_REQUESTS` passed at 300 and pinned nothing, so the comment could
        # claim a cost the code does not spend. 36 is five TENANT_LABEL_KEYS swept
        # across MAX_DATASOURCES datasources, twice, plus the health and listing
        # requests of each pass. Adding a label key or a datasource fails here and
        # sends the next author to the constant.
        self.assertEqual(summary["request_count"], 36 * obs_check.MAX_TARGETS)
        self.assertEqual(summary["request_count"], 288)
        self.assertLessEqual(summary["request_count"], obs_check.MAX_REQUESTS)

    def test_a_dead_provisioned_backend_exceeds_the_budget_and_says_so(self) -> None:
        # The cheap exit fires only for a GUARDED scheme. A Grafana proxying a
        # provisioned datasource whose own backend is dead answers 502, which is
        # not a guard, so every label of every datasource is swept and the pass
        # still does not read. No operator hold, five full-price passes, 60 per
        # target: above MAX_REQUESTS on 8 targets. The budget is deliberately not
        # sized for this. What must hold is that exceeding it degrades to an
        # incomplete result rather than to a clean one.
        #
        # The budget is patched down here so the test states its own premise. A
        # later author who raises MAX_REQUESTS to cover this shape is making a
        # legitimate change, and this test must not fail for it.
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (
                    200,
                    json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]),
                    {},
                )
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
        # The budget ran out, and the summary says which targets it could not
        # finish instead of reporting them as isolated.
        self.assertGreater(summary["targets_skipped"], 0)
        self.assertLessEqual(summary["request_count"], 240)
        self.assertEqual(summary["queries_answered"], 0)
        self.assertFalse(summary["cross_tenant_series_visible"])

    def test_a_half_swept_target_is_counted_as_skipped(self) -> None:
        # Escalation can run out of budget with credentials still untried, or
        # inside a pass that had not yet reached the label that reads. Either way
        # the target lost coverage, and a half-swept target used to look exactly
        # like a fully swept clean one. `want_request` now records the flag on any
        # pass that cannot afford its next request, so both shapes report.
        operator = obs_check.credential_header("bearer", "operator-admin-token")
        tenant = obs_check.credential_header("basic", "prom:tenant-secret")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (
                    200,
                    json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]),
                    {},
                )
            if header not in (operator, tenant):
                return (403, "", {})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, operator),
            ("kubernetes-secret", tenant),
        ]
        # Enough for the anonymous refusal and the operator pass, and not enough
        # to evaluate the tenant credential.
        budget = [15]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://grafana.example", credentials, budget
            )
        self.assertEqual(result["credential_source"], obs_check.OPERATOR_CREDENTIAL_SOURCE)
        self.assertTrue(result["budget_exhausted"])
        # A full sweep of the same target does not carry the flag, so the marker
        # tracks coverage rather than the mere presence of credentials.
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            complete = obs_check.check_endpoint_escalating(
                "https://grafana.example", credentials, [obs_check.MAX_REQUESTS]
            )
        self.assertEqual(complete["credential_source"], "kubernetes-secret")
        self.assertFalse(complete.get("budget_exhausted"))

    def test_a_complete_pass_that_spends_the_last_request_is_not_called_incomplete(self) -> None:
        # The flag must track LOST COVERAGE, and testing `out_of_budget` after a pass
        # that did not read could not tell "cut short" from "finished and happened to
        # spend the last request". A guarded backend assessed in full then landed in
        # `targets_skipped`, which blocks a clean pass, so a correctly locked-down
        # tenant read as an incomplete WARNING purely because the budget hit zero on
        # its last request.
        def fake_get(url: str, header: str):
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"status": "success", "data": {"version": "2.51.0"}}), {})
            # Refused for every caller, credentialed or not.
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
            # Counted AFTER the check returns. Reading `len(seen)` in the return
            # expression counted it before the call ran and always gave 0.
            return len(seen), result

        one = [("kubernetes-secret", obs_check.credential_header("basic", "prom:secret"))]
        unbounded_requests, unbounded = run(obs_check.MAX_REQUESTS, one)
        self.assertFalse(unbounded.get("budget_exhausted"))
        # The SAME requests, under a budget that runs out on the last one. Identical
        # coverage has to produce an identical verdict.
        exact_requests, exact = run(unbounded_requests, one)
        self.assertEqual(exact_requests, unbounded_requests)
        self.assertFalse(exact.get("budget_exhausted"))
        # One request short is a genuinely cut-short pass and stays flagged.
        _short_requests, short = run(unbounded_requests - 1, one)
        self.assertTrue(short["budget_exhausted"])
        # A second credential left untried is also still flagged, by the test at the
        # top of the escalation loop.
        two = one + [("grafana-ini", obs_check.credential_header("basic", "admin:admin"))]
        _two_requests, two_result = run(unbounded_requests, two)
        self.assertTrue(two_result["budget_exhausted"])

    def test_a_backend_that_answers_nothing_is_stopped_before_it_spends_the_budget(self) -> None:
        # The request budget bounds requests, not seconds. A timeout is not a
        # guarded scheme, and `_check_grafana` starts `reachable` at True, so a
        # Grafana that holds the proxy connection open sweeps every label of every
        # datasource on all five passes. At REQUEST_TIMEOUT_S each that is minutes
        # per target, for a command documented as a quick free report.
        calls: list[str] = []
        # A hung read: the client gives up, which `_get` reports as unreachable.
        def fake_get(url: str, header: str):
            calls.append(url)
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (
                    200,
                    json.dumps([{"id": 1, "type": "prometheus"}, {"id": 2, "type": "prometheus"}]),
                    {},
                )
            return (None, "", {})  # the proxy never answers

        targets = [f"https://grafana-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        credentials = [
            (obs_check.OPERATOR_CREDENTIAL_SOURCE, obs_check.credential_header("bearer", "op")),
            ("kubernetes-secret", obs_check.credential_header("basic", "prom:secret")),
        ]
        # An unanswered-time allowance already spent, so nothing waits.
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_UNANSWERED_MS", -1
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        # Every target is reported as not reached, rather than as isolated.
        self.assertEqual(summary["targets_skipped"], obs_check.MAX_TARGETS)
        self.assertEqual(summary["queries_answered"], 0)
        self.assertFalse(summary["cross_tenant_series_visible"])
        self.assertEqual(calls, [])

    def test_the_allowance_can_run_out_inside_one_label_sweep(self) -> None:
        # Checking only between passes is not enough: one target can spend the whole
        # allowance inside a single label sweep, which is the hanging-proxy shape.
        clock = RequestDrivenClock()

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.GRAFANA_HEALTH):
                # Answers, and not as Grafana, so this takes the Prometheus path.
                clock.spend(0.1)
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                # Answers, so the target is reachable and the sweep proceeds past
                # the index-0 abort. This is what makes the sweep expensive.
                clock.spend(0.1)
                return (200, json.dumps({"version": "2.53.0", "revision": "a", "goVersion": "1"}), {})
            clock.spend(obs_check.REQUEST_TIMEOUT_S)  # every label read hangs
            return (None, "", {})

        # The allowance is shortened to two dead requests so the boundary lands
        # inside one five-label sweep. What is under test is WHERE the budget can
        # run out, not the shipped value of the constant.
        allowance = 2 * int(obs_check.REQUEST_TIMEOUT_S * 1000)
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check, "MAX_UNANSWERED_MS", allowance
        ), mock.patch.object(obs_check.time, "monotonic", clock.read):
            budget = [obs_check.MAX_REQUESTS, allowance]
            result = obs_check.check_endpoint("https://prom.example", "", budget)
        # It started the sweep and stopped inside it. Asserting only "fewer than
        # all" would also pass if the sweep had never begun, which is what per-pass
        # checking produces.
        self.assertEqual(list(result["labels"]), ["account", "org_id"])
        self.assertLess(len(result["labels"]), len(obs_check.TENANT_LABEL_KEYS))
        # The target may make no further request. Asserting `budget[0] == 0` would
        # pin the OLD accounting, in which a spent share zeroed the run-wide request
        # count and so ended the whole run.
        self.assertTrue(obs_check.out_of_budget(budget))
        self.assertGreater(budget[0], 0)
        # Stopping inside the sweep is incomplete coverage, so the target must say
        # so. Without this the target reads as fully checked, and a hanging backend
        # scores as "refused every read" instead of as incomplete.
        self.assertTrue(result["budget_exhausted"])

    def test_an_operator_read_cut_short_inside_its_own_sweep_still_says_so(self) -> None:
        # The operator-hold return path assigned `budget_exhausted` from `truncated`
        # alone, which discarded the flag `want_request` had already set on the same
        # dict. An operator pass that read two of five labels then reported complete
        # coverage. Reachable whenever the credential list ends at the operator
        # entry, which is what this test constructs.
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
        # Enough to refuse anonymously and start the operator sweep, not to finish it.
        budget = [8]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://prom.example", credentials, budget
            )
        self.assertEqual(result["credential_source"], obs_check.OPERATOR_CREDENTIAL_SOURCE)
        self.assertLess(len(result["labels"]), len(obs_check.TENANT_LABEL_KEYS))
        self.assertTrue(result["budget_exhausted"])

    def test_a_hanging_proxy_cannot_be_kept_alive_by_the_passes_that_answer(self) -> None:
        # The shape the bound exists for, and the one that defeated the first
        # version of it. Grafana answers `/api/health` and `/api/datasources`, and
        # its datasource proxy never answers. Under escalation every pass opens with
        # those two answers, so a bound on CONSECUTIVE dead time was reset before at
        # most ten proxy timeouts could accumulate, and the check ran the full
        # request budget: measured at 448 requests and 1488 wasted seconds, about 25
        # minutes. Counting unanswered time cumulatively cannot be reset that way.
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
        # The allowance, and not the request budget, is what stopped this run. A
        # bound that answers can reset would have spent every request instead.
        allowed = obs_check.MAX_UNANSWERED_MS / 1000 + obs_check.REQUEST_TIMEOUT_S
        self.assertLess(clock.now, allowed * 2)
        self.assertLess(summary["request_count"], obs_check.MAX_REQUESTS // 4)
        # The coverage it gave up is reported, so this never reads as clean.
        self.assertEqual(summary["targets_skipped"], obs_check.MAX_TARGETS)

    def test_one_hanging_backend_does_not_spend_the_coverage_of_the_targets_behind_it(
        self,
    ) -> None:
        # A single pool of unanswered time is a resource the FIRST target can drain,
        # and endpoint discovery sorts by URL, so `<release>-grafana` sorts ahead of
        # `<release>-prometheus` on a default install. One hanging Grafana therefore
        # spent the whole run allowance and every healthy backend behind it returned
        # from the entry check having made no request: eight targets not checked, a
        # WARNING, and the cross-tenant CRITICAL on the seven never reached.
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
            # Seven healthy Prometheus backends: guarded without a credential, and
            # cross-tenant with one. They answer at once, so they charge nothing.
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            if not header:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        # Four credentials, so the old single pool was drained by this one target's
        # escalation before the healthy backends were ever reached.
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
        # The hanging target alone gives up coverage, and it still says so.
        self.assertEqual(summary["targets_skipped"], 1)
        self.assertEqual(summary["queries_answered"], obs_check.MAX_TARGETS - 1)
        # The finding the run exists to reach.
        self.assertTrue(summary["cross_tenant_series_visible"])
        self.assertEqual(
            summary["cross_tenant_credential_sources"],
            {"kubernetes-secret": obs_check.MAX_TARGETS - 1},
        )
        # The hanging target spent its own share and no more, so the run keeps the
        # rest of the allowance for the targets behind it.
        self.assertLessEqual(clock.now * 1000, obs_check.MAX_UNANSWERED_PER_TARGET_MS)
        self.assertLess(obs_check.MAX_UNANSWERED_PER_TARGET_MS, obs_check.MAX_UNANSWERED_MS)
        # The share was large enough for the whole anonymous pass, which is where
        # `unauth_query_ok`, `admin_api_exposed`, and the datasource listing come
        # from. A share that cuts that pass short discards those findings.
        self.assertTrue(summary["grafana_datasources_listable"])

    def test_a_firewalled_tenant_whose_every_target_hangs_is_still_assessed_in_full(
        self,
    ) -> None:
        # The posture this check exists to confirm. A Kubernetes NetworkPolicy DROPs
        # by default, so a tenant that is correctly cut off from the monitoring
        # namespace sees every target hang until the timeout rather than refuse at
        # once. That must report no reachable backend and pass. An unanswered-time
        # total of 30 timeouts emptied during target six, so the correct posture was
        # reported as two targets not checked and INCONCLUSIVE.
        #
        # The stub charges MORE than REQUEST_TIMEOUT_S per dead read, because that is
        # what really happens: `spend_request` measures from before the connect to
        # after the socket teardown, while the timeout bounds only the wait for data.
        # A stub that charged exactly the timeout could not see the second form of
        # this defect, where an allowance sized at exactly the direct-path timeout
        # count empties before the final request returns. UNANSWERED_OVERHEAD covers
        # the gap.
        clock = RequestDrivenClock()
        socket_overhead = obs_check.REQUEST_TIMEOUT_S * 0.25

        def fake_get(url: str, header: str):
            clock.spend(obs_check.REQUEST_TIMEOUT_S + socket_overhead)
            return (None, "", {})

        targets = [f"https://prom-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(targets, own_namespace="default")
        # Behavior first: full coverage, and the honest finding. A regression here
        # also shortens the run, so a premise check placed above this line would trip
        # first and name the wrong cause.
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
        self.assertEqual(summary["backends_reachable"], 0)
        self.assertEqual(summary["queries_answered"], 0)
        # Premise: every target really did wait out all of its dead reads, so the run
        # was not short for some unrelated reason.
        dead_path_requests = (
            obs_check.MAX_TARGETS * obs_check.DEAD_DIRECT_PATH_REQUESTS
        )
        self.assertEqual(
            clock.now,
            dead_path_requests * (obs_check.REQUEST_TIMEOUT_S + socket_overhead),
        )
        # Premise: the charge exceeded the direct path's bare timeout total. This is
        # the gap that the overhead factor exists to cover.
        self.assertGreater(
            clock.now,
            dead_path_requests * obs_check.REQUEST_TIMEOUT_S,
        )
        self.assertEqual(obs_check.MAX_UNANSWERED_MS, 240_000)
        self.assertLess(clock.now * 1000, obs_check.MAX_UNANSWERED_MS)

    def test_a_target_that_answered_nothing_is_not_escalated(self) -> None:
        # A credential cannot change transport reachability, so escalating a target
        # that answered nothing spends four more passes to learn the same thing, at
        # the full timeout for every read. With harvesting on, a correctly firewalled
        # tenant therefore spent five times its share on every target, and the earlier
        # fix to the run total held only while the feature this change adds was off.
        headers: list[str] = []

        def fake_get(url: str, header: str):
            headers.append(header)
            return (None, "", {})

        credentials = [
            ("kubernetes-secret", obs_check.credential_header("basic", "p:s")),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://prom.example", credentials, [obs_check.MAX_REQUESTS]
            )
        # Only the anonymous pass ran.
        self.assertEqual(set(headers), {""})
        self.assertFalse(result["reachable"])
        self.assertEqual(result["credential_source"], "")
        # A blocked target is still not a clean one: nothing answered, so tenancy was
        # never tested, and `queries_answered` stays at zero for it.
        self.assertFalse(result["query_ok"])

    def test_a_firewalled_tenant_is_assessed_in_full_with_escalation_on(self) -> None:
        # The whole-run consequence of the two fixes above, in the mode this change
        # adds. Every target hangs, credentials are configured, and the run must still
        # cover all eight and report the correct posture.
        clock = RequestDrivenClock()

        def fake_get(url: str, header: str):
            clock.spend(obs_check.REQUEST_TIMEOUT_S)
            return (None, "", {})

        credentials = [
            ("kubernetes-secret", obs_check.credential_header("basic", "p:s")),
            ("grafana-ini", obs_check.credential_header("basic", "a:b")),
            ("default", obs_check.credential_header("basic", "admin:admin")),
        ]
        targets = [f"https://prom-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
        self.assertEqual(summary["backends_reachable"], 0)
        self.assertEqual(summary["credential_sources_accepted"], {})

    def test_the_operator_credential_does_not_spend_a_tenant_owned_try(self) -> None:
        # FOUR categories, because they answer different questions. A read by `env` is
        # not attributed and does not stop the sweep, so it cannot produce the
        # finding; the tenant-owned sources
        # are the ones that can. Counting `env` as a tenant-owned try left only ONE
        # such try whenever CLUSTERMAX_OBS_TOKEN was set, and with collection on by
        # default that is the common shape, so the cap dropped `grafana-ini` and
        # provisioning before they ran.
        def sources(pairs):
            return [source for source, _header in obs_check.select_credentials(pairs)]

        rich = [
            ("env", "Bearer operator"),
            ("grafana-ini", "Basic a"),
            ("grafana-provisioning", "Basic b"),
            ("process-env", "Bearer c"),
            ("default", "Basic admin"),
            ("default", "Basic prom"),
        ]
        chosen = sources(rich)
        # Two tenant-owned tries survive alongside the operator credential and a
        # default, and the operator's slot comes out of the DEFAULTS reserve.
        self.assertEqual(
            chosen, ["env", "grafana-ini", "grafana-provisioning", "default"]
        )
        # The request bound does not move.
        self.assertLessEqual(len(chosen), obs_check.MAX_CREDENTIALS_PER_TARGET)
        # With no operator credential the split is unchanged from before.
        self.assertEqual(
            sources([pair for pair in rich if pair[0] != "env"]),
            ["grafana-ini", "grafana-provisioning", "default", "default"],
        )
        # With no defaults collected there is nothing to hold back, so every
        # remaining slot goes to the tenant-owned sources.
        self.assertEqual(
            sources([pair for pair in rich if pair[0] != "default"]),
            ["env", "grafana-ini", "grafana-provisioning", "process-env"],
        )
        # A cap smaller than the categories must never return more than the cap.
        for cap in (0, 1, 2, 3):
            with self.subTest(cap=cap):
                self.assertLessEqual(len(obs_check.select_credentials(rich, cap=cap)), cap)

    def test_the_shell_credential_never_displaces_a_tenant_owned_try(self) -> None:
        # FOUR categories. `process-env` can produce neither finding: it does not
        # support the tenant-held claim, for the reason it is gated opt-in, and it is
        # not the credential the operator named for this cluster. `harvest` ranks it
        # fifth, so while it sat in the tenant-owned quota it took the second of two
        # tenant tries and `kubernetes-secret` was never offered, which is the source
        # that attributes ordinary tenant access.
        def sources(pairs):
            return [source for source, _header in obs_check.select_credentials(pairs)]

        # The shape an opted-in run reaches on a pod that also mounts a token.
        self.assertEqual(
            sources(
                [
                    ("service-account", "Bearer sa"),
                    ("process-env", "Bearer shell"),
                    ("kubernetes-secret", "Basic k8s"),
                    ("default", "Basic admin"),
                    ("default", "Basic prom"),
                ]
            ),
            ["service-account", "kubernetes-secret", "default", "default"],
        )
        # It is still tried when the other three categories leave room, so opting in
        # is not silently ignored. Last, out of the leftover.
        self.assertEqual(
            sources(
                [
                    ("process-env", "Bearer shell"),
                    ("kubernetes-secret", "Basic k8s"),
                    ("default", "Basic admin"),
                    ("default", "Basic prom"),
                ]
            ),
            ["kubernetes-secret", "default", "default", "process-env"],
        )

    def test_both_operator_credentials_are_tried_when_they_fit(self) -> None:
        # `from_environment` yields TWO `env` credentials when the operator sets both
        # CLUSTERMAX_OBS_TOKEN and CLUSTERMAX_OBS_BASIC_AUTH. Both were named
        # deliberately, so taking only the first is a loss.
        two = [
            ("env", "Bearer operator"),
            ("env", "Basic operator"),
            ("grafana-ini", "Basic a"),
            ("grafana-provisioning", "Basic b"),
            ("process-env", "Bearer c"),
        ]

        def sources(pairs):
            return [source for source, _header in obs_check.select_credentials(pairs)]

        # No vendor defaults on this host, so nothing is held back for that source and
        # both operator credentials fit alongside two tenant-owned tries.
        self.assertEqual(
            sources(two),
            ["env", "env", "grafana-ini", "grafana-provisioning"],
        )
        # With defaults present, four slots cannot hold two operator credentials, the
        # two tenant-owned tries that produce the finding, AND a default. The second
        # operator credential yields, because a read by that source is not attributed
        # and does not stop the sweep, and `auth_header` has always preferred the token
        # over the basic pair. The three guarantees that remain are what matter.
        with_defaults = two + [("default", "Basic admin"), ("default", "Basic prom")]
        chosen = sources(with_defaults)
        self.assertEqual(
            chosen, ["env", "grafana-ini", "grafana-provisioning", "default"]
        )
        self.assertEqual(chosen.count("env"), 1)
        self.assertLessEqual(len(chosen), obs_check.MAX_CREDENTIALS_PER_TARGET)
        # A host that yields only operator credentials and defaults still tries both,
        # because there are no tenant-owned sources competing for the slots.
        self.assertEqual(
            sources([pair for pair in with_defaults if pair[0] in ("env", "default")]),
            ["env", "env", "default", "default"],
        )

    def test_the_vendor_defaults_are_still_tried_on_a_credential_rich_host(self) -> None:
        # `harvest` appends the vendor `default` entries last, because they are the
        # least trusted. Taking the first MAX_CREDENTIALS_PER_TARGET credentials then
        # dropped them on exactly the hosts where they are worth trying: a Grafana
        # that yields a service-account token, `grafana.ini`, provisioning, and
        # process-env values fills every try, so `admin:admin` was never offered
        # although reaching it is why the source exists.
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
        # The request bound does not move: the reservation takes slots from the
        # harvested values rather than adding tries.
        self.assertEqual(
            len(obs_check.select_credentials(credentials)),
            obs_check.MAX_CREDENTIALS_PER_TARGET,
        )

    def test_the_admin_api_is_requested_only_without_a_credential(self) -> None:
        # `admin_api_exposed` means the delete API is routed AND unauthenticated, and
        # `check_endpoint_escalating` already discards the credentialed answer for
        # that reason. Requesting it on every credential pass could therefore
        # contribute no evidence and spent one request of a shared budget each time,
        # which on eight targets under escalation can push a later backend into
        # `targets_skipped`.
        admin_headers: list[str] = []

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.ADMIN):
                admin_headers.append(header)
                return (405, "", {})
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            if not header:
                return (401, "", {"www-authenticate": 'Basic realm="prom"'})
            return (200, json.dumps({"status": "success", "data": ["acme", "globex"]}), {})

        credentials = [("kubernetes-secret", obs_check.credential_header("basic", "p:s"))]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            result = obs_check.check_endpoint_escalating(
                "https://prom.example", credentials, [obs_check.MAX_REQUESTS]
            )
        # Asked once, by the anonymous pass, and the finding is still reported.
        self.assertEqual(admin_headers, [""])
        self.assertTrue(result["admin_api_exposed"])
        self.assertEqual(result["credential_source"], "kubernetes-secret")

    def test_the_admin_api_is_still_checked_when_the_operator_supplies_a_credential(
        self,
    ) -> None:
        # With collection OFF and CLUSTERMAX_OBS_TOKEN set, `check` makes exactly ONE
        # pass and that pass carries the operator's header, so there is no anonymous
        # pass at all. Gating the request on `not header` therefore made
        # `admin_api_exposed` permanently false in that whole configuration and
        # silently removed a CRITICAL input.
        #
        # The request is also made WITHOUT the header. The finding is about
        # UNAUTHENTICATED access, and the operator credential is commonly an
        # administrator one the provider handed over, so sending it would let a `405`
        # that only proves this identity is authorized raise a CRITICAL.
        admin_headers: list[str] = []
        label_headers: list[str] = []

        def fake_get(url: str, header: str):
            if url.endswith(obs_check.ADMIN):
                admin_headers.append(header)
                return (405, "", {})
            if url.endswith(obs_check.GRAFANA_HEALTH):
                return (404, "", {})
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            label_headers.append(header)
            if not header:
                return (401, "", {"www-authenticate": "Bearer"})
            return (200, json.dumps({"status": "success", "data": ["acme"]}), {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://prom.example"],
                    [("env", obs_check.auth_header(token="operator-token"))],
                ),
            )
        self.assertEqual(admin_headers, [""])
        self.assertTrue(summary["admin_api_exposed"])
        # Premise: the rest of the pass really did carry the operator credential, so
        # the empty header above is the deliberate exception rather than a run in
        # which no credential was ever set.
        self.assertTrue(label_headers)
        self.assertEqual(set(label_headers), {"", "Bearer operator-token"})

    def test_a_target_cut_short_inside_its_sweep_is_counted_as_skipped(self) -> None:
        # The flag is only useful if it reaches the summary. `targets_skipped` is
        # what blocks a clean pass, and a mid-sweep truncation used to leave it at
        # zero, so the run reported complete coverage it did not have.
        def fake_get(url: str, header: str):
            if url.endswith(obs_check.BUILDINFO):
                return (200, json.dumps({"version": "2", "revision": "a", "goVersion": "1"}), {})
            return (None, "", {})  # every label read hangs

        # Enough budget to start the first target's sweep and not to finish it.
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
        # The allowance counts UNANSWERED time, which is why it is expressed that
        # way rather than as a ceiling on total time. A large cluster whose label
        # reads are merely slow answers every request, so it must be assessed in
        # full. A total ceiling would truncate it, and truncation is reported through
        # `targets_skipped`, which blocks a pass, so a healthy cluster would be
        # recorded as INCONCLUSIVE for being slow.
        clock = RequestDrivenClock()
        # Just under the per-request timeout, so every request answers, and slow
        # enough that the whole sweep runs past the unanswered-time allowance. An
        # answered request is charged NOTHING, so any number of them may exceed it.
        per_request = obs_check.REQUEST_TIMEOUT_S * 0.99

        def fake_get(url: str, header: str):
            clock.spend(per_request)
            return (200, json.dumps({"status": "success", "data": ["acme"]}), {})

        targets = [f"https://prom-{i}.example" for i in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get), mock.patch.object(
            obs_check.time, "monotonic", clock.read
        ):
            summary = obs_check.check(targets, own_namespace="default")
        # Behavior: every target was assessed, so the result is not incomplete.
        # This is asserted FIRST on purpose. Truncation also cuts the request
        # count, and the clock advances per request, so a regression shortens the
        # run and would trip a premise check placed above this line, reporting the
        # wrong cause.
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertEqual(summary["targets_checked"], obs_check.MAX_TARGETS)
        # Premise: the run really did outlast the allowance, so a total ceiling
        # would have fired partway through and this test would be vacuous without
        # it.
        self.assertGreater(clock.now * 1000, obs_check.MAX_UNANSWERED_MS)

    def test_a_budget_with_no_time_allowance_is_untouched(self) -> None:
        # Every existing caller passes a one-element budget, and an embedder may
        # supply its own bound. Neither may be cut short by a bound it never set,
        # and a request that answers nothing must not crash either of them.
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

    def test_no_credential_that_works_leaves_the_guard_reported(self) -> None:
        def fake_get(url: str, header: str):
            return (403, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                ["https://prom.example"],
                own_namespace="default",
                credentials_by_target=_routes(
                    ["https://prom.example"],
                    [("default", obs_check.credential_header("basic", "admin:admin"))],
                ),
            )
        self.assertEqual(summary["credential_sources_accepted"], {})
        self.assertEqual(summary["credentials_offered"], 1)
        self.assertFalse(summary["cross_tenant_series_visible"])
        self.assertFalse(summary["unauth_query_ok"])

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

    def test_any_non_guard_scheme_is_upgraded_by_a_real_guard(self) -> None:
        # A failed earlier request leaves `unreachable`, `redirect`, or
        # `unknown`. Treating only "none" as upgradable let one of those stick
        # and reported no guard on a path that did refuse the check.
        for stale in ("unreachable", "redirect", "unknown", "none"):
            result = {"auth_scheme": stale}
            obs_check.merge_auth_scheme(result, 403, {})
            self.assertEqual(result["auth_scheme"], "forbidden", stale)

    def test_a_check_that_fails_before_a_refusal_still_reports_the_guard(self) -> None:
        # The FIRST label query must fail, because only the label loop and the
        # Grafana reads call merge_auth_scheme. `account` is first in
        # TENANT_LABEL_KEYS, so timing it out records "unreachable" before a
        # later label returns 401. With the old `current == "none"` condition the
        # stale scheme sticks and the summary names no guard.
        def fake_get(url: str, header: str):
            if url.endswith("/api/v1/status/buildinfo"):
                # The target answers, so it is reachable and the sweep continues.
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
        # `admin_api_exposed` means the delete API is routed AND unauthenticated.
        # A credentialed 405 only means this identity is authorized, so reading it
        # from the authenticated retry would make every properly guarded admin API
        # a CRITICAL on exactly the backends escalation exists to reach.
        accepted = obs_check.credential_header("basic", "admin:prom-operator")

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": "Basic"})
            if not header:
                # Unauthenticated: the admin endpoint is protected, as it should be.
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

    def test_a_refused_pass_stops_at_the_first_label_query(self) -> None:
        # A failed credential pass must be cheap, or escalation across 8 targets
        # cannot fit in the budget.
        label_calls: list[str] = []

        def fake_get(url: str, header: str):
            if "/label/" in url:
                label_calls.append(url)
                return (401, "", {"www-authenticate": "Basic"})
            if url.endswith("/api/health"):
                return (401, "", {"www-authenticate": "Basic"})
            return (401, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertEqual(len(label_calls), 1)

    def test_one_transport_failure_does_not_end_the_label_sweep(self) -> None:
        # TENANT_LABEL_KEYS is ordered most-specific first and `namespace` is
        # last, so aborting on a single timeout would skip the label that
        # usually carries another tenant's series on a Kubernetes Prometheus.
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

    def test_a_dead_target_still_stops_after_one_label(self) -> None:
        asked: list[str] = []

        def fake_get(url: str, header: str):
            if "/label/" in url:
                asked.append(url)
            return (None, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertEqual(len(asked), 1)
        self.assertEqual(summary["backends_reachable"], 0)

    def test_a_refused_grafana_proxy_pass_is_cheap(self) -> None:
        # The expensive shape: a Grafana that lists datasources openly and
        # refuses the proxy. Without the break, escalation over 8 of these
        # exhausts the budget and leaves later targets unchecked.
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (200, json.dumps([{"id": 1, "type": "prometheus"}]), {})
            return (403, "", {})

        credentials = [
            ("default", obs_check.credential_header("basic", f"u{index}:p")) for index in range(4)
        ]
        targets = [f"https://grafana{index}.example" for index in range(obs_check.MAX_TARGETS)]
        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(
                targets,
                own_namespace="default",
                credentials_by_target=_routes(targets, credentials),
            )
        self.assertEqual(summary["targets_skipped"], 0)
        self.assertLessEqual(summary["request_count"], obs_check.MAX_REQUESTS)
        self.assertTrue(summary["auth_required"])

    def test_a_single_sign_on_refusal_is_as_cheap_as_a_401(self) -> None:
        # An oauth2-proxy refuses by redirecting to its login path, not with a
        # 401. Gating the break on a status list missed that, so an SSO-fronted
        # target swept every label on a pass that could not read anything.
        label_calls: list[str] = []

        def fake_get(url: str, header: str):
            if "/label/" in url:
                label_calls.append(url)
            return (302, "", {"location": "/oauth2/start?rd=%2F"})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://prom.example"], own_namespace="default")
        self.assertEqual(len(label_calls), 1)
        self.assertEqual(summary["auth_schemes"], {"oauth-proxy": 1})
        self.assertTrue(summary["auth_required"])

    def test_a_grafana_proxy_that_refuses_by_redirect_is_also_cheap(self) -> None:
        proxy_calls: list[str] = []

        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (200, json.dumps([{"id": 1, "type": "prometheus"}]), {})
            proxy_calls.append(url)
            return (302, "", {"location": "/login"})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://grafana.example"], own_namespace="default")
        self.assertEqual(len(proxy_calls), 1)
        self.assertTrue(summary["auth_required"])

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
        # A Grafana whose datasource proxy answers with no credential is the
        # same exposure as an open Prometheus, so it must set unauth_query_ok.
        def fake_get(url: str, header: str):
            if url.endswith("/api/health"):
                return (200, json.dumps({"database": "ok", "version": "12.3.6"}), {})
            if url.endswith("/api/datasources"):
                return (200, json.dumps([{"id": 7, "type": "prometheus"}]), {})
            if "/label/" in url:
                return (200, json.dumps({"status": "success", "data": ["default"]}), {})
            return (404, "", {})

        with mock.patch.object(obs_check, "_get", side_effect=fake_get):
            summary = obs_check.check(["https://grafana.example"], own_namespace="default")
        self.assertTrue(summary["unauth_query_ok"])


if __name__ == "__main__":
    unittest.main()
