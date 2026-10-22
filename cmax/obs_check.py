"""Bounded, read-only observability-backend isolation check for the security audit.

This is the operator-host counterpart to the in-pod check used by the
`tenant-observability-backend-isolation` diagnostic. It ships inside the `cmax`
package so the checkout-free `cmax audit security` can run it.

Given one or more monitoring backend URLs (a Grafana or a Prometheus-compatible
datastore) plus optional credentials from the environment, it checks whether the
backend enforces tenancy on the query path or exposes every tenant's data. The
motivating failure mode: a dashboard filters each customer client-side while the
underlying store applies no per-tenant query enforcement, so any authenticated
tenant reads all tenants' series. `cmax.obs_discovery` supplies the URLs when the
operator has not named any.

The check also reports two facts an operator needs in order to act on a result,
both read from responses it already collects:

- the backend PRODUCT (Prometheus, Thanos, VictoriaMetrics, Grafana Mimir,
  Cortex, Grafana), from `/api/v1/status/buildinfo` or `/-/healthy`;
- the AUTHENTICATION SCHEME that guards the query path (basic, bearer, a
  single-sign-on proxy redirect, or none), from the `WWW-Authenticate` or
  `Location` response header.

SAFETY / PRIVACY:
- Read-only. Bounded GETs only; never writes, deletes, or POSTs. The admin check
  reads the HTTP status of a GET against the delete endpoint and never invokes it.
- The returned summary is SANITIZED: it reports COUNTS and booleans only (e.g.
  "34 distinct account values visible"), never the label values themselves, so a
  security report can be shared without leaking other tenants' identities.
- HTTPS uses the host trust store and verifies the certificate and hostname.
"""

from __future__ import annotations

import base64
import json
from http.client import HTTPException
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence

LABEL = "/api/v1/label/{key}/values"
ADMIN = "/api/v1/admin/tsdb/delete_series"
BUILDINFO = "/api/v1/status/buildinfo"
PROM_HEALTHY = "/-/healthy"
GRAFANA_HEALTH = "/api/health"
GRAFANA_DATASOURCES = "/api/datasources"

# Labels that identify a tenant on a shared metrics backend. More than one
# distinct value for any of these (beyond our own / shared infra) means the
# query path returned other tenants' series.
TENANT_LABEL_KEYS = ("account", "org_id", "tenant", "project", "namespace")

MAX_TARGETS = 8
# Covers MAX_TARGETS targets, each with one anonymous pass and up to four
# credential passes over MAX_DATASOURCES datasources (36 requests per target).
# A backend that answers every label with a non-guarded error sweeps more and can
# exceed this; it is then counted in `targets_skipped`, so the result is
# incomplete rather than a clean pass. Both cases are pinned in test_obs_check.py.
MAX_REQUESTS = 448
MAX_DATASOURCES = 2
REQUEST_TIMEOUT_S = 4.0
# Time spent on requests that get no answer is bounded separately from the
# request count, cumulatively across the run. A total-time limit would cut off
# slow but healthy backends, and a deadline reset by any answer never fires,
# because every pass opens with requests that do answer. A firewalled tenant
# whose connections hang until timeout must still finish every target and pass.
DEAD_DIRECT_PATH_REQUESTS = 4  # health, buildinfo, /-/healthy, first label
# Run-wide allowance: 40 full timeouts.
MAX_UNANSWERED_REQUESTS = MAX_TARGETS * 5
# Held as integer milliseconds so the boundary is exact. Each charge is measured
# wall clock (connect, TLS, teardown), which exceeds REQUEST_TIMEOUT_S, so the
# allowance carries an overhead factor or it empties before the Nth timeout.
UNANSWERED_OVERHEAD = 1.5
MAX_UNANSWERED_MS = int(
    MAX_UNANSWERED_REQUESTS * REQUEST_TIMEOUT_S * UNANSWERED_OVERHEAD * 1000
)
# Per-target share, refilled for each target, so one hanging backend cannot spend
# the coverage of the targets after it. It fits one full Grafana proxy sweep of
# timeouts plus overhead, so a hanging target's anonymous pass always completes
# and only its escalation is cut short, with `budget_exhausted` set.
MAX_UNANSWERED_PER_TARGET_MS = int(
    MAX_DATASOURCES
    * len(TENANT_LABEL_KEYS)
    * REQUEST_TIMEOUT_S
    * UNANSWERED_OVERHEAD
    * 1000
)
# Credentials tried against one guarded endpoint before giving up. Escalation
# stops at the first TENANT-OWNED credential that reads, so this only bounds the
# worst case.
MAX_CREDENTIALS_PER_TARGET = 4
# Tries reserved for vendor default credentials, which `harvest` appends last, so
# hosts with many harvested values still try `admin:admin` and the like.
RESERVED_DEFAULT_TRIES = 2
DEFAULT_CREDENTIAL_SOURCE = "default"
OPERATOR_CREDENTIAL_SOURCE = "env"
# Neither source is evidence of what a tenant holds, so a read by either does not
# stop the credential sweep. Attribution still reports `process-env`.
PROCESS_ENV_CREDENTIAL_SOURCE = "process-env"
NON_TENANT_CREDENTIAL_SOURCES = frozenset(
    {OPERATOR_CREDENTIAL_SOURCE, PROCESS_ENV_CREDENTIAL_SOURCE}
)

# Build-information payload tokens that name the backend product. Checked before
# the Prometheus key shape, because Grafana Mimir, Cortex, and Thanos all serve
# the Prometheus query API and would otherwise all read as "prometheus".
BUILDINFO_TOKENS: tuple[tuple[str, str], ...] = (
    ("mimir", "mimir"),
    ("cortex", "cortex"),
    ("thanos", "thanos"),
    ("victoria", "victoriametrics"),
)
PROM_BUILDINFO_KEYS = frozenset({"version", "revision", "goVersion"})

# Authentication schemes that mean the query path is guarded. A guard is correct
# behavior; it tells the operator which credential reproduces an authenticated
# read that is not tenant-scoped. `forbidden` is a guard too: a 403 on the query
# path refused this identity, whether or not it named a scheme.
GUARDED_SCHEMES = frozenset(
    {"basic", "bearer", "challenge", "oauth-proxy", "login-redirect", "forbidden"}
)

INFRA_NAMESPACES = frozenset(
    {
        "kube-system", "kube-public", "kube-node-lease", "monitoring", "prometheus",
        "observability", "gpu-operator", "gpu-operator-resources",
        "nvidia-gpu-operator", "kube-prometheus-stack", "cattle-monitoring-system",
        "cert-manager", "ingress-nginx", "istio-system", "default", "local",
        "local-path-storage", "metallb-system", "calico-system", "cilium-secrets",
    }
)

_TLS_CTX = ssl.create_default_context()


def auth_header(token: str = "", basic: str = "") -> str:
    """Build an Authorization header value. Bearer token wins over basic."""
    if token:
        return f"Bearer {token}"
    if basic:
        return "Basic " + base64.b64encode(basic.encode("utf-8")).decode("ascii")
    return ""


def credential_header(kind: str, value: str) -> str:
    """Build an Authorization header from a harvested credential.

    `raw` carries its own scheme, because a provisioned Grafana
    `httpHeaderValue1` is already a complete header value.
    """
    if not value:
        return ""
    if kind == "bearer":
        return auth_header(token=value)
    if kind == "basic":
        return auth_header(basic=value)
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib from following redirects, so a guard stays visible.

    A redirect is DATA here. A single-sign-on proxy answers an unauthenticated
    query with `302` to its own login path. Following that redirect turns the
    guard into a `200` on a login page, which reads as "no authentication" and
    hides the scheme the operator needs.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=_TLS_CTX)
)

_UPGRADE_CODES = (301, 302, 307, 308)


def _scheme_upgrade(url: str, location: str) -> str:
    """Return `location` when it is only an https upgrade of the same request.

    Host, path and port must match (both ports implicit counts as 80 to 443), so
    the check never follows a redirect onto a different service.
    """
    if not location:
        return ""
    original = urllib.parse.urlsplit(url)
    target = urllib.parse.urlsplit(urllib.parse.urljoin(url, location))
    if original.scheme != "http" or target.scheme != "https":
        return ""
    if original.hostname != target.hostname:
        return ""
    try:
        if original.port != target.port:
            return ""
    except ValueError:
        # `Location` comes from the backend. CPython raises on a non-numeric or
        # out-of-range port, and this runs inside the HTTPError handler, so the
        # sibling `except` cannot catch it and one broken proxy template would
        # end the whole audit. An unparseable port is simply not an upgrade.
        return ""
    if (original.path, original.query) != (target.path, target.query):
        return ""
    return target.geturl()


def _get(url: str, header: str, _upgraded: bool = False) -> tuple[int | None, str, dict[str, str]]:
    """Read-only GET. Returns (status, body, headers); status None on failure.

    Response headers come back lower-cased because `WWW-Authenticate` and
    `Location` identify the authentication scheme that guards the endpoint, and
    header names are case-insensitive on the wire. Redirects are reported, not
    followed, except for a single same-host https upgrade.
    """
    headers = {"Authorization": header} if header else {}
    request = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with _OPENER.open(request, timeout=REQUEST_TIMEOUT_S) as resp:
            body = resp.read(262144).decode("utf-8", "replace")
            return resp.status, body, _lower_headers(resp.headers.items())
    except urllib.error.HTTPError as exc:
        response_headers = _lower_headers(exc.headers.items() if exc.headers else [])
        if not _upgraded and exc.code in _UPGRADE_CODES:
            upgrade = _scheme_upgrade(url, response_headers.get("location", ""))
            if upgrade:
                return _get(upgrade, header, _upgraded=True)
        return exc.code, "", response_headers
    except (urllib.error.URLError, OSError, ValueError, HTTPException):
        return None, "", {}


def _lower_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {str(name).lower(): str(value) for name, value in items}


def detect_auth_scheme(status: int | None, headers: dict[str, str]) -> str:
    """Name the authentication scheme that guards an endpoint, from a 401/407
    challenge or a login redirect."""
    if status is None:
        return "unreachable"
    if status in (401, 407):
        challenge = headers.get("www-authenticate", "").lower()
        if "bearer" in challenge:
            return "bearer"
        if "basic" in challenge:
            return "basic"
        return "challenge"
    if status in (301, 302, 303, 307, 308):
        location = headers.get("location", "").lower()
        if any(token in location for token in ("oauth", "openid", "saml", "auth/realms")):
            return "oauth-proxy"
        if "login" in location or "signin" in location:
            return "login-redirect"
        return "redirect"
    if status == 403:
        return "forbidden"
    if 200 <= status < 300:
        return "none"
    return "unknown"


def merge_auth_scheme(result: dict, status: int | None, headers: dict[str, str]) -> None:
    """Record the guard on the QUERY path, upgrading an earlier unguarded scheme.

    Grafana can list datasources anonymously and still refuse the proxy query, so a
    later refusal replaces "none". A guard already found is never downgraded.
    """
    scheme = detect_auth_scheme(status, headers)
    current = result.get("auth_scheme") or ""
    if not current or (current not in GUARDED_SCHEMES and scheme in GUARDED_SCHEMES):
        result["auth_scheme"] = scheme


def classify_buildinfo(status: int | None, body: str) -> str:
    """Name the backend product from a `/api/v1/status/buildinfo` reply."""
    if status != 200 or not body:
        return ""
    lowered = body.lower()
    for token, platform in BUILDINFO_TOKENS:
        if token in lowered:
            return platform
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return ""
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and PROM_BUILDINFO_KEYS <= set(data):
        return "prometheus"
    return "prometheus-compatible"


def classify_health_body(status: int | None, body: str) -> str:
    """Name the backend product from a `/-/healthy` reply body.

    Prometheus answers "Prometheus Server is Healthy." and VictoriaMetrics
    answers with its own name, so this covers builds whose `buildinfo` endpoint
    is absent or blocked.
    """
    if status != 200 or not body:
        return ""
    lowered = body.lower()
    for token, platform in (
        ("victoriametrics", "victoriametrics"),
        ("thanos", "thanos"),
        ("prometheus", "prometheus"),
    ):
        if token in lowered:
            return platform
    return ""


def interpret_admin_status(status: int | None) -> bool:
    """True when the admin delete endpoint is routed and unauthenticated."""
    return status in (200, 400, 405)


def is_grafana_health(status: int | None, body: str) -> bool:
    if status != 200 or not body:
        return False
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False
    return isinstance(payload, dict) and "database" in payload and "version" in payload


def parse_datasources(status: int | None, body: str) -> list[dict]:
    if status != 200 or not body:
        return []
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(payload, list):
        return []
    out = []
    for entry in payload:
        if isinstance(entry, dict):
            out.append({"id": entry.get("id"), "type": str(entry.get("type") or "")})
    return out


def extract_label_values(status: int | None, body: str) -> set[str]:
    """Values from a Prometheus `/label/<key>/values` reply."""
    if status != 200 or not body:
        return set()
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return set()
    if not isinstance(payload, dict) or payload.get("status") != "success":
        return set()
    data = payload.get("data")
    if isinstance(data, list):
        return {str(v) for v in data if v}
    return set()


def classify_cross_tenant(
    label_values: dict[str, set[str]], own_namespace: str
) -> tuple[bool, dict[str, int]]:
    """Return (cross_tenant, per-key foreign counts) from collected label values.

    For namespace, only values beyond our own and shared infra count. For the
    other tenant-identifying keys, more than one distinct value means the backend
    returned series belonging to tenants other than us.
    """
    foreign: dict[str, int] = {}
    for key, values in label_values.items():
        clean = {v for v in values if v and v != "(null)"}
        if key == "namespace":
            extra = {v for v in clean if v != own_namespace and v not in INFRA_NAMESPACES}
            if extra:
                foreign[key] = len(extra)
        else:
            if len(clean) > 1:
                foreign[key] = len(clean)
    return (bool(foreign), foreign)


def out_of_budget(budget: list) -> bool:
    """Report whether the check may make no further request for this target.

    `budget` is [requests left (run-wide), this target's unanswered-ms share, the
    run's unanswered-ms total]. Shorter lists are accepted.
    """
    if budget[0] <= 0:
        return True
    for index in (1, 2):
        if len(budget) > index and budget[index] is not None and budget[index] <= 0:
            return True
    return False


def spend_request(budget: list, url: str, header: str) -> tuple[int | None, str, dict[str, str]]:
    """Make one request and charge its wall time to both unanswered-time budgets
    when it gets no answer (`status is None`). A 401 or redirect is an answer."""
    budget[0] -= 1
    if len(budget) > 1 and budget[1] is not None:
        started = time.monotonic()
        status, body, headers = _get(url, header)
        if status is None:
            charge = round((time.monotonic() - started) * 1000)
            budget[1] -= charge
            if len(budget) > 2 and budget[2] is not None:
                budget[2] -= charge
        return status, body, headers
    return _get(url, header)


def want_request(result: dict, budget: list) -> bool:
    """Report whether one more request is affordable; mark the target incomplete
    when it is not, so a pass cut short mid-sweep never reads as fully checked."""
    if out_of_budget(budget):
        result["budget_exhausted"] = True
        return False
    return True


def _check_prometheus(
    base: str, header: str, budget: list, admin_check: bool = True
) -> dict:
    result = {"reachable": False, "unauth_query_ok": False, "admin_api_exposed": False,
              "datasources_listable": False, "labels": {}, "requests": 0,
              "platform": "", "auth_scheme": "", "query_ok": False}
    if want_request(result, budget):
        result["requests"] += 1
        status, body, _headers = spend_request(budget, base + BUILDINFO, header)
        if status is not None:
            result["reachable"] = True
        result["platform"] = classify_buildinfo(status, body)
    if not result["platform"] and want_request(result, budget):
        result["requests"] += 1
        status, body, _headers = spend_request(budget, base + PROM_HEALTHY, header)
        if status is not None:
            result["reachable"] = True
        result["platform"] = classify_health_body(status, body)
    for index, key in enumerate(TENANT_LABEL_KEYS):
        # Checked per request rather than once per pass, because one hanging target
        # can spend its whole unanswered-time share inside a single label sweep.
        if not want_request(result, budget):
            break
        result["requests"] += 1
        status, body, headers = spend_request(budget, base + LABEL.format(key=key), header)
        if status is not None:
            result["reachable"] = True
        merge_auth_scheme(result, status, headers)
        if index == 0 and (
            detect_auth_scheme(status, headers) in GUARDED_SCHEMES
            or not result["reachable"]
        ):
            # Refused (any guarded scheme, including an SSO redirect) or dead: the
            # other labels would show the same, so a refused credential pass stays
            # cheap. A timeout on a reachable target keeps sweeping, because
            # `namespace`, last in TENANT_LABEL_KEYS, usually shows other tenants.
            break
        if status == 200:
            # Only an answered query can support a PASS; reachability alone cannot.
            result["query_ok"] = True
            if not header:
                result["unauth_query_ok"] = True
        result["labels"][key] = extract_label_values(status, body)
    if admin_check and result["reachable"] and want_request(result, budget):
        # The finding is an unauthenticated delete API, so the probe is always
        # sent without a credential, and credential retries skip it.
        result["requests"] += 1
        status, _body, _headers = spend_request(budget, base + ADMIN, "")
        if interpret_admin_status(status):
            result["admin_api_exposed"] = True
    return result


def _check_grafana(base: str, header: str, budget: list) -> dict:
    result = {"reachable": True, "unauth_query_ok": False, "admin_api_exposed": False,
              "datasources_listable": False, "labels": {}, "requests": 0,
              "platform": "grafana", "auth_scheme": "", "query_ok": False,
              "label_groups": []}
    if not want_request(result, budget):
        return result
    result["requests"] += 1
    status, body, headers = spend_request(budget, base + GRAFANA_DATASOURCES, header)
    merge_auth_scheme(result, status, headers)
    sources = parse_datasources(status, body)
    if sources:
        result["datasources_listable"] = True
    prom = [s for s in sources if "prometheus" in s["type"] or "mimir" in s["type"] or not s["type"]]
    for source in prom[:MAX_DATASOURCES]:
        ident = source.get("id")
        if ident is None:
            continue
        proxy = f"/api/datasources/proxy/{ident}"
        source_labels: dict[str, set[str]] = {}
        result["label_groups"].append(source_labels)
        for index, key in enumerate(TENANT_LABEL_KEYS):
            # The proxy sweep is the shape that can hang: `_check_grafana` starts
            # `reachable` at True, so the reachability abort cannot fire here and a
            # timing-out proxy sweeps every label of every datasource.
            if not want_request(result, budget):
                break
            result["requests"] += 1
            s, b, proxy_headers = spend_request(budget, base + proxy + LABEL.format(key=key), header)
            # The proxy read is the query that matters, so its guard outranks an
            # open datasource listing.
            merge_auth_scheme(result, s, proxy_headers)
            if index == 0 and detect_auth_scheme(s, proxy_headers) in GUARDED_SCHEMES:
                # Same reason as the direct path: a refused credential pass must
                # be cheap, or escalation across 8 targets cannot fit the budget.
                # A Grafana that lists datasources openly and refuses the proxy
                # is the expensive shape, and it is the shape this feature exists
                # to reach.
                break
            if s == 200:
                result["query_ok"] = True
                if not header:
                    result["unauth_query_ok"] = True
            vals = extract_label_values(s, b)
            if vals:
                result["labels"].setdefault(key, set()).update(vals)
                source_labels.setdefault(key, set()).update(vals)
    return result


def check_endpoint(
    base: str, header: str, budget: list, admin_check: bool = True
) -> dict:
    skipped = {"reachable": False, "requests": 0, "labels": {},
               "platform": "", "auth_scheme": "", "query_ok": False}
    if not want_request(skipped, budget):
        # Not checked at all. This must stay distinguishable from "checked and
        # clean", or a bounded budget silently becomes a green check.
        # `want_request` sets the flag.
        return skipped
    status, body, headers = spend_request(budget, base + GRAFANA_HEALTH, header)
    if is_grafana_health(status, body):
        result = _check_grafana(base, header, budget)
        result["requests"] += 1
        return result
    result = _check_prometheus(base, header, budget, admin_check)
    result["requests"] += 1
    if status is not None:
        result["reachable"] = True
    merge_auth_scheme(result, status, headers)
    return result


def select_credentials(
    credentials: Sequence[tuple[str, str]],
    cap: int = MAX_CREDENTIALS_PER_TARGET,
    reserved: int = RESERVED_DEFAULT_TRIES,
) -> list[tuple[str, str]]:
    """Choose which credentials one target may try, at most `cap`.

    Order: the operator credential (taking its slot from the defaults reserve), then
    tenant-owned sources, then vendor defaults (`reserved` slots are held for them),
    then `process-env` in any room left, since it cannot produce either finding.
    The result is the same for any input order.
    """
    if cap <= 0:
        return []
    operator = [pair for pair in credentials if pair[0] == OPERATOR_CREDENTIAL_SOURCE]
    defaults = [pair for pair in credentials if pair[0] == DEFAULT_CREDENTIAL_SOURCE]
    shell = [
        pair for pair in credentials if pair[0] == PROCESS_ENV_CREDENTIAL_SOURCE
    ]
    tenant = [
        pair
        for pair in credentials
        if pair[0] not in NON_TENANT_CREDENTIAL_SOURCES
        and pair[0] != DEFAULT_CREDENTIAL_SOURCE
    ]
    if not defaults and not operator and not shell:
        return list(credentials)[:cap]
    # With defaults present, keep at least one operator credential but leave room
    # for tenant-owned tries and the defaults reserve.
    operator_room = max(cap - reserved - min(len(tenant), reserved), 1)
    chosen = operator[:operator_room] if defaults else operator[:cap]
    reserve = max(reserved - len(chosen), 0) if defaults else 0
    chosen += tenant[: max(cap - len(chosen) - reserve, 0)]
    chosen += defaults[: max(cap - len(chosen), 0)]
    chosen += shell[: max(cap - len(chosen), 0)]
    return chosen[:cap]


def check_endpoint_escalating(
    base: str, credentials: Sequence[tuple[str, str]], budget: list
) -> dict:
    """Check anonymously first, then retry with each credential until one reads.

    The anonymous pass comes first so an authenticated read is never recorded as an
    unauthenticated one. Escalation stops at the first tenant-owned credential that
    reads and records its source label, never its value. A read by a non-tenant
    source is held and returned only if no tenant-owned source also reads.

    `credentials` is a sequence of `(source_label, header_value)` pairs.
    """
    result = check_endpoint(base, "", budget)
    result["credential_source"] = ""
    if result.get("query_ok"):
        return result
    if not result.get("reachable"):
        # Nothing answered, so no credential can help. This is what a correctly
        # firewalled tenant looks like; escalating would only spend its budget.
        return result
    anonymous_scheme = result.get("auth_scheme", "")
    anonymous_requests = int(result.get("requests", 0))
    held_read: dict | None = None
    truncated = False
    for source, header in select_credentials(credentials):
        if not header:
            break
        if out_of_budget(budget):
            # Credentials left untried: the target is not fully swept.
            truncated = True
            break
        retry = check_endpoint(base, header, budget, admin_check=False)
        anonymous_requests += int(retry.get("requests", 0))
        if not retry.get("query_ok"):
            if retry.get("budget_exhausted"):
                # This pass was cut short, so "did not read" is not a finding.
                truncated = True
                break
            continue
        # The guard, `unauth_query_ok` and `admin_api_exposed` describe the
        # anonymous caller, so they come from the anonymous pass.
        retry["auth_scheme"] = anonymous_scheme or retry.get("auth_scheme", "")
        retry["unauth_query_ok"] = False
        retry["admin_api_exposed"] = bool(result.get("admin_api_exposed"))
        retry["credential_source"] = source
        if source in NON_TENANT_CREDENTIAL_SOURCES:
            # Not tenant evidence: hold the read and keep sweeping. `process-env`
            # replaces a held operator read, because attribution can name it.
            if (
                held_read is None
                or held_read.get("credential_source") == OPERATOR_CREDENTIAL_SOURCE
            ):
                held_read = retry
            continue
        retry["requests"] = anonymous_requests
        return retry
    if held_read is not None:
        held_read["requests"] = anonymous_requests
        # Incomplete if a credential was left untried or this pass was cut short.
        held_read["budget_exhausted"] = bool(
            truncated or held_read.get("budget_exhausted")
        )
        return held_read
    result["requests"] = anonymous_requests
    if truncated:
        result["budget_exhausted"] = True
    return result


def check(
    targets: Iterable[str],
    own_namespace: str = "default",
    credentials_by_target: Mapping[str, Sequence[tuple[str, str]]] | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Check backends and return a SANITIZED counts-only summary.

    A credential can be used only for the exact canonical target key that owns
    it. This prevents a discovered lookalike service from receiving credentials
    that came from another backend.
    """
    routed_credentials = {
        str(target).strip().rstrip("/"): list(credentials)
        for target, credentials in (credentials_by_target or {}).items()
        if str(target).strip()
    }
    credential_route_count = sum(
        len(credentials) for credentials in routed_credentials.values()
    )
    # [requests left, this target's unanswered-time share, the run's total].
    budget = [MAX_REQUESTS, MAX_UNANSWERED_PER_TARGET_MS, MAX_UNANSWERED_MS]
    reachable = 0
    unauth = admin = datasources = False
    cross_tenant = False
    foreign_counts: dict[str, int] = {}
    requests = 0
    checked = 0
    answered = 0
    all_targets = list(targets)
    skipped = max(0, len(all_targets) - MAX_TARGETS)
    platforms: dict[str, int] = {}
    auth_schemes: dict[str, int] = {}
    credential_sources: dict[str, int] = {}
    # Credential sources whose OWN target returned another tenant's series, which
    # is a stronger claim than "this credential was accepted somewhere".
    cross_tenant_sources: dict[str, int] = {}
    candidates = all_targets[:MAX_TARGETS]
    if skipped and progress:
        progress(f"{skipped} target(s) skipped: limit of {MAX_TARGETS} per run")
    for index, base in enumerate(candidates, start=1):
        # Refill the per-target share; the run total is never refilled.
        budget[1] = MAX_UNANSWERED_PER_TARGET_MS
        canonical_base = base.rstrip("/")
        started = time.monotonic()
        if progress:
            progress(
                f"backend {index}/{len(candidates)}: checking "
                f"{_progress_target(canonical_base)}"
            )
        credentials = routed_credentials.get(canonical_base, [])
        if credentials:
            r = check_endpoint_escalating(canonical_base, credentials, budget)
        else:
            r = check_endpoint(canonical_base, "", budget)
        if progress:
            if r.get("budget_exhausted"):
                outcome = "incomplete; check budget reached"
            elif r.get("query_ok"):
                outcome = "query answered"
            elif r.get("reachable"):
                outcome = "reachable; query did not answer"
            else:
                outcome = "no response"
            progress(
                f"backend {index}/{len(candidates)}: {outcome}; "
                f"{int(r.get('requests', 0))} request(s); "
                f"{time.monotonic() - started:.1f}s"
            )
        checked += 1
        accepted = str(r.get("credential_source") or "")
        if accepted:
            credential_sources[accepted] = credential_sources.get(accepted, 0) + 1
        requests += int(r.get("requests", 0))
        if r.get("reachable"):
            reachable += 1
        if r.get("query_ok"):
            answered += 1
        if r.get("budget_exhausted"):
            skipped += 1
        unauth = unauth or bool(r.get("unauth_query_ok"))
        admin = admin or bool(r.get("admin_api_exposed"))
        datasources = datasources or bool(r.get("datasources_listable"))
        platform = str(r.get("platform") or "")
        if platform:
            platforms[platform] = platforms.get(platform, 0) + 1
        scheme = str(r.get("auth_scheme") or "")
        if scheme:
            auth_schemes[scheme] = auth_schemes.get(scheme, 0) + 1
        labels = r.get("labels", {})
        # Classify each actual query store independently. Grafana can proxy
        # several isolated data sources, and endpoint aliases can overlap.
        own_cross = False
        for group in r.get("label_groups", [labels]):
            group_cross, group_counts = classify_cross_tenant(group, own_namespace)
            own_cross = own_cross or group_cross
            for key, count in group_counts.items():
                foreign_counts[key] = max(foreign_counts.get(key, 0), count)
        cross_tenant = cross_tenant or own_cross
        # Attribute every accepted source except the operator's own credential,
        # including `process-env`, which the report words separately.
        if accepted and accepted != OPERATOR_CREDENTIAL_SOURCE:
            # Attribute only the evidence returned by this target.
            if own_cross:
                cross_tenant_sources[accepted] = cross_tenant_sources.get(accepted, 0) + 1
    return {
        "configured": True,
        "authenticated": bool(credential_sources),
        "targets_checked": checked,
        "backends_reachable": reachable,
        # Backends whose query path actually answered. Reachability alone proves
        # nothing about tenancy, so only this count licenses a PASS.
        "queries_answered": answered,
        # Targets omitted by the target cap or request/time budgets. A non-zero count means the
        # run is incomplete and must not report a clean result.
        "targets_skipped": skipped,
        "unauth_query_ok": unauth,
        "cross_tenant_series_visible": cross_tenant,
        "admin_api_exposed": admin,
        "grafana_datasources_listable": datasources,
        "foreign_tenant_counts": foreign_counts,  # counts only; no values
        "foreign_tenant_count_scope": "maximum-per-query-store",
        "backend_platforms": platforms,  # product name -> endpoint count
        "auth_schemes": auth_schemes,  # scheme name -> endpoint count
        "auth_required": any(scheme in GUARDED_SCHEMES for scheme in auth_schemes),
        # Source LABELS only, never a credential value. A non-empty map means a
        # guarded backend accepted a credential this tenant already held.
        "credential_sources_accepted": credential_sources,
        # Sources that read foreign series on their OWN target. Only these may be
        # named as the identity that reached the exposure.
        "cross_tenant_credential_sources": cross_tenant_sources,
        "credentials_offered": credential_route_count,
        "request_count": requests,
    }


def _progress_target(value: str) -> str:
    """Return a credential-free endpoint label for live progress."""
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or "unknown-host"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme}://{host}{port}"
    except ValueError:
        return "configured backend"
