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
# Sized for 8 targets, 1 anonymous pass plus 4 credential retries each. A refused
# pass stops at its first refused label query, so a retry that fails stays cheap.
# The shape this bound covers is a Grafana that lists its datasources without a
# credential and answers the proxy read with one: the listing plus a label sweep
# for each of MAX_DATASOURCES, twice over, because a read by the operator's own
# credential does not stop the sweep. That measures 36 requests per target HERE,
# where TENANT_LABEL_KEYS has five entries, so 288 for eight targets.
# `test_the_budget_covers_the_worst_case_sweep_on_every_target` in
# test_obs_check.py runs that shape on all MAX_TARGETS and asserts both figures,
# so this comment cannot drift from what the code spends. The diagnostic twin
# sweeps nine labels and spends more; size that constant from its own test.
#
# This is NOT the worst case. The cheap exit fires only for a GUARDED scheme, so a
# pass whose first label answers a non-guarded non-200 sweeps every label of every
# datasource and still does not read, which leaves no operator hold and five
# full-price passes: 60 per target, 480 for eight. A Grafana proxying a
# provisioned datasource whose own backend is dead answers 502 exactly that way,
# and stale provisioning is common. That case is deliberately left above the
# bound: it is counted in `targets_skipped`, which blocks a clean pass in every
# verdict path, so exceeding the budget degrades to an INCONCLUSIVE result and
# never to a silent green check. `test_a_dead_provisioned_backend_exceeds_the_
# budget_and_says_so` pins that.
MAX_REQUESTS = 448
MAX_DATASOURCES = 2
REQUEST_TIMEOUT_S = 4.0
# Seconds this check may spend on requests that answer NOTHING, across the whole
# run. The request budget bounds requests, and a request that times out costs one
# unit but REQUEST_TIMEOUT_S seconds. A Grafana that holds the proxy connection
# open instead of answering is the bad case: a timeout is not a guarded scheme, so
# the cheap exit never fires and every label of every datasource is swept on all
# five passes, which measures 25 minutes for eight targets under escalation.
#
# The bound counts UNANSWERED time, and it counts it CUMULATIVELY. Two weaker
# shapes were tried and both fail:
#
# - A ceiling on TOTAL time cannot separate the two clusters it must treat
#   differently: one that hangs, and one that is slow but answering. Any ceiling
#   short enough to cut off the first also truncates the second, and truncation is
#   reported as an incomplete result, so a large healthy cluster whose label reads
#   are merely slow would be recorded as INCONCLUSIVE.
# - A deadline that any answer pushes forward, so only CONSECUTIVE dead time
#   counts, never fires on the shape above. Every escalation pass opens with
#   `/api/health` and `/api/datasources`, which answer, so at most ten proxy
#   timeouts accumulate before an answer resets the deadline. Measured: the full
#   448-request budget spent, 1488 seconds of it wasted, and the bound silent.
#   `test_a_hanging_proxy_cannot_be_kept_alive_by_the_passes_that_answer` pins it.
#
# Counting unanswered time cumulatively separates the cases for the right reason. A
# backend that answers spends none of this allowance however slow it is, and a
# backend that hangs spends it whatever else answers alongside. A request that
# fails FAST, such as a refused connection, costs nearly nothing, which is correct:
# it wastes no time.
#
# A target that has spent its share, and a run that has spent the total, both stop
# through `out_of_budget`, so the run degrades through `targets_skipped` exactly
# like an exhausted request budget and reports an incomplete result rather than a
# clean one.
#
# The total must cover every target timing out on the direct path, because that is
# what a CORRECTLY firewalled tenant looks like: a Kubernetes NetworkPolicy DROPs by
# default, so a blocked connection hangs until the timeout rather than being refused
# at once. Such a run must report `backends_reachable == 0` and pass. A flat 30
# timeouts emptied the pool during target six, so a properly isolated tenant was
# reported as two targets not checked and INCONCLUSIVE.
DEAD_DIRECT_PATH_REQUESTS = 4  # health, buildinfo, /-/healthy, first label
# Keep the run-wide allowance independent from the shorter dead-target path. It
# preserves the published 40-timeout, 240-second ceiling for mixed target shapes.
MAX_UNANSWERED_REQUESTS = MAX_TARGETS * 5
# Derived from this file's own timeout, so the two check copies do not share a
# hand-picked number: 240 s here, and 120 s in the diagnostic, whose timeout is 2 s.
# The threshold is a request COUNT because that is the quantity with a meaning: a
# run that has waited out that many full timeouts has learned all it is going to.
# Held as integer MILLISECONDS, and each charge is ROUNDED. Subtracting float
# seconds one request at a time leaves a residue: 8.0 - 4.0 - 4.0 came out as
# 8.9e-16 rather than 0, which read as allowance remaining and bought one request
# past the bound. Truncating the charge instead biased every one of them low.
# Rounded integers make the boundary exact and let a test pin it.
#
# The overhead factor is what makes the guarantee above true. `spend_request` charges
# MEASURED WALL CLOCK, from before the connect to after the socket teardown, while
# REQUEST_TIMEOUT_S bounds only the wait for data, so every charge is LARGER than the
# timeout. An allowance of exactly N * REQUEST_TIMEOUT_S therefore empties before the
# Nth timeout returns, and the eight-hanging-target case this constant exists to admit
# was cut off around target six or seven. Name resolution against an unreachable DNS
# server and TLS setup both land in that gap.
UNANSWERED_OVERHEAD = 1.5
MAX_UNANSWERED_MS = int(
    MAX_UNANSWERED_REQUESTS * REQUEST_TIMEOUT_S * UNANSWERED_OVERHEAD * 1000
)
# The share of that allowance one target may spend. A single pool for the whole run
# is a resource the FIRST target can drain, and the target that drains it is the
# likely one rather than the unlucky one: `endpoints_from_services` sorts by URL, so
# on a release-prefixed install `<release>-grafana` sorts ahead of
# `<release>-prometheus`. One hanging Grafana under escalation sweeps
# MAX_DATASOURCES * len(TENANT_LABEL_KEYS) dead proxy reads per pass, which waits out
# 40 s of TIMEOUTS here, so a single pool was gone inside that one target's
# escalation. Every later target then returned from the `check_endpoint` entry check
# having made no request, so a cluster with one hanging Grafana and seven healthy
# guarded backends reported eight targets not checked and a WARNING, and a cross-tenant
# CRITICAL on any of the seven was never reached.
#
# Exactly one worst-case pass: the Grafana proxy sweep reads
# MAX_DATASOURCES * len(TENANT_LABEL_KEYS) labels and cannot abort early, because
# `_check_grafana` starts `reachable` at True and a timeout is not a guarded scheme.
# That sweep is 40 s of timeouts here, and 36 s in the diagnostic, whose sweep is
# longer and whose timeout is shorter.
#
# The SHARE is that sweep plus the same overhead factor the run total carries, for
# the same reason: the real charge per unanswered request exceeds REQUEST_TIMEOUT_S,
# so a share of exactly one sweep's worth of timeouts empties INSIDE that sweep and
# truncates the anonymous pass it exists to protect. That makes the share 60 s here
# and 54 s in the diagnostic. Keep the two figures distinct: 40 s is what the sweep
# waits out, 60 s is what the share allows it.
#
# Sized so the ANONYMOUS pass of a hanging target always completes, because that is
# the pass which produces `unauth_query_ok`, `admin_api_exposed`, and the datasource
# listing. Only escalation on that target is cut short, and it is cut short with
# `budget_exhausted` set, so the lost coverage is reported. A smaller share, such as
# a flat quarter of the run allowance, truncates the anonymous pass itself and
# throws away the findings the run exists to collect.
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
# Tries held back for the vendor `default` source, which `harvest` appends last
# because it is the least trusted. Taking the first four credentials dropped the
# defaults on exactly the hosts where they are worth trying: a Grafana that yields
# a service-account token, `grafana.ini`, provisioning, and process-env values
# fills all four tries, so `admin:admin` and `admin:prom-operator` were never
# offered although reaching them is why the source exists. The reservation is half
# the cap, because a harvested value is likelier to read than a vendor default and
# the request bound must not move.
RESERVED_DEFAULT_TRIES = 2
# The source label of the vendor defaults, which the reservation above selects on.
# Historical fixtures use this label for vendor default credentials.
DEFAULT_CREDENTIAL_SOURCE = "default"
# Historical fixtures use this label for credentials that an operator supplied.
OPERATOR_CREDENTIAL_SOURCE = "env"
# The sweep-stop rule is the WIDER of the two, because `process-env` is not tenant
# evidence either. Attribution keeps the narrower rule and still reports
# `process-env`, so the two are deliberately different sets.
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

    A plain `http` to `https` redirect to the same host, port, and path carries no
    authentication meaning. Without this one hop an https-only backend would
    read as unreachable, and the isolation question would never be asked.

    The port must match too. A redirect from `http://host:9090/x` to
    `https://host/x` lands on 443, which is a different service, and continuing
    the check there would attribute another endpoint's answers to this target.
    Both ports implicit is the one exception, because that is the ordinary
    80-to-443 upgrade of the same service.
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
    except (urllib.error.URLError, OSError, ValueError):
        return None, "", {}


def _lower_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {str(name).lower(): str(value) for name, value in items}


def detect_auth_scheme(status: int | None, headers: dict[str, str]) -> str:
    """Name the authentication scheme that guards an endpoint.

    The scheme is what an operator needs in order to reproduce a finding with a
    legitimate credential, and it is free: it is already in the response to a
    request the check makes anyway. A `401` carries the scheme in
    `WWW-Authenticate`; a single-sign-on proxy answers with a redirect to its own
    login path instead.
    """
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
    """Record the guard on the QUERY path, upgrading an earlier "none".

    A Grafana can list its datasources without a credential and still refuse the
    proxy read that actually queries the store. Taking the scheme only from the
    listing then reports `none` while every tenancy query was refused, which
    makes `auth_required` false on a guarded query path. An existing "none" is
    therefore replaced when a later request is refused; a guard already found is
    never downgraded. Every scheme outside GUARDED_SCHEMES is upgradable, which
    covers an earlier `unreachable`, `redirect`, or `unknown` from a failed
    request. Those would otherwise stick and leave `auth_required` false on a
    path that did refuse.
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
    """Report whether the check may make no further request for THIS target.

    Three limits stop a request, and this is the ONE place that weighs them, so a
    call site cannot honour some of them and miss the rest. The request count at
    index 0 is a run-wide resource. The unanswered-time allowance at index 1 belongs
    to the current target, and `check` refills it for the next one, so a hanging
    backend costs its own coverage and not the coverage of every target behind it.
    The run-wide unanswered-time total at index 2 is never refilled, so once it is
    spent every remaining target is refused and the run ends.

    A shorter budget list is accepted, so a caller that only bounds requests, and a
    test that only bounds one target, both work unchanged.
    """
    if budget[0] <= 0:
        return True
    for index in (1, 2):
        if len(budget) > index and budget[index] is not None and budget[index] <= 0:
            return True
    return False


def spend_request(budget: list, url: str, header: str) -> tuple[int | None, str, dict[str, str]]:
    """Spend one request, and charge the time to it when it answers nothing.

    Every request the check makes goes through here, so the accounting holds by
    construction instead of by convention at each call site. `status is None` is the
    one thing that counts as no answer: `_get` returns it for a timeout and for
    every other transport failure, while a 401 or a redirect is a real reply that
    tells the check what guards the endpoint.

    The charge is the time this request actually took, so a connection refused
    instantly costs nearly nothing while a held-open connection costs the full
    timeout. Dead time is charged to this target's share AND to the run total.
    Neither is acted on here: `out_of_budget` is the single place that decides
    whether the next request may be made, so a spent share stops one target and a
    spent run total stops the run.
    """
    budget[0] -= 1
    if len(budget) > 1 and budget[1] is not None:
        started = time.monotonic()
        status, body, headers = _get(url, header)
        if status is None:
            # Each charge is rounded, because `int()` floors and lost up to a
            # millisecond every time, which drifted the bound later than the
            # constant says.
            charge = round((time.monotonic() - started) * 1000)
            budget[1] -= charge
            if len(budget) > 2 and budget[2] is not None:
                budget[2] -= charge
        return status, body, headers
    return _get(url, header)


def want_request(result: dict, budget: list) -> bool:
    """Report whether one more request is affordable, and record it when it is not.

    A target whose coverage was cut short must not read as fully checked. Setting the
    flag only where a pass never STARTED left the mid-pass case silent: a label sweep
    that stopped part way returned no flag, so the target counted as checked and
    clean, and a hanging backend scored as "refused every read" instead of as
    incomplete. Every site that wants a request and cannot afford it records that
    here, so the flag cannot be forgotten at one of them.

    Every limit is weighed by `out_of_budget`, so a caller that starts with its
    share already spent makes no request at all.
    """
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
            # This identity cannot read the query path at all, so the remaining
            # labels would spend the budget to learn the same thing. Escalation
            # relies on this: a refused credential pass must be cheap. The test is
            # the GUARDED_SCHEMES set rather than a status list, because a
            # single-sign-on proxy refuses by redirecting to its login path, not
            # with a 401, and that pass must be cheap too.
            #
            # A transport failure is different. TENANT_LABEL_KEYS is ordered
            # most-specific first, and `namespace` is last, so aborting on one
            # timeout would skip the label that usually carries another tenant's
            # series. The reachability test keeps a live target sweeping while a
            # dead one still stops after a single request.
            break
        if status == 200:
            # The query path actually ANSWERED. Reachability alone proves
            # nothing about tenancy: a backend that refuses every read is
            # reachable, and reporting that as enforced tenancy is a vacuous
            # pass. Only an answered query licenses a PASS. With a credential
            # it also means that credential works, which stops the escalation
            # loop.
            result["query_ok"] = True
            if not header:
                result["unauth_query_ok"] = True
        result["labels"][key] = extract_label_values(status, body)
    if admin_check and result["reachable"] and want_request(result, budget):
        # Skipped only on an ESCALATION RETRY. `admin_api_exposed` is defined as the
        # delete API being routed AND unauthenticated, so a credentialed 405 or 400
        # only says this identity is authorized, which is not the finding.
        # `check_endpoint_escalating` already discards the credentialed answer and
        # keeps the anonymous one, so making the request on every credential pass
        # could contribute no evidence and spent one request of a shared budget
        # each time. On eight targets under escalation that waste could push a
        # later backend into `targets_skipped`.
        #
        # The caller decides instead of this function testing `not header`, which
        # keeps this low-level helper correct for historical credential fixtures.
        #
        # The request itself is sent WITHOUT the header even when the rest of the
        # pass carries one, which is what keeps the finding anonymous by
        # construction in every configuration. Sending the operator's credential
        # here would let a `405` that only proves this identity is authorized raise
        # a CRITICAL, and the operator credential is commonly an administrator one
        # the provider handed over.
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
    """Choose which credentials one target may try, keeping the defaults reachable.

    The four categories below are ordered by trust with TWO deliberate departures,
    each stated where it is made: the operator credential takes its slot from the
    DEFAULTS reserve, and `PROCESS_ENV_CREDENTIAL_SOURCE` moves from its collection
    rank of 5 to the tail, behind the vendor defaults. So the selection is not a prefix
    of the collection order with reservations applied. On
    `[service-account, process-env, kubernetes-secret, default, default]` it comes out
    `['service-account', 'kubernetes-secret', 'default', 'default']`, with rank 5
    dropped and rank 6 promoted over it, which is the whole point of the fourth
    category.

    This holds for ANY input order, so it does not depend on `cap_keeping_defaults`
    having held the same two sources back at collection. Both layers protect them, and
    each is needed: a slot the harvest cap already spent cannot be recovered here, and
    a list this function is handed directly is not capped there.

    The reservation only changes the outcome on a host that yields enough harvested
    values to fill the cap on its own, which is where taking the first `cap` entries
    silently dropped the vendor defaults.

    Leftover room goes to the defaults, so a host with one harvested value still
    tries both of them rather than holding two tries empty.

    FOUR categories, because they answer different questions:

    - `OPERATOR_CREDENTIAL_SOURCE` is the credential the operator named. It must be
      tried, but a read by it is not attributed and does not stop the sweep, so it
      cannot produce the finding on its own.
    - Tenant-owned sources are the ones that DO produce the finding.
    - `DEFAULT_CREDENTIAL_SOURCE` is a finding in its own right.
    - `PROCESS_ENV_CREDENTIAL_SOURCE` can produce NEITHER. It cannot support the
      tenant-held claim, for the reason it is gated opt-in, and it is not the
      credential the operator named for this cluster. It is tried LAST, out of
      whatever room the other three leave.

    The operator credential takes its slot from the DEFAULTS reserve rather than from
    the tenant-owned quota. Counting it as a tenant-owned try left only one such try
    whenever an operator credential was present with collected credentials. The extra
    passes exist to attribute ordinary tenant access,
    and the cap was dropping `grafana-ini` and provisioning before they ran.

    `process-env` sat in the tenant-owned quota for the same reason, and cost more,
    because `harvest` puts it at trust rank 5. On
    `[service-account, process-env, kubernetes-secret]` it took the second of two
    tenant tries, so `kubernetes-secret` was never offered and the attributed claim was
    unreachable. Historical callers could supply that shape. Trying it last means a
    credential that cannot produce either finding never displaces one that can.

    The total is unchanged in every case, so the request bound does not move.
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
    # Historical fixtures can contain two `env` credentials, and both are tried
    # when they fit. They fit when the host yielded no
    # vendor defaults, because then nothing is held back for that source.
    #
    # With defaults present, four slots cannot hold two operator credentials, the
    # two tenant-owned tries that produce the finding, and a default. One operator
    # credential yields, because it is the try that can contribute least: a read by
    # this source is not attributed and does not stop the sweep, and `auth_header` has
    # always preferred the token over the basic pair when both are set, so the
    # non-escalating path never used the second one either. Raising the cap instead
    # would move the request bound and its derivation above `MAX_REQUESTS`.
    # Reached only when `defaults` is non-empty, because `chosen` below ignores
    # `operator_room` otherwise. The floor of 1 keeps one operator credential when the
    # reserve arithmetic would otherwise leave none: the source the operator named
    # explicitly is never the one to drop entirely.
    operator_room = max(cap - reserved - min(len(tenant), reserved), 1)
    # `operator_room` is at least 1 by its own floor, so it needs no second clamp.
    chosen = operator[:operator_room] if defaults else operator[:cap]
    # What the operator credential took comes out of the defaults reserve. With no
    # defaults collected there is nothing to hold back, so every remaining slot goes
    # to the tenant-owned sources.
    reserve = max(reserved - len(chosen), 0) if defaults else 0
    chosen += tenant[: max(cap - len(chosen) - reserve, 0)]
    chosen += defaults[: max(cap - len(chosen), 0)]
    # The shell credential is last, and only if the three categories above left room.
    # It is the one source that can produce neither finding, so it never displaces a
    # try that can. It is dropped whenever the categories above already fill the cap,
    # which is why the sweep-stop rule for it is a guard rather than the common path:
    # `harvest` ranks it fifth, and after this it is offered behind every tenant-owned
    # source that fits.
    chosen += shell[: max(cap - len(chosen), 0)]
    return chosen[:cap]


def check_endpoint_escalating(
    base: str, credentials: Sequence[tuple[str, str]], budget: list
) -> dict:
    """Check anonymously first, then retry with each credential until one reads.

    Order matters twice. The anonymous pass must come first, because
    `unauth_query_ok` is only true when NO credential was sent, and an
    authenticated read must never be recorded as an unauthenticated one. The
    credentials then run in descending order of trust, so the operator's own
    credential is tried before a harvested one. The opt-in shell credential is the one
    source offered behind a vendor default, so a default is second to last whenever
    that source is present and the cap leaves room for it, and last otherwise.

    Escalation stops at the first TENANT-OWNED credential whose query is
    answered. That is the credential that reproduces the finding, and its SOURCE
    LABEL is recorded. The value is never recorded.

    A read by any source in `NON_TENANT_CREDENTIAL_SOURCES` does not stop the sweep.
    Neither the operator's own credential nor one out of the operator's shell is
    evidence about what an ordinary tenant holds, so returning on either reported the
    finding against a source the assessment then declines to treat as tenant access.
    What each one costs differs, because their trust ranks differ.
    `OPERATOR_CREDENTIAL_SOURCE` is tried first, so returning on it left EVERY
    tenant-owned credential untried. `PROCESS_ENV_CREDENTIAL_SOURCE` sits at rank 5 in
    `harvest`, behind `service-account`, `grafana-ini`, and `grafana-provisioning`, so
    returning on it left `kubernetes-secret` untried on a login-node run, where those
    two were the whole tenant quota. `select_credentials` now offers `process-env` last
    of all, out of whatever room the other three categories leave, so that second case
    is a guard rather than the common path. The read is held and returned only when
    nothing lower in the trust order also reads, so the finding itself is never lost.

    When both non-tenant sources read, the held read is the one attribution can
    name. `OPERATOR_CREDENTIAL_SOURCE` is dropped from attribution entirely, so
    holding it reports no source at all, while `process-env` carries its own
    sentence in the report.

    `credentials` is a sequence of `(source_label, header_value)` pairs.
    """
    result = check_endpoint(base, "", budget)
    result["credential_source"] = ""
    if result.get("query_ok"):
        return result
    if not result.get("reachable"):
        # NOTHING answered on the anonymous pass, so the transport is blocked and no
        # credential can change that. Escalating would spend four more passes to
        # learn the same thing, at the full timeout for every read. That is the
        # CORRECT posture for a tenant whose NetworkPolicy cuts it off from the
        # monitoring namespace, and a DROP hangs rather than refuses, so without this
        # a properly isolated tenant spent five times its share on every target and
        # the run reported the later ones as not checked instead of passing.
        #
        # `_check_grafana` starts `reachable` at True, so a Grafana that lists its
        # datasources and hangs on the proxy is still escalated. That is the shape
        # this feature exists to reach, and it is not this case.
        return result
    anonymous_scheme = result.get("auth_scheme", "")
    anonymous_requests = int(result.get("requests", 0))
    held_read: dict | None = None
    truncated = False
    # The cap is applied by the selection, which holds tries back for the vendor
    # defaults instead of letting harvested values fill every slot.
    for source, header in select_credentials(credentials):
        if not header:
            break
        if out_of_budget(budget):
            # The budget ran out with credentials still untried, so a tenant-owned
            # credential was never offered and the target must not read as fully
            # swept. That is the silent green check `targets_skipped` exists to
            # prevent. `out_of_budget` covers a spent per-target share as well as a
            # spent request count, because a share that runs out inside a credential
            # pass leaves the remaining credentials just as untried.
            #
            # This is the CHEAP EXIT rather than the only guard. `want_request` sets
            # the flag on any pass that cannot afford its next request, including the
            # entry check in `check_endpoint`, so falling through would report the
            # same thing for the cost of one call that makes no request. Deleting
            # this block leaves every test passing. Breaking here keeps the reason
            # in one place.
            truncated = True
            break
        retry = check_endpoint(base, header, budget, admin_check=False)
        anonymous_requests += int(retry.get("requests", 0))
        if not retry.get("query_ok"):
            if retry.get("budget_exhausted"):
                # THIS pass was cut short inside its own label sweep, so "did not
                # read" is not a finding about the credential. Recording it as one
                # would report a guarded backend on evidence the check never
                # gathered. `want_request` guards every request in the pass and
                # sets the flag on the pass that could not afford one, so the test
                # is whether coverage was lost.
                #
                # Testing `out_of_budget` here instead marked a COMPLETE pass
                # truncated whenever it spent the last of the budget, which put a
                # fully assessed guarded backend into `targets_skipped` and turned
                # a clean result into an incomplete WARNING. A credential left
                # untried is already caught by the `out_of_budget` test at the top
                # of this loop on the next iteration, so nothing needs that test
                # twice.
                truncated = True
                break
            continue
        # Three facts belong to the ANONYMOUS pass, not to the authenticated one.
        # The guard is what the endpoint demanded of a caller with no credential.
        # `unauth_query_ok` is false by construction, because the anonymous pass
        # did not read. And `admin_api_exposed` means the delete API is routed AND
        # unauthenticated: a credentialed 405 or 400 only means this identity is
        # authorized, which is not the finding, so taking it from the retry would
        # make a properly guarded admin API a CRITICAL false positive on exactly
        # the backends escalation exists to reach.
        retry["auth_scheme"] = anonymous_scheme or retry.get("auth_scheme", "")
        retry["unauth_query_ok"] = False
        retry["admin_api_exposed"] = bool(result.get("admin_api_exposed"))
        retry["credential_source"] = source
        if source in NON_TENANT_CREDENTIAL_SOURCES:
            # Keep sweeping. A shell credential that answers is a reachable exposure
            # and says nothing about ordinary tenant access, so stopping here reported
            # the finding against a source the assessment then declines to treat as
            # tenant evidence, and left `kubernetes-secret` and the provisioned
            # Grafana credentials untried.
            #
            # `process-env` wins the hold, because it is the one attribution can name.
            # The trust order puts `env` first, so this only replaces a held `env`.
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
        # Both sources of the flag are merged. `truncated` covers a credential left
        # unevaluated, and `want_request` sets the same flag on this dict when THIS
        # pass was cut short inside its own sweep. A plain assignment discarded the
        # second one, so a held pass that read two of five labels reported complete
        # coverage.
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
    skipped = 0
    platforms: dict[str, int] = {}
    auth_schemes: dict[str, int] = {}
    credential_sources: dict[str, int] = {}
    # Credential sources whose OWN target returned another tenant's series, which
    # is a stronger claim than "this credential was accepted somewhere".
    cross_tenant_sources: dict[str, int] = {}
    candidates = list(targets)[:MAX_TARGETS]
    for index, base in enumerate(candidates, start=1):
        # Refill this target's share. The run total at index 2 is never refilled, so
        # it stays the ceiling on wasted time. Refilling is what stops one hanging
        # backend from spending the coverage of every target behind it.
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
        # The operator's own credential is excluded from attribution, because a
        # read it made says nothing about ordinary tenant access. Every other
        # source is recorded, INCLUDING `process-env`, which `security.py` then
        # reports in a sentence of its own rather than as tenant-held access. The
        # dict is the evidence the assessment splits three ways, so dropping a
        # source here would delete a finding instead of re-wording it. The
        # diagnostic twin reports one boolean with no source label beside it, so it
        # excludes `process-env` at this step instead.
        #
        # The sweep keeps going past both non-tenant reads, so a tenant-owned
        # source that also reads is the one recorded here.
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
        # Targets the request budget could not reach. A non-zero count means the
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
