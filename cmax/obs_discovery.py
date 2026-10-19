"""Discover the observability backends a tenant can reach, without configuration.

`cmax audit security` used to assess observability tenant isolation only when the
operator set `CLUSTERMAX_OBS_TARGETS` by hand, so the check reported
"not assessed" on clusters whose audit had just printed
"Grafana: detected (port 3000)". This module closes that gap: it finds candidate
metrics/dashboard backends from evidence that is already on the machine, and it
names the platform behind each one.

Three vantages, in descending order of confidence:

1. **Audit evidence** - the monitoring-stack block of `audit.values.json`
   (`healthChecks.monitoringStack`), which the Slurm and standalone collectors
   fill from listening sockets, systemd units, and process names.
2. **Node-local sockets and processes** - `ss -tln` (or `netstat -tln`) plus
   `ps -eo comm=` on this host. A backend that listens on this node is reachable
   from this node, which is exactly the tenant vantage the check cares about.
3. **Kubernetes Services** - `kubectl get svc -A`, matched by name against the
   known backend families and resolved to in-cluster DNS.

Only QUERY endpoints become targets. A per-node exporter (`node-exporter`,
`dcgm-exporter`) publishes its own host's metrics and answers no tenancy
question, so its port is recorded as platform evidence and never checked.

Discovery is read-only: it reads local files and runs read-only `ss` / `ps` /
`kubectl get` commands. It never opens a socket to a backend; the caller
(`cmax.obs_check`) owns every network request and its budget.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from typing import NamedTuple

# Default query/user-interface ports of multi-tenant metrics backends. A port
# here is worth checking because a query answered on it can carry another
# tenant's series.
QUERY_PORTS: dict[int, str] = {
    3000: "grafana",
    8428: "victoriametrics",
    8481: "vmselect",
    9009: "mimir",
    9090: "prometheus",
    10902: "thanos",
}

# Per-node exporter ports. These are platform evidence, never query targets:
# an exporter serves only its own host's metrics.
EXPORTER_PORTS: dict[int, str] = {
    9100: "node-exporter",
    9400: "dcgm-exporter",
}

# Process `comm` names that identify a backend. Matched exactly first, then by
# prefix plus a BUILD SUFFIX only, because the VictoriaMetrics binaries carry one
# (`victoria-metrics-prod`, `vmselect-prod`). A bare prefix match is wrong:
# `ps -eo comm=` truncates to 15 characters, so `prometheus-node-exporter`
# arrives as `prometheus-node` and would otherwise read as a Prometheus server
# and invent a query target on a node that only runs an exporter.
PROCESS_PLATFORMS: dict[str, str] = {
    "prometheus": "prometheus",
    "grafana": "grafana",
    "grafana-server": "grafana",
    "thanos": "thanos",
    "victoria-metrics": "victoriametrics",
    "vmselect": "vmselect",
    "mimir": "mimir",
    "cortex": "cortex",
}

# Kubernetes Service name substrings that identify a backend family. Kept in
# step with the diagnostic's `discover_targets.py`.
SERVICE_NAME_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("thanos", "thanos"),
    ("vmselect", "vmselect"),
    ("victoria", "victoriametrics"),
    ("mimir", "mimir"),
    ("cortex", "cortex"),
    ("prometheus", "prometheus"),
    ("grafana", "grafana"),
)

# Service name substrings that mean "not a query endpoint", checked BEFORE the
# include list. A Service named `kube-prom-prometheus-node-exporter` or
# `grafana-agent` contains an include token but serves no query API, so checking
# it spends the request budget and reports the wrong product. The socket and
# process vantages already exclude these; this keeps the Kubernetes vantage in
# step. `-operator` uses a leading hyphen so `prometheus-operated`, which IS the
# real Prometheus Service, still matches.
SERVICE_NAME_EXCLUDE: tuple[str, ...] = (
    "exporter",
    "-agent",
    "vmagent",
    "vminsert",
    "-adapter",
    "-operator",
    "alertmanager",
    "pushgateway",
    "promtail",
)

# Boolean keys of `healthChecks.monitoringStack` that name a query backend, and
# the platform each one implies.
AUDIT_STACK_PLATFORMS: dict[str, str] = {
    "prometheus": "prometheus",
    "grafana": "grafana",
}

PLATFORM_DEFAULT_PORTS: dict[str, int] = {
    platform: port for port, platform in sorted(QUERY_PORTS.items())
}
# Cortex serves the query API on the same port as its Grafana Mimir fork, so it
# has no distinct entry in QUERY_PORTS.
PLATFORM_DEFAULT_PORTS["cortex"] = 9009

MAX_TARGETS = 8

# An `addr:port` pair from `ss` / `netstat` output. The port group requires
# digits, so the `0.0.0.0:*` peer column of a LISTEN row never matches. Match
# complete whitespace-delimited endpoints and split at the last colon. This
# retains unbracketed netstat IPv6 hosts instead of matching an IPv6 suffix.
_ADDR_PORT = re.compile(
    r"(?<!\S)(\[[0-9A-Za-z:.%_-]+\]|[0-9A-Za-z._:%*-]+):([0-9]{1,5})(?=\s|$)"
)

_WILDCARD_HOSTS = frozenset({"*", "0.0.0.0", "::", "[::]", "[]", "0"})

# What may follow a backend binary's name in its `comm`: a build tag or a
# version. Anything else means a different program with a shared prefix.
_BUILD_SUFFIX = re.compile(r"^[-_.]?(?:prod|v?[0-9][0-9._-]*)$")

# The kernel caps /proc/<pid>/comm at 15 characters (TASK_COMM_LEN is 16 with the
# terminator), and `ps -eo comm=` reports that field. A longer binary name
# therefore arrives truncated: victoria-metrics-prod reads as victoria-metric,
# which neither the exact key nor the build-suffix rule can match.
COMM_MAX_LEN = 15


class Endpoint(NamedTuple):
    """One candidate backend: where it is, what it is, and how we found it."""

    url: str
    platform: str
    source: str


class Discovery(NamedTuple):
    """Everything discovery learned, whether or not it produced a target."""

    endpoints: tuple[Endpoint, ...]
    platforms: tuple[str, ...]
    sources: tuple[str, ...]

    def urls(self) -> list[str]:
        return [endpoint.url for endpoint in self.endpoints]

    def source_label(self) -> str:
        return "+".join(self.sources) if self.sources else "none"


def _normalize_host(host: str) -> str:
    """Turn a listen address into a host this node can actually connect to."""
    if host in _WILDCARD_HOSTS:
        return "127.0.0.1"
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        if not inner or inner == "::":
            return "127.0.0.1"
        return f"[{inner.replace('%', '%25')}]"
    if ":" in host:
        return f"[{host.replace('%', '%25')}]"
    return host


def _url_for(host: str, port: int, *, tls: bool = False) -> str:
    scheme = "https" if tls or port == 443 else "http"
    return f"{scheme}://{host}:{port}"


def parse_listening(text: str) -> list[tuple[str, int]]:
    """Extract `(host, port)` listen pairs from `ss -tln` or `netstat -tln` output.

    Tolerant by design: it also accepts a pre-extracted list of `addr:port`
    lines, which is the shape the audit collectors record.
    """
    pairs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for line in text.splitlines():
        if line.lower().lstrip().startswith(("state", "active", "proto")):
            continue
        for host, port_text in _ADDR_PORT.findall(line):
            try:
                port = int(port_text)
            except ValueError:  # pragma: no cover - regex guarantees digits
                continue
            key = (_normalize_host(host), port)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def endpoints_from_sockets(text: str, source: str = "sockets") -> list[Endpoint]:
    """Candidate query backends listening on this node."""
    endpoints: list[Endpoint] = []
    for host, port in parse_listening(text):
        platform = QUERY_PORTS.get(port)
        if platform is None:
            continue
        endpoints.append(Endpoint(_url_for(host, port), platform, source))
    return endpoints


def platforms_from_sockets(text: str) -> list[str]:
    """Every monitoring platform implied by a listening port, exporters included."""
    found: list[str] = []
    for _host, port in parse_listening(text):
        platform = QUERY_PORTS.get(port) or EXPORTER_PORTS.get(port)
        if platform and platform not in found:
            found.append(platform)
    return found


def platforms_from_processes(text: str) -> list[str]:
    """Platforms implied by running process names (`ps -eo comm=` output)."""
    found: list[str] = []
    for line in text.splitlines():
        comm = line.strip().rsplit("/", 1)[-1]
        if not comm:
            continue
        platform = PROCESS_PLATFORMS.get(comm)
        if platform is None:
            for name, candidate in PROCESS_PLATFORMS.items():
                if comm.startswith(name) and _BUILD_SUFFIX.match(comm[len(name) :]):
                    platform = candidate
                    break
        if platform is None and len(comm) == COMM_MAX_LEN:
            # A comm at exactly the cap may be a truncation. Only a key that is
            # itself at least that long can have been truncated, so a short key
            # such as `prometheus` cannot absorb `prometheus-node` here.
            for name, candidate in PROCESS_PLATFORMS.items():
                if len(name) >= COMM_MAX_LEN and name.startswith(comm):
                    platform = candidate
                    break
        if platform and platform not in found:
            found.append(platform)
    return found


def endpoints_from_processes(text: str, source: str = "processes") -> list[Endpoint]:
    """Localhost candidates for a detected backend process on its default port.

    A containerized or tarball install often has no systemd unit and may hide
    its socket from an unprivileged `ss`, so the process name is the only
    remaining signal. The default port is a guess; an unreachable guess costs
    one bounded request and is reported as unreachable.
    """
    endpoints: list[Endpoint] = []
    for platform in platforms_from_processes(text):
        port = PLATFORM_DEFAULT_PORTS.get(platform)
        if port is None:
            continue
        endpoints.append(Endpoint(_url_for("127.0.0.1", port), platform, source))
    return endpoints


def endpoints_from_audit(values: Mapping[str, object]) -> tuple[list[Endpoint], list[str]]:
    """Read the audit's monitoring-stack evidence into endpoints and platforms.

    Reads the `endpoints` list the collectors record (`host:port` strings) and
    falls back to the older booleans, which name a platform without a port.
    """
    stack = values
    for key in ("audit_data", "healthChecks", "monitoringStack"):
        if not isinstance(stack, Mapping):
            return ([], [])
        stack = stack.get(key)  # type: ignore[assignment]
    if not isinstance(stack, Mapping):
        return ([], [])

    endpoints: list[Endpoint] = []
    platforms: list[str] = []

    listed = stack.get("endpoints")
    if isinstance(listed, Sequence) and not isinstance(listed, (str, bytes)):
        joined = "\n".join(str(item) for item in listed)
        endpoints.extend(endpoints_from_sockets(joined, source="audit"))
        platforms.extend(platforms_from_sockets(joined))

    recorded = stack.get("platforms")
    if isinstance(recorded, Sequence) and not isinstance(recorded, (str, bytes)):
        for item in recorded:
            name = str(item)
            if name and name not in platforms:
                platforms.append(name)

    known = {endpoint.platform for endpoint in endpoints}
    for key, platform in AUDIT_STACK_PLATFORMS.items():
        if stack.get(key) is not True:
            continue
        if platform not in platforms:
            platforms.append(platform)
        port = PLATFORM_DEFAULT_PORTS.get(platform)
        if port is None or platform in known:
            continue
        endpoints.append(Endpoint(_url_for("127.0.0.1", port), platform, "audit"))
    return (endpoints, platforms)


def _service_platform(name: str) -> str | None:
    lowered = name.lower()
    if any(token in lowered for token in SERVICE_NAME_EXCLUDE):
        return None
    for token, platform in SERVICE_NAME_PLATFORMS:
        if token in lowered:
            return platform
    return None


def _preferred_port(ports: Iterable[Mapping[str, object]]) -> int | None:
    """Pick the query/user-interface port from a Service's port list."""
    named: dict[str, int] = {}
    numbered: list[int] = []
    for entry in ports:
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        named[str(entry.get("name") or "").lower()] = port
        numbered.append(port)
    for name in ("http", "web", "http-web", "query", "grafana", "https"):
        if name in named:
            return named[name]
    for well_known in sorted(QUERY_PORTS):
        if well_known in numbered:
            return well_known
    return numbered[0] if numbered else None


def parse_kubernetes_services(payload: Mapping[str, object]) -> list[Endpoint]:
    """Candidate backends from `kubectl get svc -A -o json` output."""
    items = payload.get("items")
    if not isinstance(items, Sequence):
        return []
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    for service in items:
        if not isinstance(service, Mapping):
            continue
        meta = service.get("metadata")
        spec = service.get("spec")
        if not isinstance(meta, Mapping) or not isinstance(spec, Mapping):
            continue
        name = str(meta.get("name") or "")
        namespace = str(meta.get("namespace") or "")
        if not name or not namespace:
            continue
        platform = _service_platform(name)
        if platform is None:
            continue
        ports = spec.get("ports")
        port = _preferred_port(ports if isinstance(ports, Sequence) else [])
        if port is None:
            continue
        tls = any(
            entry.get("port") == port and (
                str(entry.get("name", "")).lower().startswith("https")
                or str(entry.get("appProtocol", "")).lower() in {"https", "kubernetes.io/https"}
            )
            for entry in ports if isinstance(entry, Mapping)
        )
        url = _url_for(f"{name}.{namespace}.svc.cluster.local", port, tls=tls)
        if url in seen:
            continue
        seen.add(url)
        endpoints.append(Endpoint(url, platform, "k8s-services"))
    endpoints.sort(key=lambda endpoint: endpoint.url)
    return endpoints


def _run(command: Sequence[str]) -> str:
    """Run a read-only command, returning "" on any failure."""
    if not shutil.which(command[0]):
        return ""
    try:
        result = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def collect_local_sockets() -> str:
    text = _run(["ss", "-tln"])
    return text or _run(["netstat", "-tln"])


def collect_local_processes() -> str:
    return _run(["ps", "-eo", "comm="])


def collect_kubernetes_services() -> Mapping[str, object]:
    text = _run(["kubectl", "get", "svc", "-A", "-o", "json"])
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def discover(
    values: Mapping[str, object] | None = None,
    *,
    max_targets: int | None = MAX_TARGETS,
    sockets: str | None = None,
    processes: str | None = None,
    services: Mapping[str, object] | None = None,
) -> Discovery:
    """Find candidate backends from audit evidence, this node, and Kubernetes.

    Every input can be injected, so the whole decision path is testable without
    a cluster. Ordering is audit -> sockets -> processes -> Kubernetes Services,
    so the highest-confidence vantage fills the target budget first.
    Pass None to retain all candidates for coverage accounting by the caller.
    """
    endpoints: list[Endpoint] = []
    platforms: list[str] = []
    seen: set[str] = set()

    def extend(new: Iterable[Endpoint], source: str) -> None:
        for endpoint in new:
            if endpoint.url in seen:
                continue
            seen.add(endpoint.url)
            endpoints.append(endpoint)

    def note(new: Iterable[str]) -> None:
        for platform in new:
            if platform not in platforms:
                platforms.append(platform)

    audit_endpoints, audit_platforms = endpoints_from_audit(values or {})
    note(audit_platforms)
    extend(audit_endpoints, "audit")

    socket_text = collect_local_sockets() if sockets is None else sockets
    if socket_text:
        note(platforms_from_sockets(socket_text))
        extend(endpoints_from_sockets(socket_text), "sockets")

    process_text = collect_local_processes() if processes is None else processes
    if process_text:
        note(platforms_from_processes(process_text))
        extend(endpoints_from_processes(process_text), "processes")

    service_payload = collect_kubernetes_services() if services is None else services
    if service_payload:
        service_endpoints = parse_kubernetes_services(service_payload)
        note(endpoint.platform for endpoint in service_endpoints)
        extend(service_endpoints, "k8s-services")

    # Sources are derived AFTER the cap, from the endpoints that survive it. A
    # vantage whose endpoints all fall past the cap contributed nothing to the
    # check, so reporting "via audit+sockets" when only audit targets were checked
    # would misdescribe the result.
    kept = endpoints[:max_targets]
    sources: list[str] = []
    for endpoint in kept:
        if endpoint.source not in sources:
            sources.append(endpoint.source)
    return Discovery(
        endpoints=tuple(kept),
        platforms=tuple(platforms),
        sources=tuple(sources),
    )
