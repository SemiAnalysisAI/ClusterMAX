#!/usr/bin/env python3
"""Regenerate the ClusterMAX minimum version table from upstream feeds.

`cmax/scripts/1-audit/minimum-versions.json` holds every published
minimum version the audit grades against. This module rebuilds that file from
machine-readable upstream sources only:

  * NVIDIA CSAF bulletins (GPU driver, ConnectX / BlueField firmware, CUDA
    Toolkit, Container Toolkit) from the NVIDIA/product-security repository
  * OSV for the runc branch ladder
  * Canonical's Ubuntu Security Notices for complete Noble package floors,
    plus Ubuntu OSV records for named vulnerability-specific checks
  * The Docker Engine release notes that Docker authors as markdown in the
    docker/docs repository
  * The AMD security bulletins for the AMD Instinct ROCm minimum, read from the
    bulletin HTML pages on amd.com
  * The NVIDIA HPC SDK release index for the current and previous supported
    SDK releases

The same refresh records when each exact fix became available. It reads
official GitHub release records where a product publishes them, exact Ubuntu
Security Notices for distro packages, and the first NVIDIA CSAF revision that
confirms a fixed product when no exact release API exists.

Docker Engine publishes no advisory feed that maps onto Engine release
numbers, so the generator reads the official release-note markdown instead.
The Docker minimum is the highest stable release whose notes carry a Security
subsection, and a bug-fix release above it does not move the minimum.

AMD publishes no CSAF provider and no OSV entries for ROCm, so the AMD
Instinct ROCm minimum comes from the dated mitigation tables of the tracked AMD
graphics bulletins. Each Instinct program keeps the highest ROCm release any
tracked bulletin names for it.

The generator fails closed. When an extractor returns nothing for a component
that the existing table populates, the run stops with a non-zero exit and
writes no file. Upstream version phrasing is a text convention, so a reword
must produce a red job instead of a silently emptied minimum.

Command line::

    python3 -m cmax.minimum_refresh --print
    python3 -m cmax.minimum_refresh --write cmax/scripts/1-audit/minimum-versions.json
    python3 -m cmax.minimum_refresh --check cmax/scripts/1-audit/minimum-versions.json
    python3 -m cmax.minimum_refresh --detect-new-bulletins
    python3 -m cmax.minimum_refresh --print --generated 2026-07-30T00:00:00Z

Exit codes: 0 success, 1 `--check` mismatch, 2 fetch or fail-closed error,
3 unknown relevant NVIDIA bulletins or untracked Docker Engine majors found by
`--detect-new-bulletins`. A bulletin listed in DEFERRED_BULLETINS is reported
on every run but is a recorded decision rather than a discovery, so it does
not produce exit 3.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator, Sequence

from cmax import runtime_paths

SCHEMA_VERSION = 1
MAX_AGE_DAYS = 10
GRACE_PERIOD_DAYS = 3

USER_AGENT = "clustermax-minimum-refresh/1.0"
NVIDIA_RAW = "https://raw.githubusercontent.com/NVIDIA/product-security/main"
NVIDIA_BLOB = "https://github.com/NVIDIA/product-security/blob/main"
NVIDIA_ADVISORY = "https://nvidia.custhelp.com/app/answers/detail/a_id/{a_id}/"
GITHUB_CONTENTS = "https://api.github.com/repos/NVIDIA/product-security/contents/{year}"
NVIDIA_CSAF_TREE = (
    "https://api.github.com/repos/NVIDIA/product-security/git/trees/main?recursive=1"
)
# ClusterMAX's NVIDIA minimum-version policy began with the 2026 bulletin set.
# Keep that policy boundary explicit, but discover every bulletin at and after
# it instead of keeping a list of bulletin IDs.
NVIDIA_CSAF_START_YEAR = 2026
NVIDIA_NETWORK_SUPPORTED_PRODUCTS = ("BlueField-3", "ConnectX-7", "ConnectX-8")
GITHUB_RELEASE = "https://api.github.com/repos/{repo}/releases/tags/{tag}"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/"
# Canonical publishes its CVE tracker as OSV records. OSV.dev serves them, and
# the canonical/ubuntu-security-notices repository holds the same files. The
# Ubuntu security API above times out (HTTP 504) on CVEs with a long package
# list such as CVE-2024-3446, so it is only a last resort for fixes that OSV
# cannot describe yet (Ubuntu's "pending" state).
UBUNTU_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
UBUNTU_OSV_RAW_URL = (
    "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/cve/"
)
UBUNTU_OSV_ECOSYSTEMS = {"noble": "Ubuntu:24.04:LTS"}
UBUNTU_NOTICE_URL = "https://ubuntu.com/security/notices/"
UBUNTU_NOTICES_URL = "https://ubuntu.com/security/notices.json"
UBUNTU_NOTICE_PAGE_LIMIT = 20
UBUNTU_NOTICE_MAX_PAGES = 100
# The API has no source-package filter. `details` is only a bounded candidate
# search; every returned notice is then matched against its structured
# release_packages entries. These terms have been checked against Canonical's
# complete USN repository for Noble and cover every USN for the two graded
# source packages.
UBUNTU_PACKAGE_POLICY: tuple[tuple[str, str], ...] = (
    ("linux", "linux"),
    ("qemu", "qemu"),
)
DOCKER_RELEASE_NOTES_RAW = (
    "https://raw.githubusercontent.com/docker/docs/main"
    "/content/manuals/engine/release-notes/{major}.md"
)
DOCKER_RELEASE_NOTES_PAGE = "https://docs.docker.com/engine/release-notes/{major}/"
DOCKER_DOCS_CONTENTS = (
    "https://api.github.com/repos/docker/docs/contents"
    "/content/manuals/engine/release-notes"
)
NVHPC_RELEASES_PAGE = "https://developer.nvidia.com/hpc-sdk/releases"
NVHPC_RELEASE_RE = re.compile(r"\bHPC SDK\s+([0-9]{2}\.[0-9]{1,2})\b", re.IGNORECASE)

# Bulletins that match a graded product line and that we have decided not to
# track yet, each with the written reason. `--detect-new-bulletins` reports
# these as a separate group and does not treat them as a discovery, so the
# daily job stays green on a quiet day. Every entry is printed on every run:
# this list records a decision, and it must never become a quiet place to bury
# a bulletin nobody wants to deal with. Removing an entry puts the bulletin
# straight back on the untracked list.
DEFERRED_BULLETINS: dict[str, str] = {
    "5744": (
        "Networking SNAP4 publishes two fixed trains in one phrase, such as "
        "'SNAP-4.9.1, SNAP4 4.5.5'. The current single-version grammar keeps "
        "4.9.1 and drops the 4.5.5 LTS train, so tracking it needs parser work "
        "first."
    ),
}


def validate_bulletin_lists() -> None:
    """Fail on a contradiction between the tracked and deferred lists.

    A deferred bulletin without a written reason is an undocumented decision.
    Nvidia tracked coverage is derived from the CSAF catalog, not a second
    configuration list.
    """
    problems: list[str] = []
    for a_id, reason in DEFERRED_BULLETINS.items():
        if not str(reason).strip():
            problems.append(f"{a_id}: deferred bulletin has no written reason")
    if problems:
        raise MinimumRefreshError(
            "bulletin configuration is inconsistent:\n  - " + "\n  - ".join(problems)
        )


# Graded DCGM products, as component key and exact CSAF product label.
DCGM_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("dcgm", "DCGM"),
    ("dcgmExporter", "DCGM Exporter"),
)
NVIDIA_DCGM_PRODUCT_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "dcgm": re.compile(r"(?:^|_)dcgm_(?!exporter(?:_|$))", re.IGNORECASE),
    "dcgmExporter": re.compile(r"(?:^|_)dcgm_exporter(?:_|$)", re.IGNORECASE),
}

# Explicit policy labels for graded Nvidia products. Bulletin IDs and floors
# are deliberately absent: every matching CSAF document in the catalog enters
# the reducer automatically.
NVIDIA_SIMPLE_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("cudaToolkit", "NVIDIA CUDA Toolkit"),
    ("nvidiaContainerToolkit", "NVIDIA Container Toolkit"),
)
NVIDIA_VIRTIO_PRODUCT_PREFIX = "VIRTIO-Net"

# Product lines the audit grades. A new bulletin whose title matches one of
# these is reported by `--detect-new-bulletins`.
RELEVANT_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("GPU Display Driver", r"gpu\s+display\s+driver"),
    ("NVIDIA Container Toolkit", r"container\s+toolkit"),
    ("CUDA Toolkit", r"cuda\s+toolkit"),
    ("ConnectX / BlueField", r"connectx|bluefield|nvidia\s+networking"),
    ("DCGM", r"\bdcgm\b"),
)

RUNC_PACKAGE = "github.com/opencontainers/runc"
RUNC_ECOSYSTEM = "Go"
# OSV pages large result sets. Follow every page, and stop rather than build a
# ladder from a truncated advisory set.
OSV_MAX_PAGES = 20
RUNC_ADVISORY = (
    "https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2"
)

NVIDIA_DRIVER_RELEASE_REPO = "NVIDIA/open-gpu-kernel-modules"
NVIDIA_CONTAINER_TOOLKIT_RELEASE_REPO = "NVIDIA/nvidia-container-toolkit"
RUNC_RELEASE_REPO = "opencontainers/runc"
DCGM_EXPORTER_RELEASE_REPO = "NVIDIA/dcgm-exporter"

UBUNTU_RELEASE = "noble"
UBUNTU_PACKAGES: tuple[dict[str, Any], ...] = (
    {"key": "linuxBadEpoll", "cve": "CVE-2026-46242", "package": "linux"},
    {"key": "linuxBadEpollNvidia617", "cve": "CVE-2026-46242",
     "package": "linux-nvidia-6.17"},
    {"key": "qemu", "cve": "CVE-2024-3446", "package": "qemu"},
    {"key": "linuxVmscape", "cve": "CVE-2025-40300", "package": "linux"},
    {
        "key": "linuxFragnesia",
        "cve": "CVE-2026-46300",
        "package": "linux",
        "relatedCves": ["CVE-2026-43284", "CVE-2026-43500"],
        "abi": True,
    },
    {"key": "linuxJanuscape", "cve": "CVE-2026-53359", "package": "linux"},
)

# Docker Engine majors whose release-note pages feed the Docker minimum. Docker
# ships no CSAF feed that maps advisories onto Engine release numbers (the
# moby Go module uses 2.0.0-beta numbering), so the generator reads the
# release-note markdown that Docker authors in the docker/docs repository. A
# new major gets a new page there, so `--detect-new-bulletins` reports one and
# an operator extends this tuple.
DOCKER_ENGINE_MAJORS: tuple[int, ...] = (29,)

# One release on a Docker release-note page: a `## X.Y.Z` heading, a
# release-date shortcode below it, and a `### Security` subsection when the
# release ships a security fix.
DOCKER_RELEASE_HEADING = re.compile(
    r"^## +(\d+\.\d+\.\d+(?:-rc\.?\d+)?)\s*$", re.MULTILINE
)
DOCKER_RELEASE_DATE = re.compile(r'release-date\s+date="(\d{4}-\d{2}-\d{2})"')
DOCKER_SECURITY_HEADING = re.compile(r"^### +Security\s*$", re.MULTILINE)
DOCKER_NEXT_HEADING = re.compile(r"^#{2,3} ", re.MULTILINE)
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
GHSA_ID = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b")

# AMD publishes no CSAF provider and no OSV entries for ROCm. The generator
# therefore enumerates AMD's official bulletin index and evaluates every
# 6000-series bulletin published after the policy start date. Instinct rows,
# not bulletin titles or IDs, decide applicability.
AMD_FEED = "amd-security-bulletin"
AMD_SECURITY_INDEX = "https://www.amd.com/en/resources/product-security.html"
AMD_BULLETIN_PAGE = (
    "https://www.amd.com/en/resources/product-security/bulletin/{sb_id}.html"
)
AMD_POLICY_START_DATE = datetime(2025, 8, 1).date()
AMD_GPU_BULLETIN_ID = re.compile(r"^AMD-SB-6\d{3}$", re.IGNORECASE)

# An index row whose title matches this pattern concerns GPUs, so
# `--detect-new-bulletins` reports the bulletin when it is neither tracked nor
# deferred. The consolidated bulletins carry generic titles such as "AMD
# Graphics Vulnerabilities", so the pattern stays broad and each irrelevant
# match is deferred with a reason instead of narrowing the pattern.
AMD_GPU_TITLE = re.compile(r"graphics|instinct|rocm|gpu|radeon", re.IGNORECASE)
AMD_SB_ID = re.compile(r"\bAMD-SB-\d+\b", re.IGNORECASE)
# A mitigation cell that names one exact ROCm release: "ROCm 6.4.2", the typo
# form "ROC 6.3", and the wrapped form "BKC 26 (ROCm 7.0.1)". Trademark glyphs
# are stripped before the match, so "ROCm(TM) 6.4" also parses.
AMD_ROCM_MITIGATION = re.compile(r"^(?:BKC\s+\d+\s+\()?ROCm?\s+(\d+(?:\.\d+){1,2})\)?$")
# Any mention of ROCm in a mitigation cell. A cell that mentions ROCm and does
# not parse as one exact release stops the refresh instead of dropping a fix.
AMD_ROCM_HINT = re.compile(r"\bROCm?\b", re.IGNORECASE)
# A ROCm release outside the dated mitigation tables. Text such as "ROCm
# ecosystem" carries no digit and does not match.
AMD_ROCM_STRAY = re.compile(r"\bROCm?\W+\d", re.IGNORECASE)
AMD_DRIVER_HINT = re.compile(r"\bLinux GPU Driver\b", re.IGNORECASE)
AMD_DRIVER_STRAY = re.compile(r"\bLinux GPU Driver\W+\d", re.IGNORECASE)
# One Instinct program token, such as MI210 or MI300A. A single program cell
# can name two programs at once ("AMD Instinct MI210  AMD Instinct MI250").
AMD_PROGRAM = re.compile(r"\bMI\d+[A-Za-z]*\b")
AMD_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
AMD_TRADEMARKS = re.compile("[\u2122\u00ae]")

DEFAULT_RELATIVE_PATH = runtime_paths.MINIMUMS_TABLE_RELATIVE

VERSION = re.compile(r"\d+(?:\.\d+){1,3}(?:-rc\.?\d+)?")
# "All versions prior to X", "All driver versions up to and including Y", the
# bare-range form "0.0  to 4.5.2", and "1.7.21 and older versions" all describe
# affected versions. None of them may become a minimum on its own.
AFFECTED_PHRASE = re.compile(
    r"^(all\s+(driver\s+)?versions\s+(prior\s+to|up\s+to\s+and\s+including)\b"
    r"|[\d.]+\s+to\s+"
    r"|[\d.]+\s+and\s+older\b)",
    re.IGNORECASE,
)
# "1.7.21 and older versions" retires a whole earlier versioning scheme. The
# named version is the last vulnerable release of that scheme, so it is
# recorded as legacy evidence and never as a fixed release.
LEGACY_PHRASE = re.compile(r"^[\d.]+\s+and\s+older\b", re.IGNORECASE)
FIXED_PHRASE = re.compile(r"\bor\s+newer\b|\bor\s+later\b", re.IGNORECASE)
# Prerelease marker of a version string: the "-rc.3" of "1.5.0-rc.3", the
# "-rc95" of "1.0.0-rc95". Everything before it is the release.
PRERELEASE = re.compile(r"-(?:rc|alpha|beta)\.?(\d*)", re.IGNORECASE)
# Release-line suffix of a product label, such as GA or LTS25 in
# "VIRTIO-Net LTS25".
RELEASE_LINE = re.compile(r"[A-Z]{2,}\d*")


class MinimumRefreshError(RuntimeError):
    """A feed could not be read, or an extractor produced nothing usable."""


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urllib.parse.urlsplit(url)
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname, parsed.port or default_port


class SameOriginAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep authorization only when a redirect stays on the same origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and _origin(req.full_url) != _origin(newurl):
            redirected.remove_header("Authorization")
        return redirected


SAFE_OPENER = urllib.request.build_opener(SameOriginAuthRedirectHandler())


class Fetcher:
    """HTTP access for the generator. Tests substitute an offline stand-in."""

    timeout: int = 60

    @contextmanager
    def _open(self, request):
        """Log request progress without printing headers or credentials."""
        logger = logging.getLogger(__name__)
        started = time.monotonic()
        logger.info("fetch %s %s", request.get_method(), request.full_url)
        try:
            with SAFE_OPENER.open(request, timeout=self.timeout) as response:
                yield response
        finally:
            logger.info(
                "finished %s after %.1fs", request.full_url, time.monotonic() - started
            )

    def _headers(self, url: str, **extra: str) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, **extra}
        token = os.environ.get("GITHUB_TOKEN")
        if token and url.startswith("https://api.github.com/"):
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def get_json(self, url: str) -> Any:
        request = urllib.request.Request(url, headers=self._headers(url))
        try:
            with self._open(request) as response:
                return json.load(response)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MinimumRefreshError(f"cannot read {url}: {exc}") from exc

    def get_optional_json(self, url: str) -> Any | None:
        """Return JSON, or None only when an exact upstream object is absent.

        A missing release means its availability is not confirmed yet. Other
        HTTP, network, and JSON failures must stop the refresh, because treating
        an unavailable feed as an unavailable fix would grant an indefinite
        audit pass.
        """
        request = urllib.request.Request(url, headers=self._headers(url))
        try:
            with self._open(request) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise MinimumRefreshError(f"cannot read {url}: {exc}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MinimumRefreshError(f"cannot read {url}: {exc}") from exc

    def post_json(self, url: str, body: dict) -> Any:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers=self._headers(url, **{"Content-Type": "application/json"}),
        )
        try:
            with self._open(request) as response:
                return json.load(response)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MinimumRefreshError(f"cannot query {url}: {exc}") from exc

    def get_text_head(self, url: str, max_bytes: int = 1200) -> str | None:
        """Return the first bytes of a text file, or None when it is unreadable.

        A missing file or any non-success status returns None so the bulletin
        scan keeps going instead of failing the whole run.
        """
        request = urllib.request.Request(
            url,
            headers=self._headers(url, Range=f"bytes=0-{max_bytes - 1}"),
        )
        try:
            with self._open(request) as response:
                if response.status not in (200, 206):
                    return None
                return response.read(max_bytes).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError):
            return None

    def get_text(self, url: str) -> str:
        """Return the whole text of a page, or stop the refresh.

        The Docker minimum extractor reads a full release-note page, so a page
        that cannot be read must fail the run instead of publishing an
        emptied minimum.
        """
        request = urllib.request.Request(url, headers=self._headers(url))
        try:
            with self._open(request) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as exc:
            raise MinimumRefreshError(f"cannot read {url}: {exc}") from exc


_DEFAULT_FETCHER = Fetcher()


def _fetcher(fetch: Fetcher | None) -> Fetcher:
    return fetch if fetch is not None else _DEFAULT_FETCHER


def bulletin_url(year: int, a_id: int) -> str:
    return f"{NVIDIA_RAW}/{year}/{a_id}/{a_id}.json"


def bulletin_blob_url(year: int, a_id: int) -> str:
    return f"{NVIDIA_BLOB}/{year}/{a_id}/{a_id}.json"


def github_release_url(repo: str, tag: str) -> str:
    encoded = urllib.parse.quote(tag, safe="")
    return GITHUB_RELEASE.format(repo=repo, tag=encoded)


def github_release_availability(
    repo: str, tag: str, version: str, fetch: Fetcher | None = None
) -> dict[str, Any]:
    """Return availability evidence for one exact official GitHub release."""
    api_url = github_release_url(repo, tag)
    release = _fetcher(fetch).get_optional_json(api_url)
    encoded_tag = urllib.parse.quote(tag, safe="")
    release_url = f"https://github.com/{repo}/releases/tag/{encoded_tag}"
    if not isinstance(release, dict):
        return {
            "status": "unconfirmed",
            "feed": "github-release",
            "repo": repo,
            "tag": tag,
            "version": version,
            "url": release_url,
        }
    available = release.get("published_at")
    if not isinstance(available, str) or not available.strip():
        return {
            "status": "unconfirmed",
            "feed": "github-release",
            "repo": repo,
            "tag": tag,
            "version": version,
            "url": release.get("html_url") or release_url,
        }
    return {
        "status": "confirmed",
        "available": available,
        "feed": "github-release",
        "repo": repo,
        "tag": tag,
        "version": version,
        "url": release.get("html_url") or release_url,
    }


def nvidia_csaf_fix_availability(a_id: int, year: int, doc: dict) -> dict[str, Any]:
    """Record when NVIDIA's CSAF revision confirms the exact fixed product.

    Some NVIDIA products have no exact public release API. The revision date of
    the CSAF document that lists the fixed product is conservative evidence that
    the fix is available. A later refresh preserves the first confirmed date
    while that exact minimum stays unchanged.
    """
    tracking = doc.get("document", {}).get("tracking", {})
    available = tracking.get("current_release_date")
    bulletin_released = tracking.get("initial_release_date") or available
    result: dict[str, Any] = {
        "status": "confirmed" if available else "unconfirmed",
        "feed": "nvidia-csaf-fixed-product",
        "aId": a_id,
        "url": bulletin_blob_url(year, a_id),
    }
    if available:
        result["available"] = available
    if bulletin_released:
        result["bulletinReleased"] = bulletin_released
    return result


# ---------------------------------------------------------------------------
# CSAF product-tree walking
# ---------------------------------------------------------------------------


def csaf_arch_branches(doc: dict) -> Iterator[tuple[str, list[dict]]]:
    """Yield (architecture name, product_version children) for every arch branch."""

    def walk(node: dict) -> Iterator[tuple[str, list[dict]]]:
        for child in node.get("branches") or []:
            if child.get("category") == "architecture":
                kids = [
                    kid
                    for kid in (child.get("branches") or [])
                    if kid.get("category") == "product_version"
                ]
                if kids:
                    yield child.get("name", ""), kids
            yield from walk(child)

    for top in doc.get("product_tree", {}).get("branches") or []:
        yield from walk(top)


def csaf_product_labels(doc: dict) -> set[str]:
    """Return exact product labels declared anywhere in a CSAF product tree."""

    labels: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            name = value.get("name")
            if isinstance(name, str) and name.strip():
                labels.add(name.strip())
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(doc.get("product_tree") or {})
    return labels


def csaf_has_product(doc: dict, label: str) -> bool:
    wanted = label.casefold()
    return any(item.casefold() == wanted for item in csaf_product_labels(doc))


def csaf_has_product_prefix(doc: dict, prefix: str) -> bool:
    wanted = prefix.casefold()
    return any(item.casefold().startswith(wanted) for item in csaf_product_labels(doc))


def csaf_product_status_ids(doc: dict) -> set[str]:
    ids: set[str] = set()
    for vulnerability in doc.get("vulnerabilities") or []:
        for values in (vulnerability.get("product_status") or {}).values():
            if isinstance(values, list):
                ids.update(str(value) for value in values)
    return ids


def nvidia_csaf_documents(
    fetch: Fetcher | None = None,
    *,
    years: Sequence[int] | None = None,
) -> list[tuple[dict[str, int], dict]]:
    """Enumerate and fetch every NVIDIA bulletin CSAF document in policy scope.

    The Git tree is one atomic repository snapshot. A truncated tree, malformed
    path, missing document, or tracking-id mismatch blocks the refresh; otherwise
    a source outage could silently remove a security floor.
    """
    client = _fetcher(fetch)
    tree = client.get_json(NVIDIA_CSAF_TREE)
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise MinimumRefreshError(
            f"NVIDIA CSAF tree has an unexpected shape: {NVIDIA_CSAF_TREE}"
        )
    if tree.get("truncated"):
        raise MinimumRefreshError(
            f"NVIDIA CSAF tree is truncated: {NVIDIA_CSAF_TREE}"
        )
    selected_years = (
        {int(year) for year in years}
        if years is not None
        else set(range(NVIDIA_CSAF_START_YEAR, datetime.now(timezone.utc).year + 1))
    )
    refs: list[dict[str, int]] = []
    pattern = re.compile(r"^(\d{4})/(\d+)/(\d+)\.json$")
    for entry in tree["tree"]:
        if entry.get("type") != "blob":
            continue
        match = pattern.fullmatch(str(entry.get("path", "")))
        if not match or match.group(2) != match.group(3):
            continue
        year, a_id = int(match.group(1)), int(match.group(2))
        if year in selected_years:
            refs.append({"year": year, "aId": a_id})
    refs.sort(key=lambda ref: (ref["year"], ref["aId"]))
    if not refs:
        years_text = ", ".join(str(year) for year in sorted(selected_years))
        raise MinimumRefreshError(
            f"NVIDIA CSAF tree contains no bulletin documents for {years_text}"
        )

    def read(ref: dict[str, int]) -> tuple[dict[str, int], dict]:
        doc = client.get_json(bulletin_url(ref["year"], ref["aId"]))
        tracking_id = str(doc.get("document", {}).get("tracking", {}).get("id", ""))
        if tracking_id != str(ref["aId"]):
            raise MinimumRefreshError(
                f"NVIDIA CSAF {bulletin_url(ref['year'], ref['aId'])} "
                f"declares tracking id {tracking_id!r}"
            )
        return ref, doc

    with ThreadPoolExecutor(max_workers=min(8, len(refs))) as pool:
        return list(pool.map(read, refs))


def version_key(version: str) -> tuple:
    """Order versions numerically and rank a release above its own prerelease.

    Returns (release numbers, stable flag, prerelease number). The release part
    stops at the prerelease marker, so 1.5.0 and 1.5.0-rc.3 share a release
    tuple and the stable flag decides between them. Ordering the prerelease
    digits inside the release tuple instead would rank 1.5.0-rc.3 as
    ((1,5,0,3),) above 1.5.0 as ((1,5,0),), which let the runc ladder keep a
    release candidate as the published minimum and grade a vulnerable host as a
    pass.

    Examples::

        version_key("1.5.0")      > version_key("1.5.0-rc.3")
        version_key("1.5.0-rc.3") > version_key("1.5.0-rc.2")
        version_key("1.4.3")      > version_key("1.4.0-rc.3")

    Any other string is read as its digits in order, so Debian-style values
    such as "6.8.0-124.124" and "1:8.2.2+ds-0ubuntu1.10" still compare without
    raising.
    """
    text = str(version)
    marker = PRERELEASE.search(text)
    release_text = text[: marker.start()] if marker else text
    release = tuple(int(part) for part in re.findall(r"\d+", release_text))
    if marker is None:
        return (release, 1, 0)
    return (release, 0, int(marker.group(1) or 0))


def classify_phrase(phrase: str | None) -> tuple[str | None, str | None]:
    """Classify one upstream version phrase and return (role, version).

    Roles:
      ``fixed``   the named version is patched ("X or newer", a bare "X")
      ``priorTo`` everything below the named version is affected
      ``legacy``  a retired versioning scheme, "1.7.21 and older versions"
      ``affected`` any other affected wording, such as
                  "All versions up to and including Y" or "0.0  to 4.5.2"
      ``None``    no version, or wording this parser does not recognize

    The version always comes from the version regex, never from the raw
    string, so decoration such as the trailing comma in "24.10.50 or newer,"
    stays out of the result.
    """
    text = (phrase or "").strip()
    match = VERSION.search(text)
    if not match:
        return None, None
    version = match.group(0)
    if LEGACY_PHRASE.match(text):
        return "legacy", version
    if AFFECTED_PHRASE.match(text):
        if re.search(r"prior\s+to", text, re.IGNORECASE):
            return "priorTo", version
        return "affected", version
    if FIXED_PHRASE.search(text) or text == version or text.endswith(version):
        return "fixed", version
    return None, version


def resolve_fixed(kids: list[dict], product_filter: str | None = None) -> str | None:
    """Pick the fixed version out of a set of product_version siblings.

    The CSAF field roles here are the reverse of the intuitive reading: the
    branch ``name`` is the product label ("Tesla", "NVIDIA Container Toolkit")
    and ``product.name`` carries the version phrase ("All versions prior to X").
    Reading them the other way round yields nothing at all.

    Preference order:
      1. a sibling whose version phrase carries no "all versions ..." wording
      2. the version named inside "All versions prior to X"
    "All versions up to and including Y" never yields a minimum on its own,
    because Y itself is vulnerable, and neither does "X and older versions".
    """
    if product_filter:
        kids = [kid for kid in kids if kid.get("name") == product_filter]
    fixed_candidates: list[str] = []
    prior_to: list[str] = []
    for kid in kids:
        role, version = classify_phrase(kid.get("product", {}).get("name"))
        if role == "fixed":
            fixed_candidates.append(version)
        elif role == "priorTo":
            prior_to.append(version)
    pool = fixed_candidates or prior_to
    if not pool:
        return None
    return max(pool, key=version_key)


def release_line_name(label: str | None) -> str | None:
    """Return the release line of a product label: "VIRTIO-Net LTS25" -> "LTS25".

    Line names come from the bulletin, so a new line appears without a code
    change. A label with no release-line suffix yields None and contributes no
    line, which the fail-closed check then reports.
    """
    parts = (label or "").split()
    if not parts:
        return None
    candidate = parts[-1]
    return candidate if RELEASE_LINE.fullmatch(candidate) else None


# ---------------------------------------------------------------------------
# Per-component extractors
# ---------------------------------------------------------------------------


def nvidia_source(a_id: int, year: int, doc: dict) -> dict:
    tracking = doc["document"]["tracking"]
    return {
        "feed": "nvidia-csaf",
        "aId": a_id,
        "title": doc["document"]["title"],
        "released": tracking.get("initial_release_date")
        or tracking["current_release_date"],
        "url": bulletin_blob_url(year, a_id),
    }


def driver_branches_in(doc: dict) -> dict[str, str]:
    """Return the data-center Linux driver branches one bulletin publishes.

    Linux Tesla branches only: no vGPU guest driver, no Virtual GPU Manager,
    no cloud gaming, no Windows.
    """
    branches: dict[str, str] = {}
    for arch, kids in csaf_arch_branches(doc):
        match = re.fullmatch(r"Linux\(R(\d+)\)", arch.strip())
        if not match:
            continue
        fixed = resolve_fixed(kids, product_filter="Tesla")
        if fixed:
            branches[match.group(1)] = fixed
    return branches


def nvidia_driver_minimums(
    refs: Sequence[dict[str, Any]] | None = None,
    fetch: Fetcher | None = None,
    *,
    documents: Sequence[tuple[dict[str, int], dict]] | None = None,
) -> dict:
    """Merge every applicable driver bulletin into one minimum per branch.

    A branch keeps the highest fixed version any applicable bulletin publishes for
    it, compared numerically. NVIDIA issues one bulletin per cycle and each one
    covers only the branches it patched, so no single bulletin lists every
    supported branch: 5821 covers R535 / R580 / R595 while R570 and R590 appear
    only in the earlier 5747. Taking the maximum keeps a branch that an older
    bulletin contributes without letting that bulletin lower a branch a newer
    one raised. The result does not depend on the order of `refs`.
    """
    if refs is not None and documents is not None:
        raise ValueError("pass refs or documents, not both")
    if documents is None:
        if refs is None:
            documents = nvidia_csaf_documents(fetch=fetch)
        else:
            documents = [
                (ref, _fetcher(fetch).get_json(bulletin_url(ref["year"], ref["aId"])))
                for ref in refs
            ]
    branches: dict[str, str] = {}
    branch_sources: dict[str, int] = {}
    sources: list[dict] = []
    for ref, doc in documents:
        year, a_id = ref["year"], ref["aId"]
        extracted = driver_branches_in(doc)
        if not extracted:
            continue
        sources.append(nvidia_source(a_id, year, doc))
        for branch, fixed in extracted.items():
            current = branches.get(branch)
            if current is None or version_key(fixed) > version_key(current):
                branches[branch] = fixed
                branch_sources[branch] = a_id
    # `source` stays the newest bulletin so the block keeps the single-source
    # shape every other component uses; `sources` and `branchSources` carry the
    # merge detail.
    sources.sort(key=lambda item: (str(item["released"])[:10], item["aId"]))
    newest = sources[-1] if sources else {}
    sources_by_id = {str(item["aId"]): item for item in sources}
    by_branch = sorted(branches.items(), key=lambda kv: int(kv[0]))
    minimum_availability: dict[str, dict[str, Any]] = {}
    for branch, fixed in by_branch:
        availability = github_release_availability(
            NVIDIA_DRIVER_RELEASE_REPO, fixed, fixed, fetch=fetch
        )
        source = sources_by_id.get(str(branch_sources[branch]))
        if source and source.get("released"):
            availability["bulletinReleased"] = source["released"]
        minimum_availability[branch] = availability
    return {
        "kind": "branchMap",
        "branches": dict(by_branch),
        "branchSources": {branch: branch_sources[branch] for branch, _ in by_branch},
        "floorAvailability": minimum_availability,
        "advisory": NVIDIA_ADVISORY.format(a_id=newest.get("aId", "")),
        "source": newest,
        "sources": sorted(sources, key=lambda item: item["aId"]),
    }


def connectx_document_applies(doc: dict) -> bool:
    """Whether a networking bulletin covers ClusterMAX's supported hardware."""
    for arch, kids in csaf_arch_branches(doc):
        if not any(
            product.lower() in arch.lower()
            for product in NVIDIA_NETWORK_SUPPORTED_PRODUCTS
        ):
            continue
        if any(
            re.match(r"^(?:connectx|bluefield)(?:\s|$)", str(kid.get("name", "")), re.I)
            for kid in kids
        ):
            return True
    return False


def connectx_trains_in(doc: dict) -> dict[str, int]:
    """Return firmware train -> fixed patch for ConnectX / BlueField products."""
    if not connectx_document_applies(doc):
        return {}

    trains: dict[str, int] = {}
    network = re.compile(r"connectx|bluefield", re.IGNORECASE)
    for arch, kids in csaf_arch_branches(doc):
        product_text = " ".join(
            [
                arch,
                *[str(kid.get("name", "")) for kid in kids],
                *[
                    str(kid.get("product", {}).get("product_id", ""))
                    for kid in kids
                ],
            ]
        )
        if not network.search(product_text):
            continue
        for label in {str(kid.get("name", "")) for kid in kids}:
            fixed = resolve_fixed(kids, product_filter=label)
            parts = [int(part) for part in re.findall(r"\d+", fixed or "")]
            if len(parts) < 2:
                continue
            # Full NIC firmware is hardware-family.train.patch (16.35.8008);
            # some CSAF products omit the hardware family (47.1020).
            train, patch = str(parts[-2]), parts[-1]
            trains[train] = max(patch, trains.get(train, 0))
    return trains


def connectx_minimums(
    year: int | None = None,
    a_id: int | None = None,
    fetch: Fetcher | None = None,
    *,
    documents: Sequence[tuple[dict[str, int], dict]] | None = None,
) -> dict:
    """Merge every applicable CSAF bulletin into firmware train minimums."""
    if documents is not None and (year is not None or a_id is not None):
        raise ValueError("pass year/a_id or documents, not both")
    if documents is None:
        if year is not None or a_id is not None:
            if year is None or a_id is None:
                raise ValueError("year and a_id must be passed together")
            ref = {"year": year, "aId": a_id}
            documents = [(ref, _fetcher(fetch).get_json(bulletin_url(year, a_id)))]
        else:
            documents = nvidia_csaf_documents(fetch=fetch)
    trains: dict[str, int] = {}
    train_availability: dict[str, dict[str, Any]] = {}
    sources: list[dict] = []
    for ref, doc in documents:
        extracted = connectx_trains_in(doc)
        if not extracted:
            continue
        year, a_id = ref["year"], ref["aId"]
        source = nvidia_source(a_id, year, doc)
        sources.append(source)
        availability = nvidia_csaf_fix_availability(a_id, year, doc)
        for train, patch in extracted.items():
            if patch <= trains.get(train, -1):
                continue
            trains[train] = patch
            train_availability[train] = {
                **availability,
                "version": f"{train}.{patch}",
            }
    sources.sort(key=lambda item: (str(item["released"])[:10], item["aId"]))
    newest = sources[-1] if sources else {}
    return {
        "kind": "trainMap",
        "trains": dict(sorted(trains.items(), key=lambda kv: int(kv[0]))),
        "floorAvailability": dict(
            sorted(train_availability.items(), key=lambda kv: int(kv[0]))
        ),
        "advisory": NVIDIA_ADVISORY.format(a_id=newest.get("aId", "")),
        "source": newest,
        "sources": sorted(sources, key=lambda item: item["aId"]),
    }


def _virtio_net_minimums_from_document(year: int, a_id: int, doc: dict) -> dict:
    """VIRTIO-Net for BlueField release lines: GA and the LTS lines.

    This is a separate product from the ConnectX / BlueField firmware trains
    and carries its own versioning, so it is its own component. CVE-2026-65094
    is a tenant-to-host escape class defect: a VM user can reach a
    Write-What-Where condition in Virtio-Net on a BlueField-3 DPU.
    """
    fixed: dict[str, list[str]] = {}
    prior_to: dict[str, list[str]] = {}
    legacy: dict[str, list[str]] = {}
    for _arch, kids in csaf_arch_branches(doc):
        for kid in kids:
            line = release_line_name(kid.get("name"))
            if not line:
                continue
            role, version = classify_phrase(kid.get("product", {}).get("name"))
            if role == "fixed":
                fixed.setdefault(line, []).append(version)
            elif role == "priorTo":
                prior_to.setdefault(line, []).append(version)
            elif role == "legacy":
                legacy.setdefault(line, []).append(version)
    lines: dict[str, dict[str, str]] = {}
    for line in sorted(set(fixed) | set(prior_to)):
        pool = fixed.get(line) or prior_to.get(line) or []
        if not pool:
            continue
        entry = {"fixed": max(pool, key=version_key)}
        if legacy.get(line):
            entry["legacyAffectedThrough"] = max(legacy[line], key=version_key)
        lines[line] = entry
    availability = nvidia_csaf_fix_availability(a_id, year, doc)
    return {
        "kind": "releaseLines",
        "lines": lines,
        "floorAvailability": {
            line: {**availability, "version": entry["fixed"]}
            for line, entry in lines.items()
        },
        "cves": [item["cve"] for item in doc.get("vulnerabilities", []) if item.get("cve")],
        "advisory": NVIDIA_ADVISORY.format(a_id=a_id),
        "source": nvidia_source(a_id, year, doc),
    }


def virtio_net_minimums(year: int, a_id: int, fetch: Fetcher | None = None) -> dict:
    """Extract one VIRTIO-Net bulletin; production merges the CSAF catalog."""

    doc = _fetcher(fetch).get_json(bulletin_url(year, a_id))
    return _virtio_net_minimums_from_document(year, a_id, doc)


def nvidia_virtio_net_minimums(
    documents: Sequence[tuple[dict[str, int], dict]],
) -> dict:
    """Merge every catalog document that explicitly declares VIRTIO-Net."""

    lines: dict[str, dict[str, str]] = {}
    availability: dict[str, dict[str, Any]] = {}
    cves: set[str] = set()
    sources: list[dict] = []
    for ref, doc in documents:
        if not csaf_has_product_prefix(doc, NVIDIA_VIRTIO_PRODUCT_PREFIX):
            continue
        block = _virtio_net_minimums_from_document(ref["year"], ref["aId"], doc)
        if not block["lines"]:
            raise MinimumRefreshError(
                f"virtioNetBluefield: NVIDIA CSAF {ref['aId']} declares "
                f"{NVIDIA_VIRTIO_PRODUCT_PREFIX} but yields no fixed release lines"
            )
        sources.append(block["source"])
        cves.update(block["cves"])
        for line, entry in block["lines"].items():
            current = lines.get(line)
            if current is not None and version_key(entry["fixed"]) <= version_key(
                current["fixed"]
            ):
                continue
            lines[line] = entry
            availability[line] = block["floorAvailability"][line]
    sources.sort(key=lambda item: (str(item["released"])[:10], item["aId"]))
    newest = sources[-1] if sources else {}
    result = {
        "kind": "releaseLines",
        "lines": dict(sorted(lines.items())),
        "floorAvailability": dict(sorted(availability.items())),
        "cves": sorted(cves),
        "advisory": NVIDIA_ADVISORY.format(a_id=newest.get("aId", "")),
        "source": newest,
    }
    if len(sources) > 1:
        result["sources"] = sorted(sources, key=lambda item: item["aId"])
    return result


def _simple_product_minimum_from_document(
    year: int,
    a_id: int,
    doc: dict,
    *,
    product: str,
    fetch: Fetcher | None = None,
) -> dict:
    best: str | None = None
    for arch, kids in csaf_arch_branches(doc):
        if "linux" not in arch.lower():
            continue
        fixed = resolve_fixed(kids, product_filter=product)
        if fixed and (best is None or version_key(fixed) > version_key(best)):
            best = fixed
    source = nvidia_source(a_id, year, doc)
    if best and product == "NVIDIA Container Toolkit":
        availability = github_release_availability(
            NVIDIA_CONTAINER_TOOLKIT_RELEASE_REPO, f"v{best}", best, fetch=fetch
        )
        availability["bulletinReleased"] = source["released"]
    else:
        availability = nvidia_csaf_fix_availability(a_id, year, doc)
        if best:
            availability["version"] = best
    return {
        "kind": "minimum",
        "minimum": best,
        "fixAvailability": availability,
        "cves": [item["cve"] for item in doc.get("vulnerabilities", []) if item.get("cve")],
        "advisory": NVIDIA_ADVISORY.format(a_id=a_id),
        "source": source,
    }


def simple_product_minimum(
    year: int, a_id: int, product: str | None = None, fetch: Fetcher | None = None
) -> dict:
    """Extract one Linux product bulletin; production merges the CSAF catalog."""

    doc = _fetcher(fetch).get_json(bulletin_url(year, a_id))
    return _simple_product_minimum_from_document(
        year, a_id, doc, product=product or "", fetch=fetch
    )


def nvidia_simple_product_minimums(
    documents: Sequence[tuple[dict[str, int], dict]],
    fetch: Fetcher | None = None,
) -> dict[str, dict]:
    """Reduce all catalog bulletins for CUDA and Container Toolkit."""

    results: dict[str, dict] = {}
    for key, label in NVIDIA_SIMPLE_PRODUCTS:
        candidates: list[dict] = []
        cves: set[str] = set()
        sources: list[dict] = []
        for ref, doc in documents:
            if not csaf_has_product(doc, label):
                continue
            block = _simple_product_minimum_from_document(
                ref["year"], ref["aId"], doc, product=label, fetch=fetch
            )
            if not block["minimum"]:
                raise MinimumRefreshError(
                    f"{key}: NVIDIA CSAF {ref['aId']} declares {label} "
                    "but yields no Linux minimum"
                )
            candidates.append(block)
            cves.update(block["cves"])
            sources.append(block["source"])
        if not candidates:
            continue
        winner = max(candidates, key=lambda block: version_key(block["minimum"]))
        result = {**winner, "cves": sorted(cves)}
        if len(sources) > 1:
            result["sources"] = sorted(sources, key=lambda item: item["aId"])
        results[key] = result
    return results


def _bulletin_product_minimums_from_document(
    year: int,
    a_id: int,
    doc: dict,
    products: Sequence[tuple[str, str]],
    fetch: Fetcher | None = None,
) -> dict[str, dict]:
    """One bulletin, one `minimum` component per product it covers.

    Every product is resolved from the same fetched document and every one
    gets a block, so a product that stops resolving yields an empty minimum
    that the fail-closed check reports, instead of disappearing.

    Architecture branch names are not filtered here. DCGM bulletins use
    product-wide architecture labels such as "All(4.5)" and "All(4.8)".
    """
    cves = [item["cve"] for item in doc.get("vulnerabilities", []) if item.get("cve")]
    source = nvidia_source(a_id, year, doc)
    blocks: dict[str, dict] = {}
    for key, label in products:
        best: str | None = None
        for _arch, kids in csaf_arch_branches(doc):
            fixed = resolve_fixed(kids, product_filter=label)
            if fixed and (best is None or version_key(fixed) > version_key(best)):
                best = fixed
        blocks[key] = {
            "kind": "minimum",
            "minimum": best,
            "cves": list(cves),
            "advisory": NVIDIA_ADVISORY.format(a_id=a_id),
            "source": source,
        }
    dcgm_version = blocks.get("dcgm", {}).get("minimum")
    exporter_version = blocks.get("dcgmExporter", {}).get("minimum")
    if dcgm_version and exporter_version:
        tag = f"{dcgm_version}-{exporter_version}"
        for block in blocks.values():
            block["fixAvailability"] = github_release_availability(
                DCGM_EXPORTER_RELEASE_REPO,
                tag,
                str(block.get("minimum")),
                fetch=fetch,
            )
            block["fixAvailability"]["bulletinReleased"] = source["released"]
    for block in blocks.values():
        if "fixAvailability" not in block:
            availability = nvidia_csaf_fix_availability(a_id, year, doc)
            if block.get("minimum"):
                availability["version"] = block["minimum"]
            block["fixAvailability"] = availability
    return blocks


def bulletin_product_minimums(
    year: int,
    a_id: int,
    products: Sequence[tuple[str, str]],
    fetch: Fetcher | None = None,
) -> dict[str, dict]:
    """Extract one multi-product bulletin; production merges the CSAF catalog."""

    doc = _fetcher(fetch).get_json(bulletin_url(year, a_id))
    return _bulletin_product_minimums_from_document(
        year, a_id, doc, products, fetch=fetch
    )


def nvidia_dcgm_minimums(
    documents: Sequence[tuple[dict[str, int], dict]],
    fetch: Fetcher | None = None,
) -> dict[str, dict]:
    """Reduce every CSAF document that explicitly declares DCGM products."""

    candidates: dict[str, list[dict]] = {key: [] for key, _label in DCGM_PRODUCTS}
    cves: dict[str, set[str]] = {key: set() for key, _label in DCGM_PRODUCTS}
    sources: dict[str, list[dict]] = {key: [] for key, _label in DCGM_PRODUCTS}
    for ref, doc in documents:
        status_ids = csaf_product_status_ids(doc)
        applicable = [
            (key, label)
            for key, label in DCGM_PRODUCTS
            if csaf_has_product(doc, label)
            or any(NVIDIA_DCGM_PRODUCT_ID_PATTERNS[key].search(item) for item in status_ids)
        ]
        if not applicable:
            continue
        blocks = _bulletin_product_minimums_from_document(
            ref["year"], ref["aId"], doc, applicable, fetch=fetch
        )
        missing = [key for key, _label in applicable if not blocks[key]["minimum"]]
        if missing:
            raise MinimumRefreshError(
                f"NVIDIA CSAF {ref['aId']} yields no minimum for: "
                + ", ".join(missing)
            )
        for key, _label in applicable:
            block = blocks[key]
            candidates[key].append(block)
            cves[key].update(block["cves"])
            sources[key].append(block["source"])
    results: dict[str, dict] = {}
    for key, _label in DCGM_PRODUCTS:
        if not candidates[key]:
            continue
        winner = max(candidates[key], key=lambda block: version_key(block["minimum"]))
        result = {**winner, "cves": sorted(cves[key])}
        if len(sources[key]) > 1:
            result["sources"] = sorted(sources[key], key=lambda item: item["aId"])
        results[key] = result
    return results


def osv_package_vulns(
    package: str, ecosystem: str, fetch: Fetcher | None = None
) -> list[dict]:
    """Return every OSV advisory for a package, across every page.

    The query carries no version. A version-scoped query returns only the
    advisories that affect that one release, so an advisory published later
    against a newer branch never arrives and that branch keeps grading against
    a retired minimum.
    """
    client = _fetcher(fetch)
    query: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    vulns: list[dict] = []
    seen: set[str] = set()
    for _page in range(OSV_MAX_PAGES):
        hits = client.post_json(OSV_QUERY_URL, query)
        for vuln in hits.get("vulns", []) or []:
            vuln_id = vuln.get("id", "")
            if vuln_id in seen:
                continue
            seen.add(vuln_id)
            vulns.append(vuln)
        token = hits.get("next_page_token")
        if not token:
            return vulns
        query = {**query, "page_token": token}
    raise MinimumRefreshError(
        f"OSV returned more than {OSV_MAX_PAGES} pages for {package}; "
        f"the ladder would be built from a truncated advisory set"
    )


def runc_ladder(fetch: Fetcher | None = None) -> dict:
    """Highest fixed release per major.minor across every runc GHSA advisory.

    Beside the ladder, the block records ``advisoryRanges``: the SEMVER
    affected ranges of every advisory that contributed to it. The audit is
    offline at run time, so this is the only evidence it has to name the
    advisories that actually affect one observed version instead of the whole
    historical advisory set. A withdrawn advisory contributes nothing: its
    minimum is retracted upstream, so grading against it would fail a version
    the ecosystem no longer considers vulnerable. Only SEMVER ranges are read.
    A GIT range carries commit hashes, and a hash split on dots would enter
    the ladder as a branch key that no observed version can ever parse to,
    which the audit reads as an unusable table.
    """
    ladder: dict[str, str] = {}
    advisories: list[str] = []
    advisory_ranges: dict[str, list[dict[str, str]]] = {}
    candidates: dict[str, list[tuple[str, dict[str, Any] | None]]] = {}
    sources: dict[str, dict[str, Any]] = {}
    for vuln in osv_package_vulns(RUNC_PACKAGE, RUNC_ECOSYSTEM, fetch=fetch):
        vuln_id = vuln.get("id", "")
        if not vuln_id.startswith("GHSA-"):
            continue  # GO- entries duplicate the GHSA record.
        if vuln.get("withdrawn"):
            continue  # A retracted advisory must not hold a minimum in place.
        advisories.append(vuln_id)
        published = vuln.get("published")
        source = None
        if isinstance(published, str) and published.strip():
            source = {
                "id": vuln_id,
                "feed": "osv",
                "released": published,
                "url": f"https://osv.dev/vulnerability/{vuln_id}",
            }
            sources[vuln_id] = source
        ranges: list[dict[str, str]] = []
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("name") != RUNC_PACKAGE:
                continue
            for entry in affected.get("ranges", []):
                if entry.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                introduced = "0"
                for event in entry.get("events", []):
                    if event.get("introduced"):
                        introduced = str(event["introduced"])
                        continue
                    last_affected = event.get("last_affected")
                    if last_affected:
                        ranges.append(
                            {
                                "introduced": introduced,
                                "lastAffected": str(last_affected),
                            }
                        )
                        continue
                    fixed = event.get("fixed")
                    if not fixed:
                        continue
                    ranges.append({"introduced": introduced, "fixed": str(fixed)})
                    key = ".".join(fixed.split(".")[:2])
                    candidates.setdefault(key, []).append((fixed, source))
                    previous = ladder.get(key)
                    if previous is None or version_key(fixed) > version_key(previous):
                        ladder[key] = fixed
        if ranges:
            advisory_ranges[vuln_id] = ranges
    minimum_sources: dict[str, str] = {}
    for key, fixed in ladder.items():
        matching = [source for candidate, source in candidates[key] if candidate == fixed]
        # If one advisory that established this minimum has no publication date,
        # the audit cannot prove that the minimum is recent and grants no grace.
        if matching and all(source is not None for source in matching):
            earliest = min(matching, key=lambda item: str(item["released"]))
            minimum_sources[key] = str(earliest["id"])
    minimum_availability: dict[str, dict[str, Any]] = {}
    for key, fixed in sorted(ladder.items()):
        availability = github_release_availability(
            RUNC_RELEASE_REPO, f"v{fixed}", fixed, fetch=fetch
        )
        source = sources.get(minimum_sources.get(key, ""))
        if source and source.get("released"):
            availability["bulletinReleased"] = source["released"]
        minimum_availability[key] = availability
    result = {
        "kind": "ladder",
        "ladder": ladder,
        "floorAvailability": minimum_availability,
        "advisories": sorted(advisories),
        "advisoryRanges": {
            vuln_id: advisory_ranges[vuln_id] for vuln_id in sorted(advisory_ranges)
        },
        "advisory": RUNC_ADVISORY,
        "source": {
            "feed": "osv",
            "package": RUNC_PACKAGE,
            "ecosystem": RUNC_ECOSYSTEM,
            "url": OSV_QUERY_URL,
        },
    }
    if minimum_sources:
        result["floorSources"] = minimum_sources
        result["sources"] = [sources[source_id] for source_id in sorted(sources)]
    return result


def ubuntu_notice_url(notice_id: str) -> str:
    return f"{UBUNTU_NOTICE_URL}{notice_id}.json"


def ubuntu_notices_query_url(
    package_term: str,
    codename: str,
    offset: int = 0,
) -> str:
    """Canonical notice-list URL used to discover package fixes."""

    return UBUNTU_NOTICES_URL + "?" + urllib.parse.urlencode(
        {
            "release": codename,
            "details": package_term,
            "limit": UBUNTU_NOTICE_PAGE_LIMIT,
            "offset": offset,
        }
    )


def ubuntu_package_notices(
    package: str,
    package_term: str,
    codename: str = UBUNTU_RELEASE,
    fetch: Fetcher | None = None,
) -> list[dict]:
    """Return every USN that released one source package for one Ubuntu release.

    Canonical's notice API cannot filter on source package. It can bound the
    result set with a title/details search, so the policy records a search term
    and this function then requires an exact structured source-package match.
    Pagination is complete or the refresh fails; a source outage or a changing
    result set cannot silently look like no new advisory.
    """

    client = _fetcher(fetch)
    first = client.get_json(ubuntu_notices_query_url(package_term, codename))
    total = first.get("total_results")
    notices = first.get("notices")
    if not isinstance(total, int) or total < 1 or not isinstance(notices, list):
        raise MinimumRefreshError(
            f"Ubuntu notice discovery returned malformed metadata for {package} on "
            f"{codename}"
        )
    pages = (total + UBUNTU_NOTICE_PAGE_LIMIT - 1) // UBUNTU_NOTICE_PAGE_LIMIT
    if pages > UBUNTU_NOTICE_MAX_PAGES:
        raise MinimumRefreshError(
            f"Ubuntu notice discovery returned {total} candidates for {package}; "
            f"more than the {UBUNTU_NOTICE_MAX_PAGES}-page safety bound"
        )

    responses: list[dict] = [first]
    offsets = range(UBUNTU_NOTICE_PAGE_LIMIT, total, UBUNTU_NOTICE_PAGE_LIMIT)
    if offsets:
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses.extend(
                pool.map(
                    lambda offset: client.get_json(
                        ubuntu_notices_query_url(package_term, codename, offset)
                    ),
                    offsets,
                )
            )

    candidates: dict[str, dict] = {}
    for response in responses:
        if response.get("total_results") != total:
            raise MinimumRefreshError(
                f"Ubuntu notice discovery changed while reading {package} on {codename}"
            )
        page = response.get("notices")
        if not isinstance(page, list):
            raise MinimumRefreshError(
                f"Ubuntu notice discovery returned a malformed page for {package}"
            )
        for notice in page:
            notice_id = notice.get("id") if isinstance(notice, dict) else None
            if not isinstance(notice_id, str) or not notice_id:
                raise MinimumRefreshError(
                    f"Ubuntu notice discovery returned an entry without an ID for {package}"
                )
            candidates[notice_id] = notice
    if len(candidates) != total:
        raise MinimumRefreshError(
            f"Ubuntu notice discovery returned {len(candidates)} unique candidates for "
            f"{package}, expected {total}"
        )

    matched: list[dict] = []
    for notice_id, notice in candidates.items():
        # LSNs describe Canonical Livepatch delivery rather than the package
        # version available from Noble's security pocket.
        if not notice_id.startswith("USN-"):
            continue
        entries = (notice.get("release_packages") or {}).get(codename, [])
        source = next(
            (
                entry
                for entry in entries
                if isinstance(entry, dict)
                and entry.get("name") == package
                and entry.get("is_source") is True
                and isinstance(entry.get("version"), str)
                and entry["version"].strip()
            ),
            None,
        )
        if source is None:
            continue
        matched.append(
            {
                "id": notice_id,
                "published": notice.get("published"),
                "version": source["version"],
                "cves": sorted(
                    {
                        item.get("id")
                        for item in notice.get("cves", [])
                        if isinstance(item, dict)
                        and isinstance(item.get("id"), str)
                        and item["id"].startswith("CVE-")
                    }
                ),
            }
        )
    if not matched:
        raise MinimumRefreshError(
            f"Ubuntu notice discovery found no {package} source-package fixes for {codename}"
        )
    return matched


def ubuntu_package_minimum(
    package: str,
    package_term: str,
    codename: str = UBUNTU_RELEASE,
    fetch: Fetcher | None = None,
) -> dict:
    """Latest security-pocket source version published by an applicable USN."""

    notices = ubuntu_package_notices(
        package, package_term, codename=codename, fetch=fetch
    )
    minimum = max((notice["version"] for notice in notices), key=version_key)
    forcing = sorted(
        (notice for notice in notices if notice["version"] == minimum),
        key=lambda notice: (str(notice.get("published") or ""), notice["id"]),
    )[-1]
    published = forcing.get("published")
    if not isinstance(published, str) or not published.strip():
        raise MinimumRefreshError(
            f"Ubuntu notice {forcing['id']} does not date the {package} fix {minimum}"
        )
    url = ubuntu_notice_url(forcing["id"])
    entry = {
        "package": package,
        "status": "released",
        "fixed": minimum,
        "cveCount": len(forcing["cves"]),
        "released": published,
        "source": {
            "feed": "ubuntu-security-notice",
            "id": forcing["id"],
            "url": url,
        },
        "coverage": {
            "feed": UBUNTU_NOTICES_URL,
            "matchedNotices": len(notices),
            "query": package_term,
        },
        "fixAvailability": {
            "status": "confirmed",
            "feed": "ubuntu-security-notice",
            "id": forcing["id"],
            "url": url,
            "version": minimum,
            "available": published,
            "bulletinReleased": published,
        },
    }
    if package == "linux":
        abi = kernel_abi(minimum)
        if abi is None:
            raise MinimumRefreshError(
                f"Ubuntu notice {forcing['id']} returned an unreadable kernel version "
                f"{minimum!r}"
            )
        entry["abi"] = abi
    return entry


def ubuntu_osv_urls(cve: str) -> tuple[str, str]:
    """The OSV.dev record and its GitHub mirror for one Ubuntu CVE."""
    year = cve.split("-")[1]
    return (
        f"{UBUNTU_OSV_VULN_URL}UBUNTU-{cve}",
        f"{UBUNTU_OSV_RAW_URL}{year}/UBUNTU-{cve}.json",
    )


def ubuntu_osv_notice_urls(notice_id: str) -> tuple[str, str]:
    """The OSV.dev record and its GitHub mirror for one USN."""
    return (
        f"{UBUNTU_OSV_VULN_URL}{notice_id}",
        f"{UBUNTU_OSV_RAW_URL.removesuffix('cve/')}usn/{notice_id}.json",
    )


def ubuntu_osv_record(cve: str, fetch: Fetcher | None = None) -> dict | None:
    """Canonical's OSV record for one CVE, or None when no mirror answers."""
    logger = logging.getLogger(__name__)
    for url in ubuntu_osv_urls(cve):
        try:
            doc = _fetcher(fetch).get_json(url)
        except MinimumRefreshError as exc:
            logger.warning("ubuntu osv: %s", exc)
            continue
        if isinstance(doc, dict) and doc.get("id") == f"UBUNTU-{cve}":
            return doc
        logger.warning("ubuntu osv: %s did not return UBUNTU-%s", url, cve)
    return None


def _osv_fixed(record: dict, package: str, ecosystem: str) -> tuple[bool, str | None]:
    """Return (listed, fixed) for one source package in one OSV ecosystem."""
    listed = False
    fixed: str | None = None
    for affected in record.get("affected", []):
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != package:
            continue
        listed = True
        for rng in affected.get("ranges", []):
            if not isinstance(rng, dict) or rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed = event["fixed"]
    return listed, fixed


def _osv_priority(record: dict) -> str | None:
    for severity in record.get("severity", []):
        if isinstance(severity, dict) and severity.get("type") == "Ubuntu":
            return severity.get("score")
    return None


def _usn_order(notice_id: str) -> tuple[int, int]:
    match = re.fullmatch(r"USN-(\d+)-(\d+)", notice_id)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def ubuntu_fix_notice(
    notices: Sequence[dict],
    package: str,
    codename: str,
    fixed: str,
    fetch: Fetcher | None = None,
) -> dict | None:
    """Return the first USN that published one exact source-package fix.

    The CVE publication date can precede the package fix. The grace period must
    start from the USN that made the exact fixed version available. `notices`
    holds {"id", "published"} pairs; they are read in publication order. An
    unreadable or malformed notice is skipped because a later matching notice
    still gives a conservative availability date.
    """
    candidates = sorted(
        (
            notice
            for notice in notices
            if isinstance(notice, dict)
            and isinstance(notice.get("id"), str)
            and isinstance(notice.get("published"), str)
        ),
        key=lambda notice: notice["published"],
    )
    for notice in candidates:
        notice_id = notice["id"]
        try:
            detail = _fetcher(fetch).get_json(ubuntu_notice_url(notice_id))
        except MinimumRefreshError:
            continue
        if not isinstance(detail, dict):
            continue
        release_packages = detail.get("release_packages") or {}
        if not isinstance(release_packages, dict):
            continue
        entries = release_packages.get(codename, [])
        if not isinstance(entries, list):
            continue
        for candidate in entries:
            if (
                isinstance(candidate, dict)
                and candidate.get("is_source") is True
                and candidate.get("name") == package
                and candidate.get("version") == fixed
            ):
                detail_release = detail.get("published")
                released = (
                    detail_release
                    if isinstance(detail_release, str) and detail_release.strip()
                    else notice["published"]
                )
                return _ubuntu_notice_record(
                    released, notice_id, fixed, "ubuntu-security-notice",
                    ubuntu_notice_url(notice_id),
                )
    return None


def _ubuntu_notice_record(
    released: str, notice_id: str, fixed: str, feed: str, url: str
) -> dict:
    return {
        "released": released,
        "fixAvailability": {
            "status": "confirmed",
            "available": released,
            "bulletinReleased": released,
            "feed": feed,
            "id": notice_id,
            "version": fixed,
            "url": url,
        },
        "source": {"feed": feed, "id": notice_id, "url": url},
    }


def ubuntu_osv_fix_notices(
    notice_ids: Sequence[str],
    package: str,
    ecosystem: str,
    fixed: str,
    fetch: Fetcher | None = None,
) -> list[dict]:
    """The OSV USN records that ship one exact fix, oldest first.

    OSV.dev serves each USN as an OSV record with its publication date, so the
    first notice can be chosen without fanning out to ubuntu.com, which drops
    parallel connections. An unreadable record is skipped.
    """

    def read(notice_id: str) -> dict | None:
        doc = None
        for url in ubuntu_osv_notice_urls(notice_id):
            try:
                candidate = _fetcher(fetch).get_json(url)
            except MinimumRefreshError:
                continue
            if isinstance(candidate, dict) and candidate.get("id") == notice_id:
                doc = candidate
                break
        if doc is None:
            return None
        published = doc.get("published")
        if not isinstance(published, str) or not published.strip():
            return None
        if _osv_fixed(doc, package, ecosystem)[1] != fixed:
            return None
        return {"id": notice_id, "published": published}

    with ThreadPoolExecutor(max_workers=8) as pool:
        found = [notice for notice in pool.map(read, notice_ids) if notice]
    return sorted(found, key=lambda n: (n["published"], _usn_order(n["id"])))


def _ubuntu_api_entry(cve: str, package: str, codename: str, fetch: Fetcher | None) -> tuple[dict, list]:
    """Read one package status from the Ubuntu security API (last resort)."""
    doc = _fetcher(fetch).get_json(f"{UBUNTU_CVE_URL}{cve}.json")
    entry = {
        "cve": cve,
        "package": package,
        "priority": doc.get("priority"),
        "status": "not-found",
        "fixed": None,
    }
    for candidate in doc.get("packages", []):
        if candidate.get("name") != package:
            continue
        for status in candidate.get("statuses", []):
            if status.get("release_codename") == codename:
                entry["status"] = status.get("status")
                entry["fixed"] = status.get("description")
    return entry, list(doc.get("notices", []))


def ubuntu_entry(
    cve: str, package: str, codename: str = UBUNTU_RELEASE, fetch: Fetcher | None = None
) -> dict:
    """One Ubuntu package status for one CVE on one release.

    Canonical's OSV record is the primary source: it names the exact released
    source-package fix per Ubuntu release and the USNs that shipped it. The
    Ubuntu security API is read only when OSV is unreachable or carries no
    released fix, because only that API reports a tracked but unreleased
    ("pending") fix.
    """
    ecosystem = UBUNTU_OSV_ECOSYSTEMS.get(codename)
    if ecosystem is None:
        raise MinimumRefreshError(f"ubuntu: no OSV ecosystem for release {codename}")
    record = ubuntu_osv_record(cve, fetch=fetch)
    entry: dict | None = None
    notices: list = []
    if record is not None:
        listed, fixed = _osv_fixed(record, package, ecosystem)
        if fixed:
            entry = {
                "cve": cve,
                "package": package,
                "priority": _osv_priority(record),
                "status": "released",
                "fixed": fixed,
            }
            notices = [
                {"id": related}
                for related in sorted(
                    {r for r in record.get("related", []) if isinstance(r, str) and r.startswith("USN-")},
                    key=_usn_order,
                )
            ]
    if entry is not None:
        osv_notices = ubuntu_osv_fix_notices(
            [notice["id"] for notice in notices], package, ecosystem, entry["fixed"],
            fetch=fetch,
        )
        # Confirm the earliest notice on ubuntu.com, one request at a time, so
        # the table keeps the USN's own URL and timestamp. When ubuntu.com
        # cannot confirm any of them, OSV's own USN record still dates the fix.
        notice = ubuntu_fix_notice(
            osv_notices, package, codename, entry["fixed"], fetch=fetch
        )
        if notice is None and osv_notices:
            first = osv_notices[0]
            notice = _ubuntu_notice_record(
                first["published"], first["id"], entry["fixed"], "ubuntu-osv",
                f"{UBUNTU_OSV_VULN_URL}{first['id']}",
            )
        if notice is None:
            # No OSV USN record could date the fix. Without a date the fix
            # stays unconfirmed and its grace period never ends, so read the
            # dated notice list from the Ubuntu security API as a last resort.
            try:
                api_entry, api_notices = _ubuntu_api_entry(
                    cve, package, codename, fetch
                )
            except MinimumRefreshError as exc:
                logging.getLogger(__name__).warning("ubuntu: %s", exc)
            else:
                if api_entry.get("fixed") == entry["fixed"]:
                    notice = ubuntu_fix_notice(
                        api_notices, package, codename, entry["fixed"], fetch=fetch
                    )
        if notice:
            entry.update(notice)
    else:
        entry, notices = _ubuntu_api_entry(cve, package, codename, fetch)
        if entry["status"] == "released" and entry["fixed"]:
            notice = ubuntu_fix_notice(
                notices, package, codename, entry["fixed"], fetch=fetch
            )
            if notice:
                entry.update(notice)
    if entry.get("fixed") and "fixAvailability" not in entry:
        entry["fixAvailability"] = {
            "status": "unconfirmed",
            "feed": "ubuntu-security-api",
            "version": entry["fixed"],
            "url": f"{UBUNTU_CVE_URL}{cve}",
        }
    return entry


def ubuntu_minimums(
    codename: str = UBUNTU_RELEASE,
    specs: Sequence[dict] = UBUNTU_PACKAGES,
    package_policy: Sequence[tuple[str, str]] = UBUNTU_PACKAGE_POLICY,
    fetch: Fetcher | None = None,
) -> dict:
    def resolve(spec: dict) -> tuple[str, dict]:
        entry = ubuntu_entry(spec["cve"], spec["package"], codename, fetch=fetch)
        if spec.get("relatedCves"):
            entry["relatedCves"] = list(spec["relatedCves"])
        if spec.get("abi"):
            abi = kernel_abi(entry.get("fixed"))
            if abi is not None:
                entry["abi"] = abi
        return spec["key"], entry

    # Independent package lookups must not add every slow Ubuntu response to
    # the refresh's wall time. map preserves the input order and propagates
    # failures: no partial package table is returned.
    with ThreadPoolExecutor(max_workers=4) as pool:
        packages = dict(pool.map(resolve, specs))
    # Named CVE entries remain because the audit reports those findings
    # separately. Package-wide floors are discovered from every matching Noble
    # USN, so a new kernel or QEMU advisory cannot wait for a code edit.
    dynamic: dict[str, dict] = {}
    if package_policy:
        with ThreadPoolExecutor(max_workers=len(package_policy)) as pool:
            dynamic = dict(
                pool.map(
                    lambda policy: (
                        policy[0],
                        ubuntu_package_minimum(
                            policy[0], policy[1], codename=codename, fetch=fetch
                        ),
                    ),
                    package_policy,
                )
            )
    for key, entry in dynamic.items():
        # The QEMU collector still reports its named CVE probe even though the
        # package floor now advances with every USN. Preserve that report
        # metadata while replacing its stale, vulnerability-specific floor.
        named_cve = packages.get(key, {}).get("cve")
        if named_cve:
            entry["cve"] = named_cve
        packages[key] = entry
    return {
        "kind": "distroPackages",
        "release": codename,
        "packages": packages,
        "advisory": "https://ubuntu.com/security/notices",
        "source": {"feed": "ubuntu-security-notices", "url": UBUNTU_NOTICES_URL},
    }


def kernel_abi(fixed: str | None) -> int | None:
    """Return the kernel ABI number of an Ubuntu version such as 6.8.0-124.124."""
    if not fixed:
        return None
    match = re.search(r"-(\d+)", fixed)
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# Assembly, fail-closed verification, serialization
# ---------------------------------------------------------------------------


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def docker_release_notes_url(major: int) -> str:
    return DOCKER_RELEASE_NOTES_RAW.format(major=major)


def docker_release_notes_page(major: int) -> str:
    return DOCKER_RELEASE_NOTES_PAGE.format(major=major)


def _docker_security_section(body: str) -> str | None:
    """Return the text of the `### Security` subsection, or None."""
    heading = DOCKER_SECURITY_HEADING.search(body)
    if not heading:
        return None
    rest = body[heading.end():]
    next_heading = DOCKER_NEXT_HEADING.search(rest)
    return rest[: next_heading.start()] if next_heading else rest


def parse_docker_release_notes(text: str) -> list[dict]:
    """Read every release on one Docker Engine release-note page.

    The page is authored markdown in the docker/docs repository. Each release
    is a `## X.Y.Z` heading, the publication date is a `release-date`
    shortcode under the heading, and a release that ships a security fix
    carries a `### Security` subsection that names the CVE or GHSA
    identifiers.
    """
    releases: list[dict] = []
    headings = list(DOCKER_RELEASE_HEADING.finditer(text))
    for index, match in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[match.end():end]
        date_match = DOCKER_RELEASE_DATE.search(body)
        security = _docker_security_section(body)
        releases.append(
            {
                "version": match.group(1),
                "date": date_match.group(1) if date_match else None,
                "security": security is not None,
                "cves": sorted(set(CVE_ID.findall(security or ""))),
                "advisories": sorted(set(GHSA_ID.findall(security or ""))),
            }
        )
    return releases


def docker_minimums(
    existing: dict | None = None,
    majors: Sequence[int] | None = None,
    fetch: Fetcher | None = None,
) -> dict:
    """Derive the Docker Engine minimum from the official release notes.

    The minimum is the highest stable release whose `### Security` subsection
    names a CVE or GHSA identifier. A release without a Security subsection
    ships no security fix, so it does not move the minimum. A Security
    subsection that names no identifier is a hardening-only release (Docker
    29.8.0 added AppArmor and SELinux policy rules this way); it fixes no
    tracked vulnerability, so it does not move the minimum either. A release
    candidate never becomes the minimum. The notes are a text convention, so a
    page that yields no releases, a page that yields no security release, or a
    page on which no security release names an identifier stops the refresh
    instead of publishing a weakened minimum.

    The `existing` table is not read here. The shared checks in `verify()`
    compare the rebuild against it and reject any lowered minimum.
    """
    del existing
    client = _fetcher(fetch)
    if majors is None:
        majors = DOCKER_ENGINE_MAJORS
    candidates: list[tuple[tuple, int, dict]] = []
    hardening_only: list[str] = []
    for major in majors:
        url = docker_release_notes_url(major)
        releases = parse_docker_release_notes(client.get_text(url))
        if not releases:
            raise MinimumRefreshError(
                f"docker: extracted no releases from {url}; "
                f"the release-note format probably changed"
            )
        for release in releases:
            if PRERELEASE.search(release["version"]):
                continue
            if not release["security"]:
                continue
            if not release["cves"] and not release["advisories"]:
                # A Security subsection with no identifier is hardening, not a
                # fix for a tracked vulnerability. It cannot move the minimum,
                # and it must not stop the refresh either: Docker 29.8.0 held
                # the daily job red for weeks this way while the real minimum
                # sat unchanged one release below it.
                hardening_only.append(release["version"])
                continue
            candidates.append((version_key(release["version"]), major, release))
    if not candidates:
        pages = ", ".join(docker_release_notes_url(major) for major in majors)
        if hardening_only:
            raise MinimumRefreshError(
                "docker: every Security subsection on "
                + pages
                + " names no CVE or GHSA identifier ("
                + ", ".join(hardening_only)
                + "); the wording probably changed"
            )
        raise MinimumRefreshError(
            "docker: no release carries a Security subsection on "
            + pages
            + "; the heading convention probably changed"
        )
    _, major, release = max(candidates, key=lambda item: item[0])
    version = release["version"]
    if not release["date"]:
        raise MinimumRefreshError(
            f"docker: release {version} carries no release-date shortcode; "
            f"the page format probably changed"
        )
    anchor = version.replace(".", "")
    advisory = f"{docker_release_notes_page(major)}#{anchor}"
    available = f"{release['date']}T00:00:00Z"
    block: dict[str, Any] = {
        "kind": "minimum",
        "minimum": version,
        "cves": release["cves"],
        "advisory": advisory,
        "fixAvailability": {
            "status": "confirmed",
            "available": available,
            "feed": "docker-release-notes",
            "id": f"docker-engine-{version}",
            "version": version,
            "url": advisory,
        },
        "source": {
            "feed": "docker-release-notes",
            "majors": list(majors),
            "released": available,
            "url": docker_release_notes_page(major),
        },
    }
    if release["advisories"]:
        block["advisories"] = release["advisories"]
    return block


# ---------------------------------------------------------------------------
# NVIDIA HPC SDK supported release window
# ---------------------------------------------------------------------------


def nvhpc_release_window(fetch: Fetcher | None = None) -> dict:
    """Return the current and immediately previous NVIDIA HPC SDK releases.

    NVIDIA publishes a new SDK every few months and keeps older releases on the
    same official index. Cluster images do not need to move on release day, but
    they should remain within one release of current. The generated table makes
    that moving policy reproducible for every audit that consumes it.
    """
    text = _fetcher(fetch).get_text(NVHPC_RELEASES_PAGE)
    releases = sorted(
        set(NVHPC_RELEASE_RE.findall(text)), key=version_key, reverse=True
    )
    if len(releases) < 2:
        raise MinimumRefreshError(
            f"nvhpc: found fewer than two HPC SDK releases on {NVHPC_RELEASES_PAGE}; "
            "the release page format probably changed"
        )
    current, minimum = releases[:2]
    return {
        "kind": "releaseWindow",
        "current": current,
        "minimum": minimum,
        "policy": "current-or-previous",
        "source": {
            "feed": "nvidia-hpc-sdk-releases",
            "url": NVHPC_RELEASES_PAGE,
        },
    }


# ---------------------------------------------------------------------------
# AMD Instinct ROCm minimum
# ---------------------------------------------------------------------------


def amd_bulletin_page(sb_id: str) -> str:
    return AMD_BULLETIN_PAGE.format(sb_id=sb_id.lower())


class _HtmlTables(HTMLParser):
    """Collect every table of an HTML page as rows of (text, rowspan) cells.

    The AMD pages nest no table inside another table, so the parser reads
    depth-one tables only and folds the text of any deeper markup into the
    open cell.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[tuple[str, int]]]] = []
        self._depth = 0
        self._row: list[tuple[str, int]] | None = None
        self._cell: list[str] | None = None
        self._rowspan = 1

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "table":
            self._depth += 1
            if self._depth == 1:
                self.tables.append([])
            return
        if self._depth != 1:
            return
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th"):
            self._cell = []
            rowspan = dict(attrs).get("rowspan") or "1"
            self._rowspan = int(rowspan) if str(rowspan).isdigit() else 1
        elif self._cell is not None:
            # Any other tag inside a cell separates tokens. Without the
            # separator the text of an inline tag, such as a sup footnote
            # marker, glues onto the preceding token and can turn a CVE
            # identifier or a ROCm release into a different value that
            # still looks valid.
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._depth = max(0, self._depth - 1)
            return
        if self._depth != 1:
            return
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append((" ".join("".join(self._cell).split()), self._rowspan))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.tables[-1].append(self._row)
            self._row = None
        elif self._cell is not None:
            self._cell.append(" ")

    def handle_data(self, data: str) -> None:
        if self._depth == 1 and self._cell is not None:
            self._cell.append(data)


def _expand_rowspans(rows: list[list[tuple[str, int]]]) -> list[list[str]]:
    """Copy each cell that spans rows down into every row it covers.

    The AMD tables give one program cell a rowspan over all of its CVE rows,
    so without the expansion only the first row of each program would carry
    the program name.
    """
    pending: dict[int, tuple[str, int]] = {}
    out: list[list[str]] = []
    for cells in rows:
        row: list[str] = []
        column = 0
        index = 0
        while index < len(cells) or column in pending:
            if column in pending:
                text, remaining = pending[column]
                row.append(text)
                if remaining > 1:
                    pending[column] = (text, remaining - 1)
                else:
                    del pending[column]
            else:
                text, span = cells[index]
                index += 1
                row.append(text)
                if span > 1:
                    pending[column] = (text, span - 1)
            column += 1
        out.append(row)
    return out


def html_tables(text: str) -> list[list[list[str]]]:
    """Return every table of an HTML page with rowspans expanded."""
    parser = _HtmlTables()
    parser.feed(text)
    return [_expand_rowspans(rows) for rows in parser.tables if rows]


def amd_bulletin_catalog(fetch: Fetcher | None = None) -> list[dict[str, str]]:
    """Enumerate AMD GPU-software bulletins covered by the current policy."""

    text = _fetcher(fetch).get_text(AMD_SECURITY_INDEX)
    page = re.search(r"Showing\s+1\s+to\s+(\d+)\s+of\s+(\d+)\s+entries", text)
    if page and int(page.group(1)) < int(page.group(2)):
        raise MinimumRefreshError(
            "amd: product-security index is paginated or truncated "
            f"({page.group(1)} of {page.group(2)} rows)"
        )

    catalog: dict[str, dict[str, str]] = {}
    for table in html_tables(text):
        for row in table:
            if len(row) < 5:
                continue
            match = AMD_SB_ID.search(row[0])
            if not match:
                continue
            sb_id = match.group(0).upper()
            if not AMD_GPU_BULLETIN_ID.fullmatch(sb_id):
                continue
            try:
                published = datetime.strptime(row[4].strip(), "%b %d, %Y").date()
            except ValueError as exc:
                raise MinimumRefreshError(
                    f"amd: bulletin {sb_id} has an unparseable publication date "
                    f"{row[4]!r}"
                ) from exc
            if published < AMD_POLICY_START_DATE:
                continue
            if sb_id in catalog:
                raise MinimumRefreshError(
                    f"amd: product-security index lists {sb_id} more than once"
                )
            catalog[sb_id] = {
                "aId": sb_id,
                "published": f"{published.isoformat()}T00:00:00Z",
                "title": row[1].strip(),
                "url": amd_bulletin_page(sb_id),
            }

    if not catalog:
        raise MinimumRefreshError(
            "amd: product-security index contains no in-policy 6000-series bulletins"
        )
    return sorted(catalog.values(), key=lambda item: (item["published"], item["aId"]))


def _amd_mitigation_header(row: list[str]) -> bool:
    """Match the dated mitigation-table header of the tracked AMD series.

    The wording drifts between bulletins ("Program" or "Product", "CVE" or
    "CVE ID", "Release Date" or "Mitigation Release Date"), so each column is
    matched by meaning rather than by exact text.
    """
    if len(row) < 4:
        return False
    cells = [AMD_TRADEMARKS.sub("", cell).strip().lower() for cell in row[:4]]
    return (
        cells[0] in {"program", "product"}
        and cells[1] in {"cve", "cve id"}
        and cells[2] == "mitigation"
        and "date" in cells[3]
    )


def amd_initial_publication(tables: list[list[list[str]]], url: str) -> str:
    """Read the Initial publication date from the Revisions table."""
    for table in tables:
        for row in table:
            if len(row) >= 2 and row[1].strip().lower() == "initial publication":
                date = AMD_DATE.search(row[0])
                if date:
                    return f"{date.group(0)}T00:00:00Z"
    raise MinimumRefreshError(
        f"rocm: found no Initial publication revision on {url}; "
        f"the bulletin page format probably changed"
    )


def parse_amd_bulletin(
    text: str, url: str, catalog_published: str | None = None
) -> dict:
    """Read one in-policy AMD bulletin page.

    A bulletin may concern another 6000-series product and have no applicable
    Instinct mitigation table. That is a valid empty result. An Instinct ROCm
    or Linux GPU Driver release outside the recognized table shape still stops
    the refresh.
    """
    tables = html_tables(text)
    try:
        published = amd_initial_publication(tables, url)
    except MinimumRefreshError:
        if catalog_published is None:
            raise
        published = catalog_published
    rows: list[list[str]] = []
    other_tables: list[list[list[str]]] = []
    for table in tables:
        if _amd_mitigation_header(table[0]):
            rows.extend(table[1:])
        else:
            other_tables.append(table)
    for table in other_tables:
        body = AMD_TRADEMARKS.sub(
            " ", " ".join(" ".join(row) for row in table)
        )
        if AMD_PROGRAM.search(body) and (
            AMD_ROCM_STRAY.search(body) or AMD_DRIVER_STRAY.search(body)
        ):
            raise MinimumRefreshError(
                f"amd: an Instinct ROCm or Linux GPU Driver release appears "
                f"outside the dated mitigation "
                f"tables on {url}; the table format probably changed"
            )
    return {"published": published, "rows": rows}


def amd_rocm_minimums(
    existing: dict | None = None,
    bulletins: Sequence[str] | None = None,
    fetch: Fetcher | None = None,
) -> dict:
    """Build ROCm floors without mixing in packaged host-driver releases."""
    return _amd_program_minimums(existing, bulletins, fetch)


def amd_driver_minimums(fetch: Fetcher | None = None) -> dict:
    """Build the independent AMD Linux GPU Driver floors for Instinct."""
    return _amd_program_minimums(fetch=fetch, host_driver=True)


def _amd_program_minimums(
    existing: dict | None = None,
    bulletins: Sequence[str] | None = None,
    fetch: Fetcher | None = None,
    *,
    host_driver: bool = False,
) -> dict:
    """Merge every tracked AMD bulletin into one ROCm minimum per program.

    A program keeps the highest ROCm release any tracked bulletin names for
    it, compared numerically, and the earliest date any tracked bulletin
    gives for that exact release. AMD repeats a fix across consecutive
    bulletins, so the maximum keeps the newest fix and the minimum date keeps
    its first publication. A mitigation that names no ROCm release, such as a
    GIM driver release, a platform BKC without a ROCm release inside, "No fix
    planned", or a referral to AMD Customer Engineering, never becomes a
    minimum. A program that no tracked bulletin gives a ROCm release for, such
    as the MI355X today, gets no minimum and stays clean in the audit.

    The `existing` table is not read here. The shared checks in `verify()`
    compare the rebuild against it and reject any lowered or dropped program.
    """
    del existing
    component = "amdDriver" if host_driver else "rocm"
    release_label = "driver" if host_driver else "ROCm"
    client = _fetcher(fetch)
    if bulletins is None:
        catalog = amd_bulletin_catalog(client)
    else:
        catalog = [
            {
                "aId": sb_id.upper(),
                "url": amd_bulletin_page(sb_id),
            }
            for sb_id in bulletins
        ]
    sources: list[dict] = []
    records: dict[str, dict[str, Any]] = {}
    for bulletin in catalog:
        sb_id = bulletin["aId"]
        url = bulletin["url"]
        parsed = parse_amd_bulletin(
            client.get_text(url), url, bulletin.get("published")
        )
        used = False
        for row in parsed["rows"]:
            program_cell = row[0] if row else ""
            programs = AMD_PROGRAM.findall(AMD_TRADEMARKS.sub(" ", program_cell))
            if not programs and "instinct" not in program_cell.lower():
                # Client products often use a shorter table shape. They are
                # outside the graded Instinct policy and do not constrain it.
                continue
            if len(row) < 4:
                raise MinimumRefreshError(
                    f"{component}: a mitigation row on {url} has fewer than four "
                    f"cells: {row!r}"
                )
            program_cell, cve_cell, mitigation_cell, date_cell = row[:4]
            mitigation = " ".join(AMD_TRADEMARKS.sub(" ", mitigation_cell).split())
            if not programs:
                if (
                    "instinct" in program_cell.lower()
                    and (
                        AMD_DRIVER_HINT.search(mitigation)
                        if host_driver
                        else AMD_ROCM_HINT.search(mitigation)
                    )
                ):
                    raise MinimumRefreshError(
                        f"{component}: an applicable mitigation {mitigation!r} on {url} "
                        f"names no recognized MI program in {program_cell!r}"
                    )
                continue
            if host_driver:
                if not AMD_DRIVER_HINT.search(mitigation):
                    continue
                match = re.fullmatch(
                    r"Linux GPU Driver (\d+(?:\.\d+){1,2})", mitigation
                )
                if not match:
                    raise MinimumRefreshError(
                        f"amdDriver: unrecognized Instinct mitigation "
                        f"{mitigation!r} on {url}"
                    )
            else:
                if not AMD_ROCM_HINT.search(mitigation):
                    continue
                match = AMD_ROCM_MITIGATION.fullmatch(mitigation)
                if not match:
                    raise MinimumRefreshError(
                        f"rocm: mitigation {mitigation_cell!r} on {url} "
                        f"mentions ROCm and does not parse as one exact "
                        f"release; the wording probably changed"
                    )
            fixed = match.group(1)
            cves = sorted(set(CVE_ID.findall(cve_cell)))
            if not cves:
                raise MinimumRefreshError(
                    f"{component}: {release_label} release {fixed} on {url} carries no CVE "
                    f"identifier in {cve_cell!r}; the wording probably changed"
                )
            date = AMD_DATE.fullmatch(date_cell.strip())
            if not date:
                raise MinimumRefreshError(
                    f"{component}: {release_label} release {fixed} on {url} carries no release "
                    f"date in {date_cell!r}; the wording probably changed"
                )
            available = f"{date.group(0)}T00:00:00Z"
            key = version_key(fixed)
            used = True
            for program in dict.fromkeys(programs):
                record = records.get(program)
                if record is None or key > record["key"]:
                    records[program] = {
                        "key": key,
                        "version": fixed,
                        "available": available,
                        "aId": sb_id.upper(),
                        "url": url,
                        "cves": set(cves),
                    }
                elif key == record["key"]:
                    record["cves"].update(cves)
                    if available < record["available"]:
                        record["available"] = available
                        record["aId"] = sb_id.upper()
                        record["url"] = url
        if used:
            sources.append(
                {
                    "aId": sb_id.upper(),
                    "feed": AMD_FEED,
                    "released": parsed["published"],
                    "url": url,
                }
            )
    if not records:
        raise MinimumRefreshError(
            f"{component}: extracted no {release_label} minimum from "
            + ", ".join(item["url"] for item in catalog)
            + "; the mitigation wording probably changed"
        )
    sources.sort(key=lambda item: (str(item["released"]), item["aId"]))
    newest = sources[-1]
    ordered = sorted(records)
    return {
        "kind": "programMap",
        "programs": {program: records[program]["version"] for program in ordered},
        "programSources": {program: records[program]["aId"] for program in ordered},
        "programCves": {
            program: sorted(records[program]["cves"]) for program in ordered
        },
        "floorAvailability": {
            program: {
                "aId": records[program]["aId"],
                "available": records[program]["available"],
                "feed": AMD_FEED,
                "status": "confirmed",
                "url": records[program]["url"],
                "version": records[program]["version"],
            }
            for program in ordered
        },
        "cves": sorted(set().union(*(records[p]["cves"] for p in ordered))),
        "advisory": newest["url"],
        "source": newest,
        "sources": sorted(sources, key=lambda item: item["aId"]),
    }


def _confirmed_availability(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "confirmed"
        and isinstance(value.get("available"), str)
        and bool(value["available"].strip())
    )


def _source_release(source: Any) -> str | None:
    if not isinstance(source, dict):
        return None
    released = source.get("released") or source.get("published")
    return released if isinstance(released, str) and released.strip() else None


def _minimum_bulletin_released(block: dict, selector: str | None = None) -> str | None:
    kind = block.get("kind")
    source: Any = None
    if kind in {"branchMap", "programMap"} and selector is not None:
        field = "branchSources" if kind == "branchMap" else "programSources"
        source_id = (block.get(field) or {}).get(str(selector))
        source = next(
            (
                item
                for item in block.get("sources") or []
                if isinstance(item, dict) and str(item.get("aId")) == str(source_id)
            ),
            None,
        )
    elif kind == "ladder" and selector is not None:
        source_id = (block.get("floorSources") or {}).get(str(selector))
        source = next(
            (
                item
                for item in block.get("sources") or []
                if isinstance(item, dict) and str(item.get("id")) == str(source_id)
            ),
            None,
        )
    elif kind == "distroPackages" and selector is not None:
        package = (block.get("packages") or {}).get(str(selector))
        if isinstance(package, dict):
            released = package.get("released") or package.get("published")
            if isinstance(released, str) and released.strip():
                return released
            source = package.get("source")
    else:
        source = block.get("source")
    return _source_release(source)


def record_minimum_bulletin_dates(doc: dict) -> None:
    """Store the publication date beside each exact minimum availability record."""
    for block in (doc.get("components") or {}).values():
        kind = block.get("kind")
        if kind in {"branchMap", "trainMap", "programMap", "ladder", "releaseLines"}:
            for selector, availability in (block.get("floorAvailability") or {}).items():
                released = _minimum_bulletin_released(block, str(selector))
                if isinstance(availability, dict) and released:
                    availability["bulletinReleased"] = released
            continue
        if kind == "distroPackages":
            for selector, package in (block.get("packages") or {}).items():
                availability = (
                    package.get("fixAvailability") if isinstance(package, dict) else None
                )
                released = _minimum_bulletin_released(block, str(selector))
                if isinstance(availability, dict) and released:
                    availability["bulletinReleased"] = released
            continue
        availability = block.get("fixAvailability")
        released = _minimum_bulletin_released(block)
        if isinstance(availability, dict) and released:
            availability["bulletinReleased"] = released


def _preserved_availability(
    availability: dict, old_block: dict, selector: str | None = None
) -> dict:
    preserved = copy.deepcopy(availability)
    if "bulletinReleased" not in preserved:
        released = _minimum_bulletin_released(old_block, selector)
        if released:
            preserved["bulletinReleased"] = released
    return preserved


def preserve_confirmed_availability(doc: dict, existing: dict | None) -> None:
    """Keep first fix and bulletin dates while an exact minimum stays unchanged.

    NVIDIA CSAF gives the latest document revision date. For products without
    an exact release API, the first refresh that sees the fixed product is the
    conservative availability date. A later editorial revision must not restart
    the vendor window for an unchanged minimum.
    """
    old_components = ((existing or {}).get("components") or {})
    for name, block in (doc.get("components") or {}).items():
        old = old_components.get(name) or {}
        kind = block.get("kind")
        if kind == "minimum":
            if block.get("minimum") == old.get("minimum") and _confirmed_availability(
                old.get("fixAvailability")
            ):
                block["fixAvailability"] = _preserved_availability(
                    old["fixAvailability"], old
                )
            continue
        keyed_fields = {
            "branchMap": "branches",
            "trainMap": "trains",
            "programMap": "programs",
            "ladder": "ladder",
            "releaseLines": "lines",
        }
        field = keyed_fields.get(str(kind))
        if field:
            current_values = block.get(field) or {}
            old_values = old.get(field) or {}
            current_availability = block.get("floorAvailability") or {}
            old_availability = old.get("floorAvailability") or {}
            for key, minimum in current_values.items():
                old_minimum = old_values.get(key)
                same_minimum = (
                    minimum.get("fixed") == (old_minimum or {}).get("fixed")
                    if kind == "releaseLines" and isinstance(minimum, dict)
                    else minimum == old_minimum
                )
                if same_minimum and _confirmed_availability(
                    old_availability.get(key)
                ):
                    current_availability[key] = _preserved_availability(
                        old_availability[key], old, str(key)
                    )
            block["floorAvailability"] = current_availability
            continue
        if kind != "distroPackages":
            continue
        old_packages = old.get("packages") or {}
        for key, package in (block.get("packages") or {}).items():
            old_package = old_packages.get(key) or {}
            if package.get("fixed") == old_package.get("fixed") and _confirmed_availability(
                old_package.get("fixAvailability")
            ):
                package["fixAvailability"] = _preserved_availability(
                    old_package["fixAvailability"], old, str(key)
                )


def build_minimums(
    generated: str | None = None,
    existing: dict | None = None,
    fetch: Fetcher | None = None,
) -> dict:
    """Fetch every feed and return the full minimum table.

    Raises MinimumRefreshError when a feed cannot be read or when a component
    that the existing table populates now extracts empty.
    """
    nvidia_documents = nvidia_csaf_documents(fetch=fetch)
    driver = nvidia_driver_minimums(fetch=fetch, documents=nvidia_documents)
    connectx = connectx_minimums(fetch=fetch, documents=nvidia_documents)
    simple_products = nvidia_simple_product_minimums(nvidia_documents, fetch=fetch)
    dcgm = nvidia_dcgm_minimums(nvidia_documents, fetch=fetch)
    doc = {
        "schemaVersion": SCHEMA_VERSION,
        "generated": generated or _now_stamp(),
        "maxAgeDays": MAX_AGE_DAYS,
        "gracePeriodDays": GRACE_PERIOD_DAYS,
        "components": {
            **dcgm,
            "nvidiaDriver": driver,
            "nvidiaContainerToolkit": simple_products.get("nvidiaContainerToolkit", {}),
            "nvhpc": nvhpc_release_window(fetch=fetch),
            "cudaToolkit": simple_products.get("cudaToolkit", {}),
            "connectxFirmware": connectx,
            "virtioNetBluefield": nvidia_virtio_net_minimums(nvidia_documents),
            "runc": runc_ladder(fetch=fetch),
            "docker": docker_minimums(fetch=fetch),
            "rocm": amd_rocm_minimums(fetch=fetch),
            "amdDriver": amd_driver_minimums(fetch=fetch),
            "ubuntuNoble": ubuntu_minimums(fetch=fetch),
            "ubuntuJammy": ubuntu_minimums(
                codename="jammy",
                specs=({"key": "linuxBadEpoll", "cve": "CVE-2026-46242",
                        "package": "linux-hwe-6.8"},),
                fetch=fetch,
            ),
        },
    }
    record_minimum_bulletin_dates(doc)
    preserve_confirmed_availability(doc, existing)
    verify(doc, existing)
    return doc


def _payload(block: dict) -> Any:
    kind = block.get("kind")
    if kind == "branchMap":
        return block.get("branches")
    if kind == "trainMap":
        return block.get("trains")
    if kind == "programMap":
        return block.get("programs")
    if kind == "minimum":
        return block.get("minimum")
    if kind == "ladder":
        return block.get("ladder")
    if kind == "releaseLines":
        return block.get("lines")
    if kind == "distroPackages":
        return block.get("packages")
    if kind == "releaseWindow":
        return block.get("minimum")
    return block


def _source_url(block: dict) -> str:
    return (block.get("source") or {}).get("url", "unknown source")


def _availability_problems(label: str, availability: Any) -> list[str]:
    if not isinstance(availability, dict):
        return [f"{label}: fix availability metadata is missing"]
    status = availability.get("status")
    if status not in {"confirmed", "unconfirmed"}:
        return [f"{label}: fix availability status is invalid"]
    if status == "confirmed":
        available = availability.get("available")
        if not isinstance(available, str) or not available.strip():
            return [f"{label}: confirmed fix availability has no date"]
        try:
            datetime.fromisoformat(available.replace("Z", "+00:00"))
        except ValueError:
            return [f"{label}: fix availability date is invalid: {available!r}"]
    return []


def _minimum_downgrades(name: str, label: str, new_map: dict, old_map: dict) -> list[str]:
    """Report every keyed minimum the rebuild would lower or drop.

    Versions are compared numerically through `version_key`. A lexical
    comparison would call 580.126.09 lower than 580.99.01, and it would rank a
    release candidate above its own stable release, so a real downgrade would
    pass this guard unnoticed.
    """
    problems: list[str] = []
    for key, old_fixed in (old_map or {}).items():
        new_fixed = new_map.get(key)
        if new_fixed is None:
            problems.append(
                f"{name}.{key}: {label} minimum {old_fixed} disappeared from the "
                f"rebuild; a published minimum is never removed"
            )
        elif version_key(str(new_fixed)) < version_key(str(old_fixed)):
            problems.append(
                f"{name}.{key}: {label} minimum would drop from {old_fixed} to "
                f"{new_fixed}; a minimum only moves up"
            )
    return problems


def verify(doc: dict, existing: dict | None = None) -> None:
    """Fail closed on any component that lost its data.

    Every component must carry a non-empty minimum. On top of that, an Ubuntu
    package or a VIRTIO-Net release line that the existing table records as
    fixed must still report a fixed version, so a feed change cannot quietly
    drop one entry.

    A rebuild must never lower or remove a minimum the existing table already
    publishes. A minimum only moves up. A new bulletin, a catalog change, a
    wider upstream query, or a parsing regression that lowered one
    would turn a vulnerable fleet green, so it is a hard error rather than a
    warning. The rule covers every keyed minimum (driver branches, ConnectX
    firmware trains, Instinct ROCm programs, runc ladder rungs, VIRTIO-Net
    release lines) and the single-value `minimum` components.
    """
    problems: list[str] = []
    old_components = ((existing or {}).get("components") or {})
    for name, block in doc.get("components", {}).items():
        payload = _payload(block)
        old_block = old_components.get(name) or {}
        if not payload:
            problems.append(
                f"{name}: extracted no minimum from {_source_url(block)}; "
                f"the upstream format or wording probably changed"
            )
            continue
        kind = block.get("kind")
        if kind == "minimum":
            problems.extend(
                _availability_problems(name, block.get("fixAvailability"))
            )
        elif kind in {"branchMap", "trainMap", "programMap", "ladder", "releaseLines"}:
            availability = block.get("floorAvailability") or {}
            for key in payload:
                problems.extend(
                    _availability_problems(f"{name}.{key}", availability.get(str(key)))
                )
        elif kind == "distroPackages":
            for key, entry in payload.items():
                if entry.get("fixed"):
                    problems.extend(
                        _availability_problems(
                            f"{name}.{key}", entry.get("fixAvailability")
                        )
                    )
        if kind == "branchMap":
            problems.extend(
                _minimum_downgrades(name, "branch", payload, old_block.get("branches"))
            )
            continue
        if kind == "trainMap":
            problems.extend(
                _minimum_downgrades(name, "firmware train", payload, old_block.get("trains"))
            )
            continue
        if kind == "programMap":
            problems.extend(
                _minimum_downgrades(name, "program", payload, old_block.get("programs"))
            )
            continue
        if kind == "ladder":
            problems.extend(
                _minimum_downgrades(name, "ladder rung", payload, old_block.get("ladder"))
            )
            continue
        if kind == "minimum":
            old_minimum = old_block.get("minimum")
            if old_minimum and version_key(payload) < version_key(old_minimum):
                problems.append(
                    f"{name}: minimum would drop from {old_minimum} to {payload}; "
                    f"a minimum only moves up"
                )
            continue
        if kind == "releaseWindow":
            current = block.get("current")
            minimum = block.get("minimum")
            if not current or version_key(str(current)) < version_key(str(minimum)):
                problems.append(
                    f"{name}: current release {current!r} is below minimum {minimum!r}"
                )
            old_minimum = old_block.get("minimum")
            if old_minimum and version_key(str(minimum)) < version_key(str(old_minimum)):
                problems.append(
                    f"{name}: minimum would drop from {old_minimum} to {minimum}; "
                    "a minimum only moves up"
                )
            continue
        if kind == "releaseLines":
            old_lines = old_block.get("lines") or {}
            for key, entry in payload.items():
                if not entry.get("fixed"):
                    problems.append(
                        f"{name}.{key}: no fixed release from {_source_url(block)}"
                    )
            problems.extend(
                _minimum_downgrades(
                    name,
                    "release line",
                    {key: entry.get("fixed") for key, entry in payload.items()},
                    {
                        key: entry.get("fixed")
                        for key, entry in old_lines.items()
                        if entry.get("fixed")
                    },
                )
            )
            continue
        if kind != "distroPackages":
            continue
        # Ubuntu versions are Debian-style, so this block checks only that a
        # package that was fixed is still fixed and is still present. It does
        # not compare two Debian versions for order.
        old_packages = old_block.get("packages") or {}
        for key, entry in payload.items():
            if entry.get("fixed"):
                continue
            was_fixed = (old_packages.get(key) or {}).get("fixed")
            detail = f" (was {was_fixed})" if was_fixed else ""
            problems.append(
                f"{name}.{key}: no fixed version for {entry.get('cve')} "
                f"on {block.get('release')}{detail} from {_source_url(block)}"
            )
        for key, old_entry in old_packages.items():
            if key not in payload and old_entry.get("fixed"):
                problems.append(f"{name}.{key}: package disappeared from the rebuild")
    if problems:
        raise MinimumRefreshError(
            "minimum version refresh failed closed; nothing was written:\n  - "
            + "\n  - ".join(problems)
        )


def serialize(doc: dict) -> str:
    """Render the table exactly as it is committed, so --check is a clean diff."""
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# New-bulletin detection
# ---------------------------------------------------------------------------


def bulletin_title(year: int, a_id: str, fetch: Fetcher | None = None) -> str | None:
    """Read a bulletin title from the first bytes of its markdown file."""
    text = _fetcher(fetch).get_text_head(f"{NVIDIA_RAW}/{year}/{a_id}/{a_id}.md")
    if not text:
        return None
    for line in text.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped:
            return stripped
    return None


def relevant_product(title: str) -> str | None:
    for label, pattern in RELEVANT_PRODUCTS:
        if re.search(pattern, title, re.IGNORECASE):
            return label
    return None


def known_bulletin_ids(existing: dict | None = None) -> set[str]:
    known: set[str] = set()
    for block in ((existing or {}).get("components") or {}).values():
        a_id = (block.get("source") or {}).get("aId")
        if a_id is not None:
            known.add(str(a_id))
        for source in block.get("sources") or []:
            source_id = source.get("aId")
            if source_id is not None:
                known.add(str(source_id))
    return known


def untracked_docker_majors(
    majors: Sequence[int] | None = None,
    fetch: Fetcher | None = None,
) -> list[int]:
    """List Docker Engine majors with a release-note page this module ignores.

    One directory listing of the docker/docs release-note folder. Only a major
    above the highest tracked one counts, because an older page cannot raise
    the minimum. A listing that cannot be read is skipped, because this scan is
    a discovery aid and the minimum build fails closed on its own.
    """
    client = _fetcher(fetch)
    if majors is None:
        majors = DOCKER_ENGINE_MAJORS
    try:
        listing = client.get_json(DOCKER_DOCS_CONTENTS)
    except MinimumRefreshError:
        return []
    if not isinstance(listing, list):
        return []
    tracked = max(majors)
    found: set[int] = set()
    for entry in listing:
        name = str(entry.get("name", ""))
        stem, _, suffix = name.partition(".")
        if entry.get("type") != "file" or suffix != "md" or not stem.isdigit():
            continue
        if int(stem) > tracked:
            found.add(int(stem))
    return sorted(found)


def detect_new_bulletins(
    existing: dict | None = None,
    years: Sequence[int] | None = None,
    fetch: Fetcher | None = None,
) -> list[dict]:
    """Report NVIDIA bulletins that match a graded product line and Docker
    Engine majors whose release-note page DOCKER_ENGINE_MAJORS does not track.

    Every item carries a ``status``. ``new`` means the table does not reference
    the bulletin and nobody has decided about it, which is a discovery.
    ``deferred`` means the bulletin is in DEFERRED_BULLETINS and the item
    carries the written ``reason``. A deferred bulletin is reported on every
    run, whether or not the scan finds it and whether or not its title still
    matches a graded product line, so the decision stays in view.

    One directory listing per year, then one ranged read of the first bytes of
    each candidate bulletin's markdown file. A listing or a file that cannot be
    read is skipped instead of failing the run.
    """
    validate_bulletin_lists()
    client = _fetcher(fetch)
    if years is None:
        years = list(range(NVIDIA_CSAF_START_YEAR, datetime.now(timezone.utc).year + 1))
    known = known_bulletin_ids(existing)
    contradictory = sorted(set(DEFERRED_BULLETINS) & known)
    if contradictory:
        raise MinimumRefreshError(
            "NVIDIA bulletins are both applied and deferred: "
            + ", ".join(contradictory)
        )
    found: list[dict] = []
    seen_deferred: set[str] = set()
    for year in years:
        try:
            listing = client.get_json(GITHUB_CONTENTS.format(year=year))
        except MinimumRefreshError:
            continue
        if not isinstance(listing, list):
            continue
        for entry in listing:
            name = str(entry.get("name", ""))
            if entry.get("type") != "dir" or not name.isdigit() or name in known:
                continue
            deferred = name in DEFERRED_BULLETINS
            title = bulletin_title(year, name, fetch=fetch)
            product = relevant_product(title) if title else None
            if not deferred and not product:
                continue
            not_applicable = False
            if not deferred and product == "ConnectX / BlueField":
                doc = client.get_json(bulletin_url(year, int(name)))
                not_applicable = not connectx_document_applies(doc)
            item = {
                "id": int(name),
                "year": year,
                "status": (
                    "deferred"
                    if deferred
                    else "not_applicable"
                    if not_applicable
                    else "new"
                ),
                "product": product,
                "title": title,
                "url": bulletin_blob_url(year, int(name)),
            }
            if deferred:
                seen_deferred.add(name)
                item["reason"] = DEFERRED_BULLETINS[name]
            elif not_applicable:
                item["reason"] = (
                    "CSAF product data does not include any supported networking product: "
                    + ", ".join(NVIDIA_NETWORK_SUPPORTED_PRODUCTS)
                )
            found.append(item)
    # A deferred bulletin that the scan did not reach is still reported, so an
    # entry cannot go quiet by moving year, losing its markdown file, or being
    # retitled out of the relevance patterns.
    for a_id, reason in DEFERRED_BULLETINS.items():
        if a_id in seen_deferred:
            continue
        year = min(years) if years else datetime.now(timezone.utc).year
        found.append(
            {
                "id": int(a_id),
                "year": year,
                "status": "deferred",
                "product": None,
                "title": None,
                "url": bulletin_blob_url(year, int(a_id)),
                "reason": reason,
            }
        )
    for major in untracked_docker_majors(fetch=fetch):
        found.append(
            {
                "id": major,
                "year": datetime.now(timezone.utc).year,
                "status": "new",
                "product": "Docker Engine",
                "title": f"Docker Engine {major} release notes",
                "url": docker_release_notes_page(major),
            }
        )
    return sorted(
        found, key=lambda item: (item["status"], item["year"], str(item["id"]))
    )


# ---------------------------------------------------------------------------
# Paths and CLI
# ---------------------------------------------------------------------------


def default_minimums_path() -> Path | None:
    """Locate the committed table, in a checkout or in an installed wheel."""
    try:
        candidate = runtime_paths.package_runtime_root() / DEFAULT_RELATIVE_PATH
    except RuntimeError:
        return None
    return candidate if candidate.is_file() else None


def load_table(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise MinimumRefreshError(f"minimum table is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MinimumRefreshError(f"minimum table is not valid JSON: {path}: {exc}") from exc


def _existing_table(explicit: str | None, fallback: Path | None) -> dict | None:
    if explicit:
        return load_table(Path(explicit))
    if fallback is not None and fallback.is_file():
        return load_table(fallback)
    discovered = default_minimums_path()
    return load_table(discovered) if discovered else None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m cmax.minimum_refresh",
        description="Regenerate the ClusterMAX minimum version table from upstream feeds.",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--print", action="store_true", help="print the rebuilt table")
    action.add_argument("--write", metavar="PATH", help="write the rebuilt table to PATH")
    action.add_argument(
        "--check",
        metavar="PATH",
        help="compare the rebuild with PATH; exit 1 when they differ",
    )
    action.add_argument(
        "--detect-new-bulletins",
        action="store_true",
        help=(
            "report relevant NVIDIA bulletins the table does not reference, "
            "untracked Docker Engine majors, untracked AMD GPU bulletins, and "
            "the deferred lists; exit 3 only when an untracked item exists"
        ),
    )
    parser.add_argument("--generated", metavar="ISO8601", help="pin the generated timestamp")
    parser.add_argument("--existing", metavar="PATH", help="read the existing table from PATH")
    parser.add_argument("--verbose", action="store_true", help="log feed requests to stderr")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    try:
        if args.detect_new_bulletins:
            existing = _existing_table(args.existing, None)
            found = detect_new_bulletins(existing)
            new = [item for item in found if item["status"] == "new"]
            deferred = [item for item in found if item["status"] == "deferred"]
            not_applicable = [
                item for item in found if item["status"] == "not_applicable"
            ]
            if not_applicable:
                print("Not-applicable bulletins (from structured product matching):")
                for item in not_applicable:
                    print(f"  {item['id']}  {item['title']}  {item['url']}")
                    print(f"      reason: {item['reason']}")
                print()
            if deferred:
                print("Deferred bulletins (a recorded decision, reviewed every run):")
                for item in deferred:
                    title = item["title"] or "title unavailable"
                    print(f"  {item['id']}  {title}  {item['url']}")
                    print(f"      reason: {item['reason']}")
                print()
            if new:
                print("Untracked bulletins that match a graded product line:")
                for item in new:
                    print(
                        f"  {item['id']}  {item['product']}: {item['title']}  {item['url']}"
                    )
                print(
                    f"{len(new)} unknown bulletin(s) match a graded product line. "
                    "Add or repair the CSAF product policy for each applicable "
                    "NVIDIA bulletin, or record the reason to defer it in "
                    "DEFERRED_BULLETINS. Track each Docker Engine major in "
                    "DOCKER_ENGINE_MAJORS.",
                    file=sys.stderr,
                )
                return 3
            print("no unknown bulletins for the graded product lines")
            return 0

        target = Path(args.write or args.check) if (args.write or args.check) else None
        existing = _existing_table(args.existing, target)
        generated = args.generated
        if generated is None and args.check and existing is not None:
            generated = existing.get("generated")
        rendered = serialize(build_minimums(generated=generated, existing=existing, fetch=None))

        if args.check:
            current = Path(args.check).read_text()
            if current == rendered:
                print(f"{args.check} matches the rebuilt table")
                return 0
            diff = difflib.unified_diff(
                current.splitlines(True),
                rendered.splitlines(True),
                fromfile=str(args.check),
                tofile="rebuilt",
            )
            sys.stdout.writelines(diff)
            print(f"{args.check} differs from the rebuilt table", file=sys.stderr)
            return 1
        if args.write:
            Path(args.write).write_text(rendered)
            print(f"wrote {args.write}")
            return 0
        sys.stdout.write(rendered)
        return 0
    except MinimumRefreshError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
