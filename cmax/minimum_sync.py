#!/usr/bin/env python3
"""Fetch the published ClusterMAX minimum version table over HTTPS.

`cmax/scripts/1-audit/minimum-versions.json` is the source of truth for
every minimum version the audit grades against. The daily
`minimum-versions-refresh` workflow regenerates that file, and a publish job
copies the merged file to the ClusterMAX website. The website serves the same
bytes at one stable address:

    https://www.clustermax.ai/minimum-versions.json

This module reads that address and stores the result in a user cache
directory. A pip installation freezes the minimum table inside the wheel, and
`cmax.minimum_refresh` cannot help there, because it rebuilds the table from the
upstream feeds and needs a writable checkout. This module needs one HTTPS GET
request and a writable cache directory, so it works for a wheel installation
and for a checkout.

The security audit fetches by default on startup, so an installed client
grades against the current published minimums without any flag. A cluster
under audit frequently has no outbound network access, so a failed fetch
prints one warning and the audit continues against the installed table. An
operator who needs a committed audit result to stay reproducible from the
committed table opts out with `cmax audit security --no-fetch-minimums`.

Design rules:

  * The module is standard library only, the same as `cmax.minimum_refresh`.
  * The module never raises to its caller. `sync()` reports the outcome in a
    `SyncResult`, so a failed fetch prints a warning and the audit continues
    against the installed table.
  * A conditional GET request sends the stored entity tag, so a daily run
    transfers no body when no minimum moved.
  * The fetched table replaces the installed table only when it is valid and
    it is not older than the installed table. A published table can therefore
    move the minimums forward, and it can never move them backward.
  * A failed fetch leaves the last successfully fetched table in the cache.
    `cached_table()` hands that copy to the audit, so one launch with a
    working network keeps every later offline run on the newest table this
    host has seen.

Command line::

    python3 -m cmax.minimum_sync
    python3 -m cmax.minimum_sync --url https://www.clustermax.ai/minimum-versions.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_URL = "https://www.clustermax.ai/minimum-versions.json"
URL_ENV = "CLUSTERMAX_MINIMUMS_URL"
USER_AGENT = "clustermax-minimum-sync/1.0"
DEFAULT_TIMEOUT = 15
# The published table is a small JSON document. The current table is under
# 100 kB. A 4 MB limit accepts years of growth, and it stops a wrong address
# from filling the cache directory.
MAX_BYTES = 4 * 1024 * 1024
SCHEMA_VERSION = 1
CACHE_FILE = "minimum-versions.json"
STATE_FILE = "minimum-versions.http.json"


class MinimumSyncError(RuntimeError):
    """The published table is unreachable, unreadable, or unusable."""


@dataclass
class SyncResult:
    """The outcome of one fetch attempt."""

    ok: bool
    updated: bool
    path: Path | None
    generated: str | None
    message: str


def published_url() -> str:
    """Return the address of the published table."""
    override = os.environ.get(URL_ENV, "").strip()
    return override or DEFAULT_URL


def cache_dir() -> Path:
    """Return the writable directory that holds the fetched table.

    The audit runs as a normal user, and a wheel installation is frequently
    read-only, so the cache never goes next to the installed table.
    """
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base).expanduser() if base else Path.home() / ".cache"
    return root / "clustermax"


def cache_path() -> Path:
    """Return the path of the fetched table."""
    return cache_dir() / CACHE_FILE


def state_path() -> Path:
    """Return the path of the cache validators."""
    return cache_dir() / STATE_FILE


def read_state() -> dict[str, str]:
    """Return the stored validators for the current address, or an empty map.

    The state records the address that produced the cached table. A changed
    address therefore starts a full fetch instead of a conditional fetch.
    """
    try:
        data = json.loads(state_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or data.get("url") != published_url():
        return {}
    return {
        key: str(value)
        for key, value in data.items()
        if key in {"etag", "lastModified"} and value
    }


def write_state(validators: dict[str, str]) -> None:
    """Store the validators next to the cached table."""
    payload = {"url": published_url(), **validators}
    try:
        state_path().write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError:
        # The validators are an optimization. A failed write costs one extra
        # body transfer on the next run, and it must not fail the fetch.
        return


def parse_stamp(value: Any) -> datetime | None:
    """Return the timestamp of a `generated` value, or None."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate(payload: bytes) -> dict[str, Any]:
    """Return the parsed table, or raise `MinimumSyncError`.

    The audit grades against this data, so a partial or unknown document must
    never reach the cache. The reader `minimum_versions.py` accepts one schema
    version, and this check gives the operator a clear message before the
    reader fails.
    """
    try:
        table = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MinimumSyncError(f"the published table is not valid JSON: {exc}") from exc
    if not isinstance(table, dict):
        raise MinimumSyncError("the published table is not a JSON object")
    if table.get("schemaVersion") != SCHEMA_VERSION:
        raise MinimumSyncError(
            f"the published table has schema version "
            f"{table.get('schemaVersion')!r} and this clustermax reads schema "
            f"version {SCHEMA_VERSION}. Update clustermax."
        )
    components = table.get("components")
    if not isinstance(components, dict) or not components:
        raise MinimumSyncError("the published table carries no components")
    if parse_stamp(table.get("generated")) is None:
        raise MinimumSyncError(
            f"the published table has no usable generated timestamp: "
            f"{table.get('generated')!r}"
        )
    return table


def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    validators: dict[str, str] | None = None,
) -> tuple[bytes | None, dict[str, str]]:
    """Return the response body and the new validators.

    The body is None when the server answers 304 Not Modified, which means the
    cached table is current.
    """
    if not url.lower().startswith("https://"):
        # The table decides a pass or a fail result, so the transport must
        # authenticate the server.
        raise MinimumSyncError(f"the minimum table address must use https: {url}")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    stored = validators or {}
    if stored.get("etag"):
        headers["If-None-Match"] = stored["etag"]
    if stored.get("lastModified"):
        headers["If-Modified-Since"] = stored["lastModified"]
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # urllib follows a redirect across schemes, so an origin or CDN rule
            # that bounces through http:// would hand back a body no one
            # authenticated. Check the address the body actually came from.
            final = response.geturl()
            if not final.lower().startswith("https://"):
                raise MinimumSyncError(
                    f"{url} redirected to an address that is not https: {final}"
                )
            body = response.read(MAX_BYTES + 1)
            fresh = {
                key: value
                for key, value in (
                    ("etag", response.headers.get("ETag", "")),
                    ("lastModified", response.headers.get("Last-Modified", "")),
                )
                if value
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, stored
        raise MinimumSyncError(f"{url} answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise MinimumSyncError(f"{url} could not be read: {exc}") from exc
    if len(body) > MAX_BYTES:
        raise MinimumSyncError(
            f"{url} returned more than {MAX_BYTES} bytes, so it is not the "
            f"minimum table"
        )
    return body, fresh


def store(payload: bytes) -> Path:
    """Write the fetched table to the cache and return its path.

    The write is atomic. A run that stops during the write therefore leaves
    the previous cached table in place instead of a truncated file.
    """
    target = cache_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=target.parent, prefix=f".{CACHE_FILE}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        os.replace(temporary, target)
    except OSError as exc:
        raise MinimumSyncError(f"the cache directory is not writable: {exc}") from exc
    return target


def cached_table() -> tuple[Path, str] | None:
    """Return the cached table path and its `generated` stamp, or None.

    The cache holds the last successfully fetched table. A run whose fetch
    fails grades against this copy when it is not older than the installed
    table. The payload is validated again here, so a truncated or foreign
    file in the cache directory never reaches the audit.
    """
    try:
        payload = cache_path().read_bytes()
    except OSError:
        return None
    try:
        parsed = validate(payload)
    except MinimumSyncError:
        return None
    return cache_path(), str(parsed.get("generated"))


def sync(
    *,
    url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    installed_generated: str | None = None,
) -> SyncResult:
    """Fetch the published table into the cache and report the outcome.

    `installed_generated` is the `generated` timestamp of the table the audit
    uses now. The fetched table is rejected when it is older, so a published
    file that regressed cannot retire a newer minimum.

    This function never raises. The audit continues against the installed
    table for every failure.
    """
    address = url or published_url()
    try:
        body, validators = fetch(address, timeout=timeout, validators=read_state())
    except MinimumSyncError as exc:
        return SyncResult(False, False, None, None, str(exc))
    cached = cache_path()
    if body is None:
        # 304 Not Modified. The cache holds the current published table.
        generated = None
        try:
            generated = str(json.loads(cached.read_text()).get("generated") or "")
        except (OSError, json.JSONDecodeError, AttributeError):
            # The validators and the cached file disagree. Drop the validators
            # so that the next run fetches the complete body again.
            write_state({})
            return SyncResult(
                False,
                False,
                None,
                None,
                f"{address} reported no change, and the cached table {cached} "
                f"could not be read. The next run fetches it again.",
            )
        return SyncResult(
            True,
            False,
            cached,
            generated or None,
            f"the published minimum table is unchanged (generated {generated}).",
        )
    try:
        table = validate(body)
    except MinimumSyncError as exc:
        return SyncResult(False, False, None, None, str(exc))
    published = parse_stamp(table.get("generated"))
    installed = parse_stamp(installed_generated)
    if installed is not None and published is not None and published < installed:
        return SyncResult(
            False,
            False,
            None,
            str(table.get("generated")),
            f"the published table was generated {table.get('generated')} and "
            f"the installed table was generated {installed_generated}, so the "
            f"published table is older. Keeping the installed table.",
        )
    try:
        path = store(body)
    except MinimumSyncError as exc:
        return SyncResult(False, False, None, None, str(exc))
    write_state(validators)
    return SyncResult(
        True,
        True,
        path,
        str(table.get("generated")),
        f"fetched the published minimum table (generated {table.get('generated')}) "
        f"to {path}.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch the published ClusterMAX minimum version table."
    )
    parser.add_argument(
        "--url",
        default=None,
        help=f"Read the table from this address. Default: {DEFAULT_URL}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Stop the request after this many seconds. Default: {DEFAULT_TIMEOUT}",
    )
    args = parser.parse_args(argv)
    result = sync(url=args.url, timeout=args.timeout)
    print(result.message)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
