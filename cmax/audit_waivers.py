"""Load the waiver file that marks accepted audit findings."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from cmax.yaml_support import load_yaml_module

DEFAULT_NAME = ".cmax-waivers.yaml"
ENV_VAR = "CLUSTERMAX_WAIVERS"
VERSION = 1
_ENTRY_FIELDS = frozenset({"check", "reason", "expires", "status"})
# The worst result that a waiver accepts, in order of severity.
STATUSES = ("warning", "fail")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class WaiverError(ValueError):
    pass


@dataclass(frozen=True)
class Waiver:
    check: str
    reason: str
    expires: date | None = None
    # None accepts a warning and a failure.
    status: str | None = None

    def accepts(self, status: str) -> bool:
        """A waiver for a warning does not accept a later failure."""
        if self.status is None:
            return True
        return STATUSES.index(status) <= STATUSES.index(self.status)

    def expired(self, today: date) -> bool:
        """A waiver applies through its expiry date."""
        return self.expires is not None and today > self.expires


@dataclass(frozen=True)
class WaiverSet:
    path: Path
    waivers: tuple[Waiver, ...]

    def get(self, key: str) -> Waiver | None:
        return next((waiver for waiver in self.waivers if waiver.check == key), None)


def find_path(explicit: str | None = None, *, cwd: Path | None = None) -> Path | None:
    """Return the waiver file to use: the option, the variable, then the working directory."""
    named = explicit if explicit is not None else os.environ.get(ENV_VAR, "").strip() or None
    if named is not None:
        path = Path(named).expanduser()
        if not named.strip() or not path.exists():
            raise WaiverError(f"waiver file not found: {named or '(empty path)'}")
        return _regular_file(path)
    path = (cwd or Path.cwd()) / DEFAULT_NAME
    # A dangling link is a mistake, not an absent file.
    if not path.exists() and not path.is_symlink():
        return None
    return _regular_file(path)


def _regular_file(path: Path) -> Path:
    if not path.is_file():
        raise WaiverError(f"waiver file is not a readable file: {path}")
    return path


def _expiry(entry: dict[str, Any], where: str) -> date | None:
    if "expires" not in entry:
        return None
    value = entry["expires"]
    # YAML reads an unquoted 2027-06-30 as a date and a quoted one as text.
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    # An empty value is an error: it must not make a waiver permanent.
    if isinstance(value, str) and _ISO_DATE.fullmatch(value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise WaiverError(f"{where}: expires must be a YYYY-MM-DD date")


def _status(entry: dict[str, Any], where: str) -> str | None:
    if "status" not in entry:
        return None
    value = entry["status"]
    if value not in STATUSES:
        raise WaiverError(f"{where}: status must be {' or '.join(STATUSES)}")
    return value


def load(path: Path) -> WaiverSet:
    """Read and validate one waiver file."""
    yaml = load_yaml_module(path.parent)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise WaiverError(f"could not read waiver file {path}: {exc}") from exc
    version = data.get("version") if isinstance(data, dict) else None
    # `true` and 1.0 equal 1 in Python, so compare the type too.
    if type(version) is not int or version != VERSION:
        raise WaiverError(f"{path}: not a version {VERSION} waiver file")
    entries = data.get("waivers")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise WaiverError(f"{path}: waivers must be a list")

    waivers: list[Waiver] = []
    seen: set[str] = set()
    for number, entry in enumerate(entries, start=1):
        where = f"{path}: waiver {number}"
        if not isinstance(entry, dict):
            raise WaiverError(f"{where}: must have check and reason fields")
        unknown = sorted(str(name) for name in set(entry) - _ENTRY_FIELDS)
        if unknown:
            raise WaiverError(f"{where}: unknown field {', '.join(unknown)}")
        check = entry.get("check")
        reason = entry.get("reason")
        if not isinstance(check, str) or not check.strip():
            raise WaiverError(f"{where}: check must name an audit check")
        # A waiver without a reason hides a finding and explains nothing.
        if not isinstance(reason, str) or not reason.strip():
            raise WaiverError(f"{where}: {check} needs a reason")
        check = check.strip()
        if check in seen:
            raise WaiverError(f"{where}: {check} is waived twice")
        seen.add(check)
        waivers.append(
            Waiver(
                check,
                " ".join(reason.split()),
                _expiry(entry, where),
                _status(entry, where),
            )
        )
    return WaiverSet(path, tuple(waivers))
