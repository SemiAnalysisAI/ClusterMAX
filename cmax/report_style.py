"""Shared terminal styling for ClusterMAX audit reports."""

from __future__ import annotations

from collections.abc import Iterable


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[1;31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
}

_STATUS = {
    "pass": ("PASS", "green"),
    "warning": ("WARNING", "yellow"),
    "fail": ("FAIL", "red"),
    "critical": ("FAIL", "red"),
    "skipped": ("SKIPPED", "dim"),
    "not_applicable": ("SKIPPED", "dim"),
}


def paint(text: str, *codes: str, color: bool) -> str:
    """Apply report colors only when the destination is a terminal."""
    if not color or not codes:
        return text
    prefix = "".join(_ANSI[code] for code in codes)
    return f"{prefix}{text}{_ANSI['reset']}"


def hyperlink(label: str, url: str, *, color: bool) -> str:
    """Return a clickable label on a terminal and a visible URL everywhere."""
    if not color:
        return f"{label}  {url}"
    opening = f"\x1b]8;;{url}\x1b\\"
    closing = "\x1b]8;;\x1b\\"
    linked = f"{opening}\x1b[4m{label}\x1b[24m{closing}"
    return f"{linked}  {paint(url, 'dim', color=color)}"


def count(text: str, status: str, *, color: bool) -> str:
    """Style one summary count with the same color as its check status."""
    _label, status_color = _STATUS[status]
    return paint(text, status_color, color=color)


def format_check(
    *,
    title: str,
    check_id: str,
    status: str,
    assessment: str,
    details: Iterable[tuple[str, str]] = (),
    recommendation: str = "",
    references: Iterable[tuple[str, str]] = (),
    color: bool = False,
) -> list[str]:
    """Render one audit check with a fixed status and detail layout."""
    label, status_color = _STATUS[status]
    status_text = paint(f"{label:<8}", status_color, color=color)
    heading = (
        f"{status_text} "
        f"{paint(title, 'bold', color=color)}  "
        f"{paint('[' + check_id + ']', 'dim', color=color)}"
    )
    lines = [heading]
    if assessment:
        lines.append(f"         {assessment}")
    for name, value in details:
        lines.append(
            f"         {paint(name + ':', 'bold', color=color)} {value}"
        )
    if recommendation:
        lines.append(
            f"         {paint('Recommendation:', 'bold', color=color)} "
            f"{recommendation}"
        )
    refs = list(references)
    if refs:
        lines.append(f"         {paint('References:', 'bold', color=color)}")
        for index, (reference_label, url) in enumerate(refs, start=1):
            lines.append(
                f"           [{index}] "
                f"{hyperlink(reference_label, url, color=color)}"
            )
    return lines
