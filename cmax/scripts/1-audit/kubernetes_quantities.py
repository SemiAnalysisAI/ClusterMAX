"""Helpers for normalizing Kubernetes resource quantities."""

from __future__ import annotations

import re
from typing import Any


def kubernetes_memory_gib(value: Any) -> float:
    """Convert a Kubernetes memory quantity to GiB, or zero when unknown."""
    text = str(value).strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|Ti)?", text, re.I)
    if not match:
        return 0.0
    amount = float(match.group(1))
    unit = (match.group(2) or "").lower()
    scale = {
        "": 1 / (1024**3),
        "ki": 1 / (1024**2),
        "mi": 1 / 1024,
        "gi": 1,
        "ti": 1024,
    }
    return amount * scale[unit]
