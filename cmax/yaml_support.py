from __future__ import annotations

from pathlib import Path
from types import ModuleType


def load_yaml_module(repo_root: Path) -> ModuleType:
    del repo_root
    import yaml

    return yaml
