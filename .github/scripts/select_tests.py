#!/usr/bin/env python3
"""Select the test files that cover a set of changed paths.

A test covers a source file when it names the file or imports its module. A
change to a source file selects its tests and the tests of the source files
that use it directly (shell ``.``/``source``, script paths, top-level imports).
Unknown paths select the full suite. Pushes to master and the nightly run use
the full suite, so a dependency this misses still fails within a day.

Usage:
    select_tests.py [--base REF] [PATH ...]

Prints one test path per line, ``ALL`` for the full suite, or nothing when no
test is affected.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
SOURCE_ROOTS = ("cmax",)
SOURCE_SUFFIXES = {".py", ".sh", ".json", ".yaml", ".yml"}

# Changes here select no tests.
IGNORED = (
    "docs/*",
    "*.md",
    "LICENSE",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/workflows/codeql*.yml",
    ".github/workflows/python-nightly.yml",
    ".github/workflows/minimum-versions-publish.yml",
)

# Changes here select the full suite.
FULL_SUITE = (
    "cmax/__init__.py",
    "cmax/_version.py",
    "cmax/scripts/1-audit/cluster-audit-standalone-security.sh",
    "pyproject.toml",
    "setup.py",
    "tests/conftest.py",
    "tests/audit/conftest.py",
    "tests/audit/bashtest.py",
    ".github/workflows/python-tests.yml",
    ".github/scripts/select_tests.py",
)

# Non-source files that tests read by name.
EXTRA_SOURCES = (
    ".github/workflows/minimum-versions-refresh.yml",
    ".github/scripts/nightly_version.py",
    ".github/requirements/release.in",
    ".github/requirements/release.txt",
    ".github/scripts/select_tests.py",
)


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def source_files() -> list[str]:
    files = []
    for top in SOURCE_ROOTS:
        for path in sorted((ROOT / top).rglob("*")):
            if (
                path.is_file()
                and path.suffix in SOURCE_SUFFIXES
                and "__pycache__" not in path.parts
            ):
                files.append(path.relative_to(ROOT).as_posix())
    files.extend(path for path in EXTRA_SOURCES if (ROOT / path).is_file())
    return files


def test_files() -> list[str]:
    return sorted(
        path.relative_to(ROOT).as_posix()
        for path in TESTS.rglob("test_*.py")
        if "__pycache__" not in path.parts
    )


@lru_cache(maxsize=None)
def _text(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""



_FROM_CMAX = re.compile(r"^\s*from\s+cmax\s+import\s+\(?([\w\s,]+)\)?", re.M)
_DOTTED = re.compile(r"\bcmax\.(\w+)")
_TOP_IMPORT = re.compile(r"^(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import\s+\(?([\w\s,]+)\)?)", re.M)
_FILENAME = re.compile(r"[\w.-]+\.(?:py|sh|json|ya?ml|in|txt)\b")
_COMMENT = re.compile(r"(?:^|(?<=\s))#.*$", re.M)


def _cmax_modules(text: str, top_level_only: bool) -> set[str]:
    """``cmax.X`` modules imported by ``text``."""
    found: set[str] = set()
    if top_level_only:
        for match in _TOP_IMPORT.finditer(text):
            module, package, names = match.groups()
            if module and module.startswith("cmax."):
                found.add(module.split(".")[1])
            if package == "cmax":
                found |= {n.strip() for n in names.replace("\n", ",").split(",") if n.strip()}
            elif package and package.startswith("cmax."):
                found.add(package.split(".")[1])
    else:
        for match in _FROM_CMAX.finditer(text):
            found |= {n.strip() for n in match.group(1).replace("\n", ",").split(",") if n.strip()}
        found |= set(_DOTTED.findall(text))
    return {f"cmax/{name}.py" for name in found}


def _sibling_imports(path: str, text: str) -> set[str]:
    """Plain ``import X`` of a module next to a script (sys.path imports)."""
    folder = Path(path).parent
    found = set()
    for match in _TOP_IMPORT.finditer(text):
        module = match.group(1) or match.group(2) or ""
        candidate = folder / f"{module.split('.')[0]}.py"
        if module and (ROOT / candidate).is_file():
            found.add(candidate.as_posix())
    return found


def _named_files(text: str, by_name: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    for name in _FILENAME.findall(text):
        found |= by_name.get(name, set())
    return found


def _dependencies(path: str, text: str, by_name: dict[str, set[str]], top_level_only: bool) -> set[str]:
    deps = _named_files(text, by_name) | _cmax_modules(text, top_level_only)
    if path.startswith("tests/"):
        for match in _TOP_IMPORT.finditer(text):
            module = (match.group(1) or match.group(2) or "").split(".")[0]
            deps |= by_name.get(f"{module}.py", set())
    elif path.endswith(".py"):
        deps |= _sibling_imports(path, text)
    deps.discard(path)
    return deps


@lru_cache(maxsize=1)
def _graph() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return (source -> sources that use it, source -> tests that use it)."""
    sources = source_files()
    known = set(sources)
    by_name: dict[str, set[str]] = {}
    for source in sources:
        by_name.setdefault(Path(source).name, set()).add(source)
    used_by: dict[str, set[str]] = {s: set() for s in sources}
    tested_by: dict[str, set[str]] = {s: set() for s in sources}
    for source in sources:
        code = _COMMENT.sub("", _text(source))
        for dep in _dependencies(source, code, by_name, top_level_only=False) & known:
            used_by[dep].add(source)
    for test in test_files():
        for dep in _dependencies(test, _text(test), by_name, top_level_only=False) & known:
            tested_by[dep].add(test)
    return used_by, tested_by


def _test_dependents(test: str) -> set[str]:
    """Tests that import ``test`` (shared fixtures/helpers)."""
    module = Path(test).stem
    pattern = re.compile(rf"\b(import|from)\s+(\S+\.)?{re.escape(module)}\b")
    return {other for other in test_files() if other != test and pattern.search(_text(other))}


def tests_for_source(path: str) -> set[str]:
    """Tests of ``path`` and of the sources that use it directly."""
    used_by, tested_by = _graph()
    selected = set(tested_by.get(path, set()))
    for user in used_by.get(path, set()):
        selected |= tested_by.get(user, set())
    return selected


def _close_over_test_imports(selected: set[str]) -> set[str]:
    stack = list(selected)
    while stack:
        for dependent in _test_dependents(stack.pop()):
            if dependent not in selected:
                selected.add(dependent)
                stack.append(dependent)
    return selected


def select(changed: list[str]) -> list[str] | None:
    """Return selected test paths, or None for the full suite."""
    sources = set(source_files())
    tests = set(test_files())
    selected: set[str] = set()
    for path in changed:
        if _matches(path, FULL_SUITE):
            return None
        if path in tests:
            selected.add(path)
        elif path.startswith("tests/"):
            name = Path(path).name
            parent = Path(path).parent.name
            hits = {t for t in tests if name in _text(t) or (parent != "audit" and parent in _text(t))}
            if not hits:
                return None
            selected |= hits
        elif path in sources:
            selected |= tests_for_source(path)
        elif _matches(path, IGNORED):
            continue
        else:
            return None
    return sorted(_close_over_test_imports(selected))


def changed_paths(base: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="git ref to diff against (merge base with HEAD)")
    parser.add_argument("paths", nargs="*", help="changed paths (overrides --base)")
    args = parser.parse_args(argv)
    if args.paths:
        changed = args.paths
    elif args.base:
        changed = changed_paths(args.base)
    else:
        parser.error("give --base or paths")
    result = select(changed)
    if result is None:
        print("ALL")
    else:
        print("\n".join(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
