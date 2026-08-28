"""Executable-test helpers for bash workloads.

This module is the shared harness behind the repo's preferred test pattern:
run the real script (or a block extracted from it) under bash with stub
executables on PATH, then assert on behavior, instead of pinning source
fragments with assertIn. See the "Testing doctrine" section of AGENTS.md.

Typical use:

    from pathlib import Path
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    import bashtest

    block = bashtest.extract_function(RUN_SH, "nccl_cache_valid_on_node")
    run = bashtest.run_bash(
        block + '\nnccl_cache_valid_on_node worker-0',
        stubs={"srun": bashtest.exec_from("bash")},
        env={"NCCL_TESTS_DIR": str(cache_dir)},
    )
    assert run.returncode == 0
    assert run.calls("srun")[0][-1] == "worker-0"

Every stub records its argv before running its body, so tests can assert on
how a tool was invoked as well as on the script's observable result.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# Field and record separators for the stub call logs. Unit separator between
# argv fields, record separator between invocations; neither appears in the
# tool arguments these workloads pass.
_FS = "\x1f"
_RS = "\x1e"

def exec_from(command: str) -> str:
    """Stub body that execs the argv tail starting at the named command.

    This makes dispatchers like `srun [flags] bash -c '...' _ args` run
    their payload in-process, which is how tests execute per-node logic
    without a cluster. Skipping forward to the payload command by name
    handles dispatcher flags with separated values (`-n 1`), which a
    skip-leading-dashes loop would misread as the command. Exits 127 when
    the command never appears, so a changed payload fails readably.
    """
    return (
        f'while [[ $# -gt 0 && "$1" != "{command}" ]]; do shift; done\n'
        f'[[ $# -gt 0 ]] || {{ echo "exec_from: {command} not in argv" >&2; exit 127; }}\n'
        'exec "$@"\n'
    )


class BashRun:
    """Result of run_bash: the CompletedProcess plus recorded stub calls."""

    def __init__(self, result: subprocess.CompletedProcess, calls_dir: Path) -> None:
        self.result = result
        self._calls_dir = calls_dir
        # Call logs are read eagerly because the temp dir is gone by the time
        # the caller asserts.
        self._calls: dict[str, list[list[str]]] = {}
        for log in calls_dir.glob("*.calls"):
            parsed = []
            for record in log.read_text().split(_RS):
                if not record:
                    continue
                # Each record is argc followed by the args, so empty and
                # zero-argument invocations round-trip exactly.
                fields = record.split(_FS)[:-1]
                parsed.append(fields[1 : 1 + int(fields[0])])
            self._calls[log.name[: -len(".calls")]] = parsed

    @property
    def returncode(self) -> int:
        return self.result.returncode

    @property
    def stdout(self) -> str:
        return self.result.stdout

    @property
    def stderr(self) -> str:
        return self.result.stderr

    def calls(self, stub_name: str) -> list[list[str]]:
        """Argv of each recorded invocation of the named stub, in order."""
        return self._calls.get(stub_name, [])


def run_bash(
    snippet: str,
    *,
    stubs: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: int = 30,
) -> BashRun:
    """Run a bash snippet with stub executables prepended to PATH.

    stubs maps executable name to a bash body. Each stub records its argv to
    a call log (readable via BashRun.calls) and then runs its body, which
    receives the original "$@". A body of "" makes the stub succeed silently;
    use exec_from() for dispatchers that should exec their payload locally.
    env entries are overlaid on os.environ. The snippet runs without
    `set -e` unless it opts in, matching how extracted blocks behave inside
    their scripts.
    """
    with tempfile.TemporaryDirectory(prefix="bashtest-") as tmp:
        stub_dir = Path(tmp) / "bin"
        calls_dir = Path(tmp) / "calls"
        stub_dir.mkdir()
        calls_dir.mkdir()
        for name, body in (stubs or {}).items():
            stub = stub_dir / name
            # The interpreter path is absolute on purpose: an env-resolved
            # `#!/usr/bin/env bash` shebang would find the stub dir first, so
            # a stub named `bash` (used to intercept `exec bash <script>`
            # harness dispatches) would recurse into itself.
            stub.write_text(
                "#!/bin/bash\n"
                "{\n"
                f"  printf '%s{_FS}' \"$#\" \"$@\"\n"
                f"  printf '{_RS}'\n"
                f'}} >> "{calls_dir}/{name}.calls"\n' + body + "\n"
            )
            stub.chmod(0o755)
        merged_env = {
            **os.environ,
            **(env or {}),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        }
        # The outer interpreter is resolved from the parent environment, not
        # the merged child PATH: execvpe would otherwise find a stub named
        # bash and hand it the whole snippet instead of the dispatch line the
        # test means to intercept.
        result = subprocess.run(
            [shutil.which("bash") or "/bin/bash", "-c", snippet],
            capture_output=True,
            text=True,
            env=merged_env,
            cwd=str(cwd) if cwd is not None else None,
            timeout=timeout,
        )
        return BashRun(result, calls_dir)


def extract_function(script: str | Path, name: str) -> str:
    """Return the source of a top-level `name() {` bash function.

    The function must end with an unindented closing brace, the convention
    throughout this repo's workloads. Raises AssertionError naming the
    script and function when the anchor is missing, so a renamed function
    fails the test readably instead of silently testing nothing.
    """
    text = Path(script).read_text()
    header = f"{name}() {{"
    assert header in text, f"{script}: function {name}() not found"
    start = text.index(header)
    end = text.find("\n}\n", start)
    assert end != -1, f"{script}: no closing brace found for {name}()"
    return text[start : end + len("\n}\n")]


def extract_block(script: str | Path, start_anchor: str, end_anchor: str) -> str:
    """Return the source between two anchors, inclusive of both anchor lines.

    Both anchors are asserted present (and in order) so a refactor that moves
    or renames the block fails with a readable message instead of extracting
    the wrong region.
    """
    text = Path(script).read_text()
    assert start_anchor in text, f"{script}: start anchor not found: {start_anchor!r}"
    start = text.index(start_anchor)
    end = text.find(end_anchor, start)
    assert end != -1, f"{script}: end anchor not found after start: {end_anchor!r}"
    end_line = text.index("\n", end + len(end_anchor))
    return text[start : end_line + 1]
