"""Run the python-tests change classifier under bash against real git repos.

`.github/workflows/python-tests.yml` decides which steps a change needs
from the files that differ between the base commit and HEAD. These tests
extract that step and run it in a throwaway clone, the way the job does.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "python-tests.yml"
ZERO_SHA = "0" * 40
UNREACHABLE_SHA = "a" * 40

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def classifier_script() -> str:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["test"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "changes")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=GIT_ENV, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def commit_files(repo: Path, files: dict[str, str], message: str) -> str:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class ChangeClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.origin = root / "origin"
        self.origin.mkdir()
        git(self.origin, "init", "-q", "-b", "master")
        self.base_sha = commit_files(
            self.origin,
            {
                "README.md": "docs\n",
                "cmax/cli.py": "code\n",
                "tests/test_x.py": "tests\n",
                ".github/requirements/release.txt": "build==1\n",
            },
            "base",
        )
        self.work = root / "work"
        git(root, "clone", "-q", str(self.origin), str(self.work))

    def classify(self, files: dict[str, str], base_sha: str | None = None) -> dict[str, str]:
        if files:
            commit_files(self.work, files, "change")
        output = Path(self.directory.name) / "output"
        summary = Path(self.directory.name) / "summary"
        output.touch()
        summary.touch()
        run = subprocess.run(
            ["bash", "-c", classifier_script()],
            cwd=self.work,
            env={
                **GIT_ENV,
                "BASE_SHA": self.base_sha if base_sha is None else base_sha,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("### python-tests", summary.read_text())
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_docs_only_change_skips_every_step(self) -> None:
        result = self.classify({"README.md": "new docs\n"})
        self.assertEqual(result, {"run_tests": "false", "run_wheel": "false"})

    def test_pinned_ci_requirements_skip_every_step(self) -> None:
        result = self.classify({".github/requirements/release.txt": "build==2\n"})
        self.assertEqual(result, {"run_tests": "false", "run_wheel": "false"})

    def test_test_change_runs_tests_only(self) -> None:
        result = self.classify({"tests/test_x.py": "more tests\n"})
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "false"})

    def test_refresh_workflow_change_runs_tests_only(self) -> None:
        result = self.classify(
            {".github/workflows/minimum-versions-refresh.yml": "name: refresh\n"}
        )
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "false"})

    def test_package_change_runs_every_step(self) -> None:
        result = self.classify({"cmax/scripts/1-audit/run.sh": "#!/bin/bash\n"})
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_packaging_change_runs_every_step(self) -> None:
        result = self.classify({"pyproject.toml": "[project]\n"})
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_workflow_self_change_runs_every_step(self) -> None:
        result = self.classify({".github/workflows/python-tests.yml": "name: x\n"})
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_deleted_package_file_runs_every_step(self) -> None:
        (self.work / "cmax/cli.py").unlink()
        git(self.work, "commit", "-q", "-am", "delete")
        result = self.classify({})
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_missing_base_runs_every_step(self) -> None:
        result = self.classify({"README.md": "x\n"}, base_sha=ZERO_SHA)
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_empty_base_runs_every_step(self) -> None:
        result = self.classify({"README.md": "x\n"}, base_sha="")
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})

    def test_unreachable_base_runs_every_step(self) -> None:
        result = self.classify({"README.md": "x\n"}, base_sha=UNREACHABLE_SHA)
        self.assertEqual(result, {"run_tests": "true", "run_wheel": "true"})


if __name__ == "__main__":
    unittest.main()
