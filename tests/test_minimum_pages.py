"""Tests for the GitHub Pages copy of the minimum version table."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / ".github" / "scripts" / "minimum_pages.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "minimum-versions-publish.yml"
SPEC = importlib.util.spec_from_file_location("minimum_pages", SCRIPT_PATH)
assert SPEC and SPEC.loader
PAGES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAGES)


def table(generated: str, docker: str = "29.7.0", advisory: str = "a") -> dict:
    return {
        "schemaVersion": 1,
        "generated": generated,
        "maxAgeDays": 10,
        "gracePeriodDays": 3,
        "components": {
            "docker": {
                "kind": "minimum",
                "minimum": docker,
                "source": {"feed": "docker-release-notes", "id": advisory},
            }
        },
    }


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "test")
    git(tmp_path, "config", "user.email", "test@example.test")
    return tmp_path


def commit(repo: Path, data: dict) -> Path:
    path = repo / "minimum-versions.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    git(repo, "add", path.name)
    git(repo, "commit", "-q", "-m", data["generated"])
    return path


def test_changed_is_the_revision_that_set_the_current_minimums(repo: Path) -> None:
    commit(repo, table("2026-10-01T07:00:00Z", docker="29.6.0"))
    commit(repo, table("2026-10-05T07:00:00Z", docker="29.7.0"))
    # A timestamp-only refresh and a metadata-only change do not move `changed`.
    commit(repo, table("2026-10-13T07:00:00Z", docker="29.7.0"))
    path = commit(repo, table("2026-10-20T07:00:00Z", docker="29.7.0", advisory="b"))
    current = json.loads(path.read_text())
    assert PAGES.last_changed(current, path, repo=repo) == "2026-10-05T07:00:00Z"


def test_changed_follows_a_new_minimum(repo: Path) -> None:
    commit(repo, table("2026-10-05T07:00:00Z", docker="29.7.0"))
    path = commit(repo, table("2026-10-20T07:00:00Z", docker="29.8.0"))
    current = json.loads(path.read_text())
    assert PAGES.last_changed(current, path, repo=repo) == "2026-10-20T07:00:00Z"


def test_changed_falls_back_to_generated_without_history(tmp_path: Path) -> None:
    path = tmp_path / "minimum-versions.json"
    data = table("2026-10-20T07:00:00Z")
    path.write_text(json.dumps(data))
    assert PAGES.last_changed(data, path, repo=tmp_path) == "2026-10-20T07:00:00Z"


def test_refreshed_moves_without_a_content_change() -> None:
    data = table("2026-10-13T07:00:00Z")
    first = PAGES.build(data, refreshed="2026-10-20T07:28:00Z", changed="2026-10-05T07:00:00Z")
    second = PAGES.build(data, refreshed="2026-10-21T07:28:00Z", changed="2026-10-05T07:00:00Z")
    assert first["components"] == second["components"] == data["components"]
    assert first["changed"] == second["changed"] == "2026-10-05T07:00:00Z"
    assert (first["refreshed"], second["refreshed"]) == (
        "2026-10-20T07:28:00Z",
        "2026-10-21T07:28:00Z",
    )


def test_refreshed_falls_back_to_the_published_stamp_then_generated() -> None:
    data = table("2026-10-13T07:00:00Z")
    kept = PAGES.build(data, refreshed=None, changed="2026-10-13T07:00:00Z",
                       previous="2026-10-19T07:28:00Z")
    assert kept["refreshed"] == "2026-10-19T07:28:00Z"
    bare = PAGES.build(data, refreshed=None, changed="2026-10-13T07:00:00Z")
    assert bare["refreshed"] == "2026-10-13T07:00:00Z"


def test_refreshed_is_never_older_than_generated() -> None:
    data = table("2026-10-13T07:00:00Z")
    published = PAGES.build(data, refreshed="2026-10-01T00:00:00Z", changed="2026-10-13T07:00:00Z")
    assert published["refreshed"] == "2026-10-13T07:00:00Z"


@pytest.mark.parametrize(
    "broken",
    [
        {"schemaVersion": 2},
        {"components": {}},
        {"generated": "not a time"},
        {"components": {"docker": {"kind": "minimum", "source": {}}}},
    ],
)
def test_an_incomplete_table_is_refused(broken: dict) -> None:
    data = {**table("2026-10-13T07:00:00Z"), **broken}
    with pytest.raises(PAGES.PublishError):
        PAGES.check_complete(data)


def test_main_writes_only_the_table(repo: Path, tmp_path: Path) -> None:
    path = commit(repo, table("2026-10-13T07:00:00Z"))
    out = tmp_path / "site"
    assert PAGES.main([
        "--table", str(path), "--out", str(out),
        "--refreshed", "2026-10-24T07:28:02Z", "--repo", str(repo),
    ]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["minimum-versions.json"]
    published = json.loads((out / "minimum-versions.json").read_text())
    assert published["refreshed"] == "2026-10-24T07:28:02Z"
    assert published["changed"] == "2026-10-13T07:00:00Z"


def test_the_workflow_uses_no_secret_and_deploys_with_oidc() -> None:
    text = WORKFLOW_PATH.read_text()
    assert "secrets." not in text
    workflow = yaml.safe_load(text)
    assert workflow["permissions"] == {"contents": "read"}
    deploy = workflow["jobs"]["deploy"]
    assert deploy["permissions"] == {"pages": "write", "id-token": "write"}
    assert deploy["environment"]["name"] == "github-pages"
    assert "contents" not in deploy["permissions"]
