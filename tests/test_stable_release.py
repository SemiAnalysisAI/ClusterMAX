"""Offline release tests. Synthetic files and fake services never publish."""

import importlib.util
import json
from pathlib import Path
import subprocess
from urllib.error import HTTPError

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stable_release", ROOT / ".github/scripts/stable_release.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
VERSION = "0.3.0"
COMMIT = "a" * 40


class FakeGitHub:
    def __init__(self):
        self.target = None
        self.release = None
        self.assets = {}
        self.writes = []
        self.fail_upload = None

    def tag_commit(self, tag):
        assert tag == f"v{VERSION}"
        return self.target

    def find_release(self, tag):
        return self.release

    def request(self, path, payload=None, *, method="GET"):
        if method == "GET":
            return self.release
        self.writes.append((method, path, payload))
        if path == "git/refs":
            self.target = payload["sha"]
            return {}
        if path == "releases":
            self.release = {**payload, "id": 42, "assets": []}
        elif path == "releases/42":
            self.release.update(payload)
        else:
            raise AssertionError(path)
        return self.release

    def upload(self, tag, path):
        if self.fail_upload == path.name:
            raise RuntimeError("Simulated interrupted upload")
        assert path.name not in self.assets, "Never overwrite an existing asset"
        self.writes.append(("UPLOAD", path.name, None))
        self.assets[path.name] = path.read_bytes()
        self.release["assets"].append({"name": path.name})

    def asset_bytes(self, tag, name):
        return self.assets[name]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Live network or gh execution is forbidden in release tests")
    monkeypatch.setattr(release, "read_url", forbidden)
    monkeypatch.setattr(release.subprocess, "run", forbidden)


@pytest.fixture
def context(monkeypatch):
    for key, value in {
        "GITHUB_REPOSITORY": release.REPOSITORY,
        "GITHUB_REF": "refs/heads/master",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": COMMIT,
        "RELEASE_CHANNEL": "stable",
        "EXPECTED_VERSION": VERSION,
        "SMOKE_TESTED_COMMIT": COMMIT,
    }.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / "publication"
    (root / "dist").mkdir(parents=True)
    (root / "dist" / f"clustermax-{VERSION}-py3-none-any.whl").write_bytes(b"synthetic wheel")
    (root / "dist" / f"clustermax-{VERSION}.tar.gz").write_bytes(b"synthetic source")
    notes = tmp_path / "notes.md"
    notes.write_text("# Synthetic release notes\n")
    release.prepare(root, VERSION, COMMIT, notes)
    return root


def pypi_fixture(bundle):
    manifest = release.verify_bundle(bundle, VERSION, COMMIT, stable=True)
    return {
        "info": {"version": VERSION},
        "urls": [
            {"filename": name, "digests": {"sha256": info["sha256"]},
             "size": info["size"], "yanked": False,
             "url": f"https://files.pythonhosted.org/packages/{name}"}
            for name, info in manifest["files"].items()
        ],
    }


def test_bundle_verifies_original_identity_and_notes(bundle):
    manifest = release.verify_bundle(bundle, VERSION, COMMIT, stable=True)
    assert manifest["commit"] == COMMIT
    assert len(manifest["files"]) == 2
    assert "release-notes.md" in (bundle / "release/SHA256SUMS").read_text()
    assert "manifest.json" in (bundle / "release/SHA256SUMS").read_text()


@pytest.mark.parametrize("version", ["v0.3.0", "0.3.0rc1", "0.3.0+local", "00.3.0", "../0.3.0", "0.3.0\nx"])
def test_invalid_stable_identity_is_rejected(version):
    with pytest.raises(ValueError):
        release.identity(version, COMMIT, stable=True)


@pytest.mark.parametrize("commit", ["master", "a" * 12, "a" * 39, "A" * 40])
def test_only_full_commit_sha_is_allowed(commit):
    with pytest.raises(ValueError):
        release.identity(VERSION, commit, stable=True)


@pytest.mark.parametrize("file", [
    "dist/clustermax-0.3.0-py3-none-any.whl", "dist/clustermax-0.3.0.tar.gz",
    "release/release-notes.md", "release/SHA256SUMS",
])
def test_corrupt_files_fail_before_github_writes(bundle, context, file):
    (bundle / file).write_bytes(b"changed")
    github = FakeGitHub()
    with pytest.raises(ValueError):
        release.finish_github(bundle, VERSION, COMMIT, github)
    assert github.writes == []


@pytest.mark.parametrize("version,commit", [("0.3.1", COMMIT), (VERSION, "b" * 40)])
def test_cross_version_or_commit_artifact_is_rejected(bundle, version, commit):
    with pytest.raises(ValueError, match="identity"):
        release.verify_bundle(bundle, version, commit, stable=True)


def test_extra_distribution_and_metadata_are_rejected(bundle):
    extra = bundle / "dist/credential.txt"
    extra.write_text("synthetic")
    with pytest.raises(ValueError):
        release.verify_bundle(bundle, VERSION, COMMIT, stable=True)
    extra.unlink()
    (bundle / "release/extra").write_text("synthetic")
    with pytest.raises(ValueError):
        release.verify_bundle(bundle, VERSION, COMMIT, stable=True)


def test_symlink_distribution_is_rejected(bundle, tmp_path):
    path = bundle / "dist/clustermax-0.3.0.tar.gz"
    elsewhere = tmp_path / "copy.tar.gz"
    elsewhere.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(elsewhere)
    with pytest.raises(ValueError):
        release.verify_bundle(bundle, VERSION, COMMIT, stable=True)


def test_nightly_bundle_has_no_notes_and_cannot_create_stable_release(tmp_path):
    version = "0.3.1.dev2026101801"
    (tmp_path / "dist").mkdir()
    for suffix in ("-py3-none-any.whl", ".tar.gz"):
        (tmp_path / "dist" / f"clustermax-{version}{suffix}").write_bytes(b"fixture")
    release.prepare(tmp_path, version, COMMIT, None)
    assert "notes" not in release.verify_bundle(tmp_path, version, COMMIT)
    with pytest.raises(ValueError):
        release.verify_bundle(tmp_path, version, COMMIT, stable=True)


@pytest.mark.parametrize("key,value", [
    ("GITHUB_REPOSITORY", "fork/ClusterMAX"),
    ("GITHUB_REF", "refs/heads/feature"),
    ("GITHUB_EVENT_NAME", "schedule"),
    ("GITHUB_SHA", "b" * 40),
    ("RELEASE_CHANNEL", "nightly"),
])
def test_wrong_context_cannot_write_release(bundle, context, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    github = FakeGitHub()
    with pytest.raises(ValueError):
        release.finish_github(bundle, VERSION, COMMIT, github)
    assert github.writes == []


def test_preflight_requires_new_version_and_matching_smoke_test(context, monkeypatch):
    github = FakeGitHub()
    monkeypatch.setattr(release, "pypi_record", lambda version: None)
    release.preflight(VERSION, COMMIT, github)
    assert github.writes == []
    monkeypatch.setenv("SMOKE_TESTED_COMMIT", "b" * 40)
    with pytest.raises(ValueError, match="smoke-tested"):
        release.preflight(VERSION, COMMIT, github)
    monkeypatch.setenv("SMOKE_TESTED_COMMIT", COMMIT)
    monkeypatch.setenv("EXPECTED_VERSION", "0.2.1")
    with pytest.raises(ValueError, match="Expected version"):
        release.preflight(VERSION, COMMIT, github)


def test_preflight_existing_pypi_version_aborts(context, monkeypatch):
    monkeypatch.setattr(release, "pypi_record", lambda version: {})
    with pytest.raises(ValueError, match="already exists"):
        release.preflight(VERSION, COMMIT, FakeGitHub())


def test_preflight_tag_collision_aborts(context, monkeypatch):
    monkeypatch.setattr(release, "pypi_record", lambda version: None)
    github = FakeGitHub()
    github.target = "b" * 40
    with pytest.raises(ValueError, match="another commit"):
        release.preflight(VERSION, COMMIT, github)
    assert github.writes == []


def test_pypi_404_is_absent_but_permission_and_server_errors_are_not(monkeypatch):
    for code in (404, 403, 500):
        def fail(url):
            raise HTTPError(url, code, "fixture", {}, None)
        monkeypatch.setattr(release, "read_url", fail)
        if code == 404:
            assert release.pypi_record(VERSION) is None
        else:
            with pytest.raises(HTTPError):
                release.pypi_record(VERSION)


def test_pypi_eventual_visibility_then_exact_wheel_download(bundle, tmp_path, monkeypatch):
    record = pypi_fixture(bundle)
    wheel = bundle / "dist/clustermax-0.3.0-py3-none-any.whl"
    records = iter([None, {"info": {"version": VERSION}, "urls": []}, record])
    monkeypatch.setattr(release, "pypi_record", lambda version: next(records))
    monkeypatch.setattr(release, "read_url", lambda url: wheel.read_bytes())
    release.verify_pypi(bundle, VERSION, COMMIT, tmp_path / "downloaded", attempts=3, delay=0)
    assert (tmp_path / "downloaded" / wheel.name).read_bytes() == wheel.read_bytes()


@pytest.mark.parametrize("problem", ["digest", "yanked", "version", "extra", "host", "bytes"])
def test_pypi_mismatch_is_not_retried_or_accepted(bundle, tmp_path, monkeypatch, problem):
    record = pypi_fixture(bundle)
    wheel = next(item for item in record["urls"] if item["filename"].endswith(".whl"))
    if problem == "digest":
        wheel["digests"]["sha256"] = "0" * 64
    elif problem == "yanked":
        wheel["yanked"] = True
    elif problem == "version":
        record["info"]["version"] = "0.3.1"
    elif problem == "extra":
        record["urls"].append({"filename": "unexpected"})
    elif problem == "host":
        wheel["url"] = "https://untrusted.example/wheel"
    monkeypatch.setattr(release, "pypi_record", lambda version: record)
    monkeypatch.setattr(release, "read_url", lambda url: b"wrong bytes")
    with pytest.raises(ValueError):
        release.verify_pypi(bundle, VERSION, COMMIT, tmp_path / "downloaded", attempts=1, delay=0)


def test_missing_pypi_release_times_out_without_release_creation(bundle, tmp_path, monkeypatch):
    monkeypatch.setattr(release, "pypi_record", lambda version: None)
    with pytest.raises(ValueError, match="Timed out"):
        release.verify_pypi(bundle, VERSION, COMMIT, tmp_path / "downloaded", attempts=2, delay=0)


def test_release_is_draft_until_all_original_artifacts_are_uploaded(bundle, context):
    github = FakeGitHub()
    release.finish_github(bundle, VERSION, COMMIT, github)
    assert github.target == COMMIT
    assert github.writes[0][1] == "git/refs"
    assert github.writes[1][2]["draft"] is True
    assert github.writes[-1] == ("PATCH", "releases/42", {"draft": False, "make_latest": "true"})
    assert len(github.assets) == 5
    assert github.release["draft"] is False
    assert COMMIT in github.release["body"]


def test_partial_draft_upload_resumes_without_replacing_files(bundle, context):
    github = FakeGitHub()
    github.fail_upload = "manifest.json"
    with pytest.raises(RuntimeError):
        release.finish_github(bundle, VERSION, COMMIT, github)
    assert github.release["draft"] is True
    previous = dict(github.assets)
    github.fail_upload = None
    release.finish_github(bundle, VERSION, COMMIT, github)
    assert all(github.assets[name] == data for name, data in previous.items())
    assert github.release["draft"] is False
    writes = len(github.writes)
    release.finish_github(bundle, VERSION, COMMIT, github)
    assert len(github.writes) == writes


@pytest.mark.parametrize("problem", ["tag", "missing-tag", "asset", "notes", "prerelease", "extra", "missing"])
def test_existing_release_conflicts_never_overwrite(bundle, context, problem):
    github = FakeGitHub()
    release.finish_github(bundle, VERSION, COMMIT, github)
    if problem == "tag":
        github.target = "b" * 40
    elif problem == "missing-tag":
        github.target = None
    elif problem == "asset":
        github.assets["manifest.json"] = b"changed"
    elif problem == "notes":
        github.release["body"] = "Other release"
    elif problem == "prerelease":
        github.release["prerelease"] = True
    elif problem == "extra":
        github.release["assets"].append({"name": "unexpected"})
    else:
        github.release["assets"].pop()
    writes = len(github.writes)
    with pytest.raises(ValueError):
        release.finish_github(bundle, VERSION, COMMIT, github)
    assert len(github.writes) == writes


def test_gh_permission_errors_are_not_treated_as_missing(monkeypatch):
    github = release.GitHub()
    for code in (404, 403):
        monkeypatch.setattr(release.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
            a[0], 1, json.dumps({"status": str(code)}), "fixture error"
        ))
        if code == 404:
            assert github.request("releases/tags/v0.3.0") is None
        else:
            with pytest.raises(RuntimeError):
                github.request("releases/tags/v0.3.0")


def test_annotated_tag_is_resolved_without_modification(monkeypatch):
    github = release.GitHub()
    calls = iter([{"object": {"type": "tag", "sha": "b" * 40}},
                  {"object": {"type": "commit", "sha": COMMIT}}])
    monkeypatch.setattr(github, "request", lambda path: next(calls))
    assert github.tag_commit("v0.3.0") == COMMIT


def test_draft_release_discovery_uses_all_pages(monkeypatch):
    github = release.GitHub()
    draft = {"id": 42, "tag_name": "v0.3.0", "draft": True}
    calls = []
    def response(path):
        calls.append(path)
        if path.endswith("page=1"):
            return [{"tag_name": f"v0.0.{i}"} for i in range(100)]
        return [draft]
    monkeypatch.setattr(github, "request", response)
    assert github.find_release("v0.3.0") == draft
    assert len(calls) == 2


def test_duplicate_drafts_are_not_silently_selected(monkeypatch):
    github = release.GitHub()
    monkeypatch.setattr(github, "request", lambda path: [
        {"tag_name": "v0.3.0", "draft": True}, {"tag_name": "v0.3.0", "draft": True}
    ])
    with pytest.raises(ValueError, match="Multiple"):
        github.find_release("v0.3.0")


def test_workflow_permissions_dependencies_and_manual_inputs():
    workflow = yaml.safe_load((ROOT / ".github/workflows/python-nightly.yml").read_text())
    triggers = workflow.get("on") or workflow[True]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {
        "channel", "expected_version", "smoke_tested_commit"
    }
    jobs = workflow["jobs"]
    assert jobs["publish"]["needs"] == "build"
    assert jobs["verify-pypi"]["needs"] == ["build", "publish"]
    assert jobs["github-release"]["needs"] == ["build", "verify-pypi"]
    assert workflow["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["github-release"]["permissions"] == {"contents": "write"}
    assert "pypi-nightly" in jobs["publish"]["environment"]["name"]
    for name in ("verify-pypi", "github-release"):
        assert "workflow_dispatch" in jobs[name]["if"]
        assert "== 'stable'" in jobs[name]["if"]
        assert "refs/heads/master" in jobs[name]["if"]
    for name, job in jobs.items():
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                expected = "${{ github.sha }}" if name == "build" else "${{ needs.build.outputs.commit }}"
                assert step["with"]["ref"] == expected
                assert step["with"]["persist-credentials"] is False
