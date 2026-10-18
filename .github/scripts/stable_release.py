#!/usr/bin/env python3
"""Bind publication artifacts to one commit and finish an approved release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import urlopen


REPOSITORY = "SemiAnalysisAI/ClusterMAX"
PYPI = "https://pypi.org/pypi/clustermax"
NUMBER = r"(?:0|[1-9][0-9]*)"
STABLE = rf"{NUMBER}\.{NUMBER}\.{NUMBER}"
VERSION = re.compile(rf"{STABLE}(?:\.dev[0-9]+)?")
SHA = re.compile(r"[0-9a-f]{40}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(version: str, commit: str, *, stable: bool = False) -> None:
    pattern = STABLE if stable else VERSION.pattern
    if re.fullmatch(pattern, version) is None or SHA.fullmatch(commit) is None:
        raise ValueError("Expected a canonical version and full lowercase commit SHA")


def approved_context(commit: str) -> None:
    expected = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/master",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": commit,
        "RELEASE_CHANNEL": "stable",
    }
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise ValueError("Stable publication requires manual dispatch on public master")


def read_url(url: str) -> bytes:
    with urlopen(url, timeout=30) as response:
        return response.read()


def pypi_record(version: str) -> dict | None:
    try:
        return json.loads(read_url(f"{PYPI}/{version}/json"))
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


class GitHub:
    """Use the runner token via gh, never a saved or printed credential."""

    def request(self, path: str, payload: dict | None = None, *, method: str = "GET"):
        args = ["gh", "api", f"repos/{REPOSITORY}/{path}", "--method", method]
        if payload is not None:
            args += ["--input", "-"]
        result = subprocess.run(
            args, input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            try:
                status = json.loads(result.stdout).get("status")
            except (ValueError, AttributeError):
                status = None
            if method == "GET" and str(status) == "404":
                return None
            raise RuntimeError(f"GitHub {method} {path} failed: {result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def tag_commit(self, tag: str) -> str | None:
        value = self.request(f"git/ref/tags/{tag}")
        if value is None:
            return None
        obj = value["object"]
        for _ in range(8):
            if obj["type"] == "commit":
                return obj["sha"]
            if obj["type"] != "tag":
                break
            value = self.request(f"git/tags/{obj['sha']}")
            if value is None:
                break
            obj = value["object"]
        raise ValueError("Tag does not resolve to a commit")

    def find_release(self, tag: str) -> dict | None:
        # The tag endpoint returns published releases only. List releases to
        # find an interrupted draft too, using the final job's write token.
        matches = []
        for page in range(1, 101):
            values = self.request(f"releases?per_page=100&page={page}")
            if not isinstance(values, list):
                raise ValueError("Cannot enumerate releases")
            matches.extend(value for value in values if value.get("tag_name") == tag)
            if len(values) < 100:
                if len(matches) > 1:
                    raise ValueError("Multiple releases use this tag. Inspect them manually.")
                return matches[0] if matches else None
        raise ValueError("Release listing was truncated. Inspect it manually.")

    def asset_bytes(self, tag: str, name: str) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                ["gh", "release", "download", tag, "--repo", REPOSITORY,
                 "--pattern", name, "--dir", directory],
                check=True, capture_output=True,
            )
            return (Path(directory) / name).read_bytes()

    def upload(self, tag: str, path: Path) -> None:
        # Deliberately omit --clobber. A conflicting asset must stop the job.
        subprocess.run(
            ["gh", "release", "upload", tag, str(path), "--repo", REPOSITORY],
            check=True, capture_output=True,
        )


def preflight(version: str, commit: str, github: GitHub) -> None:
    identity(version, commit, stable=True)
    approved_context(commit)
    if os.environ.get("EXPECTED_VERSION") != version:
        raise ValueError("Expected version must match the checked-out source version")
    if os.environ.get("SMOKE_TESTED_COMMIT") != commit:
        raise ValueError("Confirm the full commit smoke-tested on a test cluster")
    if pypi_record(version) is not None:
        raise ValueError("Version already exists on PyPI. Do not rebuild or republish it.")
    target = github.tag_commit(f"v{version}")
    if target is not None and target != commit:
        raise ValueError("Existing tag points to another commit. Never move it.")
    if github.find_release(f"v{version}") is not None:
        raise ValueError("GitHub Release already exists. Inspect it before publication.")


def file_record(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": digest(data), "size": len(data)}


def distribution_paths(root: Path, version: str) -> list[Path]:
    paths = [
        root / "dist" / f"clustermax-{version}-py3-none-any.whl",
        root / "dist" / f"clustermax-{version}.tar.gz",
    ]
    if set((root / "dist").iterdir()) != set(paths):
        raise ValueError("Expected exactly the versioned wheel and source distribution")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("Distribution files must be regular files")
    return paths


def checksum_text(paths: list[Path]) -> str:
    return "".join(f"{digest(path.read_bytes())}  {path.name}\n" for path in sorted(paths))


def prepare(root: Path, version: str, commit: str, notes: Path | None) -> None:
    identity(version, commit, stable=notes is not None)
    paths = distribution_paths(root, version)
    release = root / "release"
    release.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema": 1, "version": version, "commit": commit,
        "files": {path.name: file_record(path) for path in paths},
    }
    if notes is not None:
        if notes.is_symlink() or not notes.is_file() or not notes.read_text().strip():
            raise ValueError("Stable release requires committed, nonempty release notes")
        destination = release / "release-notes.md"
        shutil.copyfile(notes, destination)
        manifest["notes"] = file_record(destination)
        paths.append(destination)
    manifest_path = release / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    paths.append(manifest_path)
    (release / "SHA256SUMS").write_text(checksum_text(paths))


def verify_bundle(root: Path, version: str, commit: str, *, stable: bool = False) -> dict:
    identity(version, commit, stable=stable)
    release = root / "release"
    manifest_path = release / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Manifest must be a regular file")
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema"), manifest.get("version"), manifest.get("commit")) != (1, version, commit):
        raise ValueError("Artifact identity does not match this workflow run")
    paths = distribution_paths(root, version)
    actual = {path.name: file_record(path) for path in paths}
    if manifest.get("files") != actual:
        raise ValueError("Distribution hashes do not match the manifest")
    if stable or "notes" in manifest:
        notes = release / "release-notes.md"
        if notes.is_symlink() or not notes.is_file() or manifest.get("notes") != file_record(notes):
            raise ValueError("Release notes do not match the manifest")
        paths.append(notes)
    paths.append(manifest_path)
    expected = {path for path in paths if path.parent == release} | {release / "SHA256SUMS"}
    if set(release.iterdir()) != expected:
        raise ValueError("Unexpected files in release metadata")
    if any(path.is_symlink() or not path.is_file() for path in expected):
        raise ValueError("Release metadata must be regular files")
    if (release / "SHA256SUMS").read_text() != checksum_text(paths):
        raise ValueError("Checksums do not match the publication files")
    return manifest


def verify_pypi(root: Path, version: str, commit: str, wheel_dir: Path,
                *, attempts: int = 18, delay: float = 10) -> None:
    manifest = verify_bundle(root, version, commit, stable=True)
    expected = manifest["files"]
    for attempt in range(attempts):
        record = pypi_record(version)
        if record is not None:
            if record.get("info", {}).get("version") != version:
                raise ValueError("PyPI returned a different version")
            remote = {item["filename"]: item for item in record.get("urls", [])}
            if set(remote) - set(expected):
                raise ValueError("PyPI contains unexpected files for this version")
            for name, item in remote.items():
                if item.get("yanked") or item.get("digests", {}).get("sha256") != expected[name]["sha256"]:
                    raise ValueError("PyPI file is yanked or has a different digest")
            if set(remote) == set(expected):
                wheel_name = f"clustermax-{version}-py3-none-any.whl"
                url = remote[wheel_name]["url"]
                parsed = urlparse(url)
                if parsed.scheme != "https" or parsed.netloc != "files.pythonhosted.org":
                    raise ValueError("Wheel URL is not on the PyPI file host")
                data = read_url(url)
                if digest(data) != expected[wheel_name]["sha256"]:
                    raise ValueError("Downloaded PyPI wheel does not match the built wheel")
                wheel_dir.mkdir(parents=True, exist_ok=True)
                (wheel_dir / wheel_name).write_bytes(data)
                return
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise ValueError("Timed out waiting for both verified distribution files on PyPI")


def release_body(root: Path, version: str, commit: str) -> str:
    notes = (root / "release" / "release-notes.md").read_text().rstrip()
    return (
        f"{notes}\n\n## Publication provenance\n\n"
        f"Version: `{version}`\n\nCommit: `{commit}`\n\n"
        "The attached distributions match the verified PyPI files. "
        "See `SHA256SUMS` and `manifest.json` for their hashes.\n"
    )


def finish_github(root: Path, version: str, commit: str, github: GitHub) -> None:
    verify_bundle(root, version, commit, stable=True)
    approved_context(commit)
    tag = f"v{version}"
    target = github.tag_commit(tag)
    if target is not None and target != commit:
        raise ValueError("Existing tag points to another commit. Never move it.")
    body = release_body(root, version, commit)
    title = f"ClusterMAX {version}"
    release = github.find_release(tag)
    if release is not None:
        if target is None:
            raise ValueError("Existing release is missing its tag. Inspect it manually.")
        if (release["tag_name"], release["name"], release["body"], release["prerelease"]) != (tag, title, body, False):
            raise ValueError("Existing release metadata differs. Refusing to replace it.")
    if target is None:
        github.request("git/refs", {"ref": f"refs/tags/{tag}", "sha": commit}, method="POST")
    if release is None:
        release = github.request("releases", {
            "tag_name": tag, "target_commitish": commit, "name": title, "body": body,
            "draft": True, "prerelease": False,
        }, method="POST")
    paths = distribution_paths(root, version) + sorted((root / "release").iterdir())
    expected = {path.name: path for path in paths}
    assets = {item["name"]: item for item in release.get("assets", [])}
    if set(assets) - set(expected):
        raise ValueError("Existing release has unexpected assets")
    for name, path in expected.items():
        if name in assets:
            if github.asset_bytes(tag, name) != path.read_bytes():
                raise ValueError(f"Existing release asset differs: {name}. Never overwrite it.")
        elif release["draft"]:
            github.upload(tag, path)
        else:
            raise ValueError("Published release is missing an asset. Inspect it manually.")
    # Confirm every upload before making the draft visible.
    for name, path in expected.items():
        if github.asset_bytes(tag, name) != path.read_bytes():
            raise ValueError(f"Uploaded release asset does not match: {name}")
    if github.tag_commit(tag) != commit:
        raise ValueError("Tag changed during release creation")
    if release["draft"]:
        github.request(f"releases/{release['id']}", {"draft": False, "make_latest": "true"}, method="PATCH")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["preflight", "prepare", "verify", "verify-pypi", "github-release"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--root", type=Path, default=Path("publication"))
    parser.add_argument("--notes", type=Path)
    parser.add_argument("--stable", action="store_true")
    parser.add_argument("--wheel-dir", type=Path, default=Path("/tmp/clustermax-pypi-wheel"))
    args = parser.parse_args()
    if args.operation == "preflight":
        preflight(args.version, args.commit, GitHub())
    elif args.operation == "prepare":
        prepare(args.root, args.version, args.commit, args.notes)
    elif args.operation == "verify":
        verify_bundle(args.root, args.version, args.commit, stable=args.stable)
    elif args.operation == "verify-pypi":
        verify_pypi(args.root, args.version, args.commit, args.wheel_dir)
    else:
        finish_github(args.root, args.version, args.commit, GitHub())


if __name__ == "__main__":
    main()
