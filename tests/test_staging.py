import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from bke_updater_core.models import SignedUpdatePolicy
from bke_updater_core.staging import StagingError, stage_verified_zip


def _policy(path: Path) -> SignedUpdatePolicy:
    data = path.read_bytes()
    return SignedUpdatePolicy(
        schema="bke.update-policy.v1",
        product_id="bke-test",
        current_version="1.0.0",
        latest_version="1.1.0",
        minimum_supported_version="1.0.0",
        channel="stable",
        platform="windows",
        architecture="x64",
        release_id="release-1",
        artifact_id="artifact-1",
        artifact_sha256=hashlib.sha256(data).hexdigest(),
        artifact_size=len(data),
        content_type="application/zip",
        published_at="2026-08-26T00:00:00Z",
        issued_at="2026-08-26T00:00:00Z",
        revision=1,
        signing_key_id="test",
        algorithm="Ed25519",
        signature="test",
        raw={},
    )


def _zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_stages_verified_tree_and_requires_expected_executable(tmp_path: Path):
    artifact = tmp_path / "update.zip"
    _zip(artifact, {"App.exe": b"new", "assets/config.json": b"{}"})
    staged = stage_verified_zip(artifact, tmp_path / "stage", _policy(artifact), executable_relative="App.exe")
    assert (staged / "App.exe").read_bytes() == b"new"
    assert (staged / "assets" / "config.json").read_bytes() == b"{}"


def test_rejects_traversal_and_does_not_leave_stage(tmp_path: Path):
    artifact = tmp_path / "bad.zip"
    _zip(artifact, {"../escape.exe": b"bad", "App.exe": b"new"})
    with pytest.raises(StagingError, match="escapes"):
        stage_verified_zip(artifact, tmp_path / "stage", _policy(artifact), executable_relative="App.exe")
    assert not (tmp_path / "stage").exists()
    assert not (tmp_path / "escape.exe").exists()


def test_rejects_symlink_entries(tmp_path: Path):
    artifact = tmp_path / "link.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        link = zipfile.ZipInfo("App.exe")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target.exe")
    with pytest.raises(StagingError, match="links"):
        stage_verified_zip(artifact, tmp_path / "stage", _policy(artifact), executable_relative="App.exe")


def test_rejects_package_without_expected_executable(tmp_path: Path):
    artifact = tmp_path / "missing.zip"
    _zip(artifact, {"Other.exe": b"new"})
    with pytest.raises(StagingError, match="omits expected executable"):
        stage_verified_zip(artifact, tmp_path / "stage", _policy(artifact), executable_relative="App.exe")


def test_rejects_hash_or_size_mismatch_before_extraction(tmp_path: Path):
    artifact = tmp_path / "update.zip"
    _zip(artifact, {"App.exe": b"new"})
    policy = _policy(artifact)
    broken = SignedUpdatePolicy(**{**policy.__dict__, "artifact_sha256": "0" * 64})
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        stage_verified_zip(artifact, tmp_path / "stage", broken, executable_relative="App.exe")
