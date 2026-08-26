from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bke_updater_core.authority import AuthorityCompositionError, compose_authority
from bke_updater_core.models import SignedUpdatePolicy
from bke_updater_core.privileged import PrivilegedUpdateRequest
from bke_updater_core.target_policy import TargetInstallPolicy


def _sha(document: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _policy(artifact: bytes) -> SignedUpdatePolicy:
    raw = {
        "schema": "bke.update-policy.v1",
        "product_id": "bke-air-stack",
        "current_version": "1.0.0",
        "latest_version": "2.0.0",
        "minimum_supported_version": "1.0.0",
        "channel": "stable",
        "platform": "windows",
        "architecture": "x64",
        "release_id": "release-123",
        "artifact_id": "artifact-123",
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "artifact_size": len(artifact),
        "content_type": "application/vnd.bke.update-package+zip",
        "published_at": "2026-08-26T00:00:00Z",
        "issued_at": "2026-08-26T00:00:00Z",
        "revision": 7,
        "signing_key_id": "digital-v1",
        "algorithm": "Ed25519",
        "signature": "sig",
    }
    return SignedUpdatePolicy(raw=raw, **raw)


def _target() -> TargetInstallPolicy:
    raw = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "air-stack-win-x64",
        "revision": 3,
        "product_id": "bke-air-stack",
        "platform": "windows",
        "architecture": "x64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\Air Stack",
        "entry_point": "BKE AirStack.exe",
        "signing_key_id": "bke-target-v1",
        "algorithm": "Ed25519",
        "signature": "sig",
    }
    from bke_updater_core.target_policy import target_policy_sha256
    return TargetInstallPolicy(raw=raw, policy_id="air-stack-win-x64", revision=3, product_id="bke-air-stack", platform="windows", architecture="x64", install_root=raw["install_root"], entry_point=raw["entry_point"], signing_key_id="bke-target-v1", policy_sha256=target_policy_sha256(raw))


def _request(policy: SignedUpdatePolicy, target: TargetInstallPolicy) -> PrivilegedUpdateRequest:
    now = datetime(2026, 8, 26, tzinfo=timezone.utc)
    return PrivilegedUpdateRequest(
        raw={}, request_id="request-1234567890", product_id="bke-air-stack",
        current_version="1.0.0", target_version="2.0.0", platform="windows", architecture="x64",
        install_root=target.install_root, entry_point=target.entry_point,
        artifact_sha256=policy.artifact_sha256, artifact_size=policy.artifact_size,
        update_policy_sha256=_sha(policy.raw), target_policy_sha256=target.policy_sha256,
        issued_at=now, expires_at=now, signing_key_id="agent-v1",
    )


def test_compose_authority_accepts_all_matching_authorities(tmp_path: Path):
    artifact = b"verified updater payload"
    path = tmp_path / "update.zip"
    path.write_bytes(artifact)
    policy = _policy(artifact)
    target = _target()
    authorized = compose_authority(_request(policy, target), policy, target, path)
    assert authorized.product_id == "bke-air-stack"
    assert authorized.target_version == "2.0.0"
    assert authorized.entry_point.name == "BKE AirStack.exe"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("product_id", "other-product", "product identity mismatch"),
        ("target_version", "9.9.9", "target version mismatch"),
        ("architecture", "arm64", "architecture mismatch"),
        ("install_root", r"C:\Program Files\BKE Digital Solutions\Elsewhere", "install root mismatch"),
        ("entry_point", "evil.exe", "entry point mismatch"),
        ("artifact_sha256", "0" * 64, "artifact hash mismatch"),
        ("artifact_size", 9999, "artifact size mismatch"),
        ("update_policy_sha256", "0" * 64, "update policy hash mismatch"),
        ("target_policy_sha256", "0" * 64, "target policy hash mismatch"),
    ],
)
def test_compose_authority_rejects_cross_authority_mismatch(tmp_path: Path, field: str, value: object, message: str):
    artifact = b"verified updater payload"
    path = tmp_path / "update.zip"
    path.write_bytes(artifact)
    policy = _policy(artifact)
    target = _target()
    request = _request(policy, target)
    changed = PrivilegedUpdateRequest(**{**request.__dict__, field: value})
    with pytest.raises(AuthorityCompositionError, match=message):
        compose_authority(changed, policy, target, path)


def test_compose_authority_rejects_tampered_artifact(tmp_path: Path):
    expected = b"verified updater payload"
    path = tmp_path / "update.zip"
    path.write_bytes(b"tampered updater payload")
    policy = _policy(expected)
    target = _target()
    with pytest.raises(Exception, match="artifact"):
        compose_authority(_request(policy, target), policy, target, path)
