from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.privileged import FileReplayGuard, PrivilegedRequestError, PrivilegedRequestVerifier


def _document(private: Ed25519PrivateKey, *, now: datetime, request_id: str = "request-0123456789", **changes):
    unsigned = {
        "schema": "bke.privileged-update-request.v1",
        "request_id": request_id,
        "product_id": "bke-air-stack",
        "current_version": "1.0.0",
        "target_version": "1.1.0",
        "platform": "windows",
        "architecture": "x64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\Air Stack",
        "entry_point": "BKE AirStack.exe",
        "artifact_sha256": "a" * 64,
        "artifact_size": 1234,
        "update_policy_sha256": "b" * 64,
        "target_policy_sha256": "c" * 64,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "signing_key_id": "agent-local-v1",
        "algorithm": "Ed25519",
    }
    unsigned.update(changes)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**unsigned, "signature": base64.b64encode(private.sign(canonical)).decode()}


def test_privileged_request_is_signed_short_lived_and_single_use(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    now = datetime(2026, 8, 26, 7, 15, tzinfo=timezone.utc)
    guard = FileReplayGuard(tmp_path / "consumed")
    verifier = PrivilegedRequestVerifier(
        {"agent-local-v1": private.public_key().public_bytes_raw()},
        consume_request_id=guard.consume,
        clock=lambda: now,
    )
    document = _document(private, now=now)
    verified = verifier.verify(document)
    assert verified.product_id == "bke-air-stack"
    assert verified.target_version == "1.1.0"
    assert (tmp_path / "consumed" / verified.request_id).is_file()
    with pytest.raises(PrivilegedRequestError, match="already consumed"):
        verifier.verify(document)


def test_tampering_and_unknown_agent_key_fail_closed(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    now = datetime(2026, 8, 26, 7, 15, tzinfo=timezone.utc)
    document = _document(private, now=now)
    verifier = PrivilegedRequestVerifier(
        {"agent-local-v1": private.public_key().public_bytes_raw()},
        consume_request_id=FileReplayGuard(tmp_path / "consumed").consume,
        clock=lambda: now,
    )
    tampered = {**document, "install_root": r"C:\Windows\System32"}
    with pytest.raises(PrivilegedRequestError, match="signature"):
        verifier.verify(tampered)
    unknown = PrivilegedRequestVerifier(
        {}, consume_request_id=lambda _: True, clock=lambda: now,
    )
    with pytest.raises(PrivilegedRequestError, match="unknown Agent signing key"):
        unknown.verify(document)


def test_expiry_future_issue_and_long_lifetime_are_rejected():
    private = Ed25519PrivateKey.generate()
    now = datetime(2026, 8, 26, 7, 15, tzinfo=timezone.utc)
    verifier = PrivilegedRequestVerifier(
        {"agent-local-v1": private.public_key().public_bytes_raw()},
        consume_request_id=lambda _: True,
        clock=lambda: now,
    )
    expired = _document(
        private,
        now=now - timedelta(minutes=5),
        expires_at=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    )
    with pytest.raises(PrivilegedRequestError, match="expired"):
        verifier.verify(expired)
    future = _document(
        private,
        now=now + timedelta(minutes=1),
        expires_at=(now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
    )
    with pytest.raises(PrivilegedRequestError, match="future"):
        verifier.verify(future)
    long_lived = _document(
        private,
        now=now,
        expires_at=(now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    )
    with pytest.raises(PrivilegedRequestError, match="lifetime"):
        verifier.verify(long_lived)


def test_contract_shape_and_hashes_are_strict():
    private = Ed25519PrivateKey.generate()
    now = datetime(2026, 8, 26, 7, 15, tzinfo=timezone.utc)
    verifier = PrivilegedRequestVerifier(
        {"agent-local-v1": private.public_key().public_bytes_raw()},
        consume_request_id=lambda _: True,
        clock=lambda: now,
    )
    bad_hash = _document(private, now=now, artifact_sha256="not-a-hash")
    with pytest.raises(PrivilegedRequestError, match="artifact_sha256"):
        verifier.verify(bad_hash)
    extra = {**_document(private, now=now), "surprise": "field"}
    with pytest.raises(PrivilegedRequestError, match="contract"):
        verifier.verify(extra)
