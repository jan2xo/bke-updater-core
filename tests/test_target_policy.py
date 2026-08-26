from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.target_policy import TargetInstallPolicyVerifier, TargetPolicyError, target_policy_sha256


def _policy(private: Ed25519PrivateKey, **overrides) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "air-stack-win-x64",
        "revision": 1,
        "product_id": "bke-air-stack",
        "platform": "windows",
        "architecture": "x64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\Air Stack",
        "entry_point": "BKE AirStack.exe",
        "signing_key_id": "bke-target-v1",
        "algorithm": "Ed25519",
    }
    unsigned.update(overrides)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**unsigned, "signature": base64.b64encode(private.sign(canonical)).decode()}


def _verifier(private: Ed25519PrivateKey) -> TargetInstallPolicyVerifier:
    return TargetInstallPolicyVerifier(
        {"bke-target-v1": private.public_key().public_bytes_raw()},
        approved_roots=(r"C:\Program Files\BKE Digital Solutions",),
    )


def test_accepts_signed_bke_target_inside_approved_root():
    private = Ed25519PrivateKey.generate()
    document = _policy(private)
    verified = _verifier(private).verify(document)
    assert verified.product_id == "bke-air-stack"
    assert verified.install_root.endswith(r"BKE Digital Solutions\Air Stack")
    assert verified.entry_point == "BKE AirStack.exe"
    assert verified.policy_sha256 == target_policy_sha256(document)


def test_rejects_tampering_unknown_key_and_stale_revision():
    private = Ed25519PrivateKey.generate()
    verifier = _verifier(private)
    document = _policy(private)
    tampered = {**document, "product_id": "attacker-product"}
    with pytest.raises(TargetPolicyError, match="signature"):
        verifier.verify(tampered)
    unknown = _policy(private, signing_key_id="unknown")
    with pytest.raises(TargetPolicyError, match="unknown BKE signing key"):
        verifier.verify(unknown)
    with pytest.raises(TargetPolicyError, match="stale"):
        verifier.verify(document, last_revision=1)


def test_rejects_outside_program_files_and_relative_or_cross_drive_roots():
    private = Ed25519PrivateKey.generate()
    verifier = _verifier(private)
    for root in (r"C:\Users\Public\Air Stack", r"..\Air Stack", r"D:\Program Files\BKE Digital Solutions\Air Stack"):
        with pytest.raises(TargetPolicyError):
            verifier.verify(_policy(private, install_root=root))


def test_rejects_entry_point_escape_and_wrong_platform():
    private = Ed25519PrivateKey.generate()
    verifier = _verifier(private)
    with pytest.raises(TargetPolicyError):
        verifier.verify(_policy(private, entry_point=r"..\evil.exe"))
    with pytest.raises(TargetPolicyError, match="not for Windows"):
        verifier.verify(_policy(private, platform="linux"))


def test_contract_shape_and_revision_are_strict():
    private = Ed25519PrivateKey.generate()
    verifier = _verifier(private)
    document = _policy(private)
    with pytest.raises(TargetPolicyError, match="unsupported"):
        verifier.verify({**document, "extra": True})
    with pytest.raises(TargetPolicyError, match="revision"):
        verifier.verify(_policy(private, revision=0))
