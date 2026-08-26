from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import re
from dataclasses import dataclass
from pathlib import PureWindowsPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class TargetPolicyError(ValueError):
    pass


def _canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def target_policy_sha256(document: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _windows_absolute(path: object, field: str) -> str:
    if not isinstance(path, str) or not path or len(path) > 1024:
        raise TargetPolicyError(f"invalid {field}")
    normalized = ntpath.normpath(path.replace("/", "\\"))
    parsed = PureWindowsPath(normalized)
    if not parsed.is_absolute() or not parsed.drive or parsed.root != "\\":
        raise TargetPolicyError(f"invalid {field}")
    if any(part in {".", ".."} for part in parsed.parts):
        raise TargetPolicyError(f"invalid {field}")
    return str(parsed)


def _relative_entry_point(path: object) -> str:
    if not isinstance(path, str) or not path or len(path) > 512:
        raise TargetPolicyError("invalid entry_point")
    normalized = path.replace("/", "\\")
    parsed = PureWindowsPath(normalized)
    if parsed.is_absolute() or parsed.drive or any(part in {"", ".", ".."} for part in parsed.parts):
        raise TargetPolicyError("invalid entry_point")
    return str(parsed)


def _under(root: str, child: str) -> bool:
    try:
        return ntpath.commonpath((ntpath.normcase(root), ntpath.normcase(child))) == ntpath.normcase(root)
    except ValueError:
        return False


@dataclass(frozen=True)
class TargetInstallPolicy:
    raw: dict[str, object]
    policy_id: str
    revision: int
    product_id: str
    platform: str
    architecture: str
    install_root: str
    entry_point: str
    signing_key_id: str
    policy_sha256: str


class TargetInstallPolicyVerifier:
    """Verify BKE-owned constraints for privileged installation targets.

    The policy answers only where a named BKE product may be replaced. It does not
    authorize an update by itself; the elevated helper must also verify the
    Digital-signed update policy, Agent-signed privileged request, and artifact.
    """

    _required = {
        "schema", "policy_id", "revision", "product_id", "platform", "architecture",
        "install_root", "entry_point", "signing_key_id", "algorithm", "signature",
    }

    def __init__(self, trusted_bke_keys: dict[str, bytes], *, approved_roots: tuple[str, ...]):
        self.trusted_bke_keys = trusted_bke_keys
        self.approved_roots = tuple(_windows_absolute(root, "approved_root") for root in approved_roots)
        if not self.approved_roots:
            raise TargetPolicyError("approved roots are required")

    def verify(self, document: dict[str, object], *, last_revision: int | None = None) -> TargetInstallPolicy:
        if set(document) != self._required:
            raise TargetPolicyError("unsupported target policy contract")
        if document.get("schema") != "bke.install-target-policy.v1" or document.get("algorithm") != "Ed25519":
            raise TargetPolicyError("unsupported target policy contract")

        for field in ("policy_id", "product_id", "platform", "architecture", "signing_key_id"):
            value = document.get(field)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise TargetPolicyError(f"invalid {field}")
        policy_id = str(document["policy_id"])
        if re.fullmatch(r"[A-Za-z0-9_.-]{8,128}", policy_id) is None:
            raise TargetPolicyError("invalid policy_id")
        revision = document.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise TargetPolicyError("invalid revision")
        if last_revision is not None and revision <= last_revision:
            raise TargetPolicyError("stale target policy")
        if document["platform"] != "windows":
            raise TargetPolicyError("target policy is not for Windows")

        install_root = _windows_absolute(document.get("install_root"), "install_root")
        if not any(_under(root, install_root) for root in self.approved_roots):
            raise TargetPolicyError("install root is outside approved BKE roots")
        entry_point = _relative_entry_point(document.get("entry_point"))
        executable = str(PureWindowsPath(install_root) / PureWindowsPath(entry_point))
        if not _under(install_root, executable):
            raise TargetPolicyError("entry point escapes install root")

        key_id = str(document["signing_key_id"])
        key = self.trusted_bke_keys.get(key_id)
        if key is None:
            raise TargetPolicyError("unknown BKE signing key")
        signature = document.get("signature")
        if not isinstance(signature, str):
            raise TargetPolicyError("invalid target policy signature")
        unsigned = {name: value for name, value in document.items() if name != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(signature, validate=True), _canonical(unsigned))
        except Exception as exc:
            raise TargetPolicyError("invalid target policy signature") from exc

        return TargetInstallPolicy(
            raw=document,
            policy_id=policy_id,
            revision=revision,
            product_id=str(document["product_id"]),
            platform="windows",
            architecture=str(document["architecture"]),
            install_root=install_root,
            entry_point=entry_point,
            signing_key_id=key_id,
            policy_sha256=target_policy_sha256(document),
        )
