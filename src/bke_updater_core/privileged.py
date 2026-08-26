from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class PrivilegedRequestError(ValueError):
    pass


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PrivilegedRequestError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PrivilegedRequestError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise PrivilegedRequestError(f"invalid {field}")
    return parsed.astimezone(timezone.utc)


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PrivilegedRequestError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class PrivilegedUpdateRequest:
    raw: dict[str, object]
    request_id: str
    product_id: str
    current_version: str
    target_version: str
    platform: str
    architecture: str
    install_root: str
    entry_point: str
    artifact_sha256: str
    artifact_size: int
    update_policy_sha256: str
    target_policy_sha256: str
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str


class FileReplayGuard:
    """Atomically consume helper request IDs in an elevated helper-owned directory."""

    def __init__(self, root: Path):
        self.root = root

    def consume(self, request_id: str) -> bool:
        if re.fullmatch(r"[A-Za-z0-9_.-]{16,128}", request_id) is None:
            return False
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / request_id
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        try:
            os.write(fd, b"consumed\n")
        finally:
            os.close(fd)
        return True


class PrivilegedRequestVerifier:
    """Verify an Agent-authorized, short-lived, single-use helper request.

    This request is an additional local authority boundary. It does not replace
    verification of the Digital-signed update policy, the BKE-signed target
    policy, or the exact update artifact at the elevated helper boundary.
    """

    _required = {
        "schema", "request_id", "product_id", "current_version", "target_version",
        "platform", "architecture", "install_root", "entry_point",
        "artifact_sha256", "artifact_size", "update_policy_sha256",
        "target_policy_sha256", "issued_at", "expires_at", "signing_key_id",
        "algorithm", "signature",
    }

    def __init__(
        self,
        trusted_agent_keys: dict[str, bytes],
        *,
        consume_request_id: Callable[[str], bool],
        clock: Callable[[], datetime] | None = None,
        maximum_lifetime_seconds: int = 300,
        maximum_future_skew_seconds: int = 30,
    ):
        self.trusted_agent_keys = trusted_agent_keys
        self.consume_request_id = consume_request_id
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.maximum_lifetime_seconds = maximum_lifetime_seconds
        self.maximum_future_skew_seconds = maximum_future_skew_seconds

    def verify(self, document: dict[str, object]) -> PrivilegedUpdateRequest:
        if set(document) != self._required:
            raise PrivilegedRequestError("unsupported privileged request contract")
        if document.get("schema") != "bke.privileged-update-request.v1" or document.get("algorithm") != "Ed25519":
            raise PrivilegedRequestError("unsupported privileged request contract")

        strings = (
            "request_id", "product_id", "current_version", "target_version", "platform",
            "architecture", "install_root", "entry_point", "signing_key_id",
        )
        for field in strings:
            value = document.get(field)
            if not isinstance(value, str) or not value or len(value) > 1024:
                raise PrivilegedRequestError(f"invalid {field}")
        request_id = str(document["request_id"])
        if re.fullmatch(r"[A-Za-z0-9_.-]{16,128}", request_id) is None:
            raise PrivilegedRequestError("invalid request_id")

        artifact_sha256 = _sha256(document.get("artifact_sha256"), "artifact_sha256")
        update_policy_sha256 = _sha256(document.get("update_policy_sha256"), "update_policy_sha256")
        target_policy_sha256 = _sha256(document.get("target_policy_sha256"), "target_policy_sha256")
        artifact_size = document.get("artifact_size")
        if not isinstance(artifact_size, int) or isinstance(artifact_size, bool) or artifact_size < 0:
            raise PrivilegedRequestError("invalid artifact_size")

        issued_at = _parse_time(document.get("issued_at"), "issued_at")
        expires_at = _parse_time(document.get("expires_at"), "expires_at")
        lifetime = (expires_at - issued_at).total_seconds()
        if lifetime <= 0 or lifetime > self.maximum_lifetime_seconds:
            raise PrivilegedRequestError("invalid request lifetime")
        now = self.clock().astimezone(timezone.utc)
        if (issued_at - now).total_seconds() > self.maximum_future_skew_seconds:
            raise PrivilegedRequestError("request issued in the future")
        if now >= expires_at:
            raise PrivilegedRequestError("privileged request expired")

        key_id = str(document["signing_key_id"])
        key = self.trusted_agent_keys.get(key_id)
        if key is None:
            raise PrivilegedRequestError("unknown Agent signing key")
        unsigned = {key_name: value for key_name, value in document.items() if key_name != "signature"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        signature = document.get("signature")
        if not isinstance(signature, str):
            raise PrivilegedRequestError("invalid privileged request signature")
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(signature, validate=True), canonical)
        except Exception as exc:
            raise PrivilegedRequestError("invalid privileged request signature") from exc

        if not self.consume_request_id(request_id):
            raise PrivilegedRequestError("privileged request already consumed")

        return PrivilegedUpdateRequest(
            raw=document,
            request_id=request_id,
            product_id=str(document["product_id"]),
            current_version=str(document["current_version"]),
            target_version=str(document["target_version"]),
            platform=str(document["platform"]),
            architecture=str(document["architecture"]),
            install_root=str(document["install_root"]),
            entry_point=str(document["entry_point"]),
            artifact_sha256=artifact_sha256,
            artifact_size=artifact_size,
            update_policy_sha256=update_policy_sha256,
            target_policy_sha256=target_policy_sha256,
            issued_at=issued_at,
            expires_at=expires_at,
            signing_key_id=key_id,
        )
