from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .privileged import FileReplayGuard, PrivilegedRequestVerifier
from .privileged_entrypoint import PrivilegedExecutionConfig
from .target_policy import TargetPolicyVerifier
from .verifier import PolicyVerifier


class TrustedRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class TrustedRuntimePaths:
    root: Path
    trust_file: Path
    replay_root: Path

    @classmethod
    def under(cls, root: Path) -> "TrustedRuntimePaths":
        resolved = root.resolve()
        return cls(resolved, resolved / "trust.json", resolved / "replay")


def _decode_keys(value: object, field: str) -> dict[str, bytes]:
    if not isinstance(value, dict) or not value:
        raise TrustedRuntimeError(f"invalid {field}")
    result: dict[str, bytes] = {}
    for key_id, encoded in value.items():
        if not isinstance(key_id, str) or not key_id or not isinstance(encoded, str):
            raise TrustedRuntimeError(f"invalid {field}")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise TrustedRuntimeError(f"invalid {field}") from exc
        if len(raw) != 32:
            raise TrustedRuntimeError(f"invalid {field}")
        result[key_id] = raw
    return result


def _assert_private_runtime_path(path: Path) -> None:
    if not path.is_absolute():
        raise TrustedRuntimeError("trusted runtime root must be absolute")
    if os.name != "nt":
        mode = path.stat().st_mode & 0o777
        if mode & 0o022:
            raise TrustedRuntimeError("trusted runtime root is writable by group or others")


def load_privileged_execution_config(
    paths: TrustedRuntimePaths,
    *,
    staged_root: Path,
    backup_root: Path,
    transaction_id: str,
    current_pid: int | None = None,
) -> PrivilegedExecutionConfig:
    """Load helper-owned trust anchors; invocation supplies no signing authority."""
    _assert_private_runtime_path(paths.root)
    try:
        document = json.loads(paths.trust_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedRuntimeError("trusted runtime configuration unavailable") from exc
    if not isinstance(document, dict) or document.get("schema") != "bke.updater-trust.v1":
        raise TrustedRuntimeError("unsupported trusted runtime configuration")

    agent_keys = _decode_keys(document.get("agent_keys"), "agent_keys")
    digital_keys = _decode_keys(document.get("digital_keys"), "digital_keys")
    target_keys = _decode_keys(document.get("target_keys"), "target_keys")
    approved_roots = document.get("approved_install_roots")
    allowed_channels = document.get("allowed_channels")
    if not isinstance(approved_roots, list) or not approved_roots or not all(isinstance(v, str) and v for v in approved_roots):
        raise TrustedRuntimeError("invalid approved_install_roots")
    if not isinstance(allowed_channels, list) or not allowed_channels or not all(isinstance(v, str) and v for v in allowed_channels):
        raise TrustedRuntimeError("invalid allowed_channels")

    replay = FileReplayGuard(paths.replay_root)
    return PrivilegedExecutionConfig(
        request_verifier=PrivilegedRequestVerifier(agent_keys, consume_request_id=replay.consume),
        update_policy_verifier=PolicyVerifier(digital_keys),
        target_policy_verifier=TargetPolicyVerifier(target_keys, approved_install_roots=tuple(approved_roots)),
        staged_root=staged_root,
        backup_root=backup_root,
        transaction_id=transaction_id,
        allowed_channels=frozenset(allowed_channels),
        current_pid=current_pid,
    )
