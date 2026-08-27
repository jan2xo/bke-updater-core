from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .privileged_entrypoint import PrivilegedExecutionConfig


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
    if not path.is_absolute() or not path.is_dir():
        raise TrustedRuntimeError("trusted runtime root must be an absolute directory")
    if os.name != "nt":
        mode = path.stat().st_mode & 0o777
        if mode & 0o022:
            raise TrustedRuntimeError("trusted runtime root is writable by group or others")


def load_privileged_execution_config(paths: TrustedRuntimePaths) -> PrivilegedExecutionConfig:
    """Load helper-owned trust anchors and policy from the installed runtime."""
    _assert_private_runtime_path(paths.root)
    try:
        document = json.loads(paths.trust_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedRuntimeError("trusted runtime configuration unavailable") from exc
    if not isinstance(document, dict) or document.get("schema") != "bke.updater-trust.v1":
        raise TrustedRuntimeError("unsupported trusted runtime configuration")

    agent_keys = _decode_keys(document.get("agent_keys"), "agent_keys")
    digital_keys = _decode_keys(document.get("digital_keys"), "digital_keys")
    bke_keys = _decode_keys(document.get("target_keys"), "target_keys")

    approved_roots = document.get("approved_install_roots")
    if (
        not isinstance(approved_roots, list)
        or not approved_roots
        or not all(isinstance(value, str) and value for value in approved_roots)
    ):
        raise TrustedRuntimeError("invalid approved_install_roots")

    expected_channel = document.get("expected_channel")
    if not isinstance(expected_channel, str) or not expected_channel:
        raise TrustedRuntimeError("invalid expected_channel")

    last_update_policy_revision = document.get("last_update_policy_revision")
    last_target_policy_revision = document.get("last_target_policy_revision")
    if last_update_policy_revision is not None and (
        not isinstance(last_update_policy_revision, int) or isinstance(last_update_policy_revision, bool)
    ):
        raise TrustedRuntimeError("invalid last_update_policy_revision")
    if last_target_policy_revision is not None and (
        not isinstance(last_target_policy_revision, int) or isinstance(last_target_policy_revision, bool)
    ):
        raise TrustedRuntimeError("invalid last_target_policy_revision")

    return PrivilegedExecutionConfig(
        trusted_agent_keys=agent_keys,
        trusted_digital_keys=digital_keys,
        trusted_bke_keys=bke_keys,
        approved_roots=tuple(approved_roots),
        expected_channel=expected_channel,
        replay_root=paths.replay_root,
        last_update_policy_revision=last_update_policy_revision,
        last_target_policy_revision=last_target_policy_revision,
    )
