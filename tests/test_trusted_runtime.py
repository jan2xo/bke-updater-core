from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from bke_updater_core.trusted_runtime import TrustedRuntimeError, TrustedRuntimePaths, load_privileged_execution_config


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def _write(root: Path, **overrides: object) -> TrustedRuntimePaths:
    root.mkdir(mode=0o700)
    doc: dict[str, object] = {
        "schema": "bke.updater-trust.v1",
        "agent_keys": {"agent-1": _key(1)},
        "digital_keys": {"digital-1": _key(2)},
        "target_keys": {"target-1": _key(3)},
        "approved_install_roots": [r"C:\\Program Files\\BKE Digital Solutions"],
        "allowed_channels": ["stable"],
    }
    doc.update(overrides)
    paths = TrustedRuntimePaths.under(root)
    paths.trust_file.write_text(json.dumps(doc), encoding="utf-8")
    return paths


def test_loads_all_authorities_from_helper_owned_trust_file(tmp_path: Path) -> None:
    paths = _write(tmp_path / "runtime")
    config = load_privileged_execution_config(
        paths,
        staged_root=tmp_path / "stage",
        backup_root=tmp_path / "backup",
        transaction_id="tx-1",
    )
    assert set(config.request_verifier.trusted_agent_keys) == {"agent-1"}
    assert set(config.update_policy_verifier.trusted_public_keys) == {"digital-1"}
    assert set(config.target_policy_verifier.trusted_bke_keys) == {"target-1"}
    assert config.allowed_channels == frozenset({"stable"})


def test_rejects_world_writable_runtime_root(tmp_path: Path) -> None:
    paths = _write(tmp_path / "runtime")
    paths.root.chmod(0o777)
    with pytest.raises(TrustedRuntimeError, match="writable"):
        load_privileged_execution_config(paths, staged_root=tmp_path / "s", backup_root=tmp_path / "b", transaction_id="tx")


def test_rejects_malformed_key_material(tmp_path: Path) -> None:
    paths = _write(tmp_path / "runtime", agent_keys={"agent-1": "not-base64"})
    with pytest.raises(TrustedRuntimeError, match="agent_keys"):
        load_privileged_execution_config(paths, staged_root=tmp_path / "s", backup_root=tmp_path / "b", transaction_id="tx")
