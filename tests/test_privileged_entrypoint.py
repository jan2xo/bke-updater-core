from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import bke_updater_core.privileged_entrypoint as entrypoint
from bke_updater_core.privileged_entrypoint import PrivilegedExecutionConfig


def _config(tmp_path: Path) -> PrivilegedExecutionConfig:
    return PrivilegedExecutionConfig(
        trusted_agent_keys={"agent": b"a" * 32},
        trusted_digital_keys={"digital": b"d" * 32},
        trusted_bke_keys={"bke": b"b" * 32},
        approved_roots=(r"C:\Program Files\BKE Digital Solutions",),
        expected_channel="stable",
        replay_root=tmp_path / "replay",
        last_update_policy_revision=7,
        last_target_policy_revision=3,
    )


def test_privileged_entrypoint_does_not_accept_install_authority_arguments():
    parameters = inspect.signature(entrypoint.execute_privileged_update).parameters
    assert "install_root" not in parameters
    assert "executable" not in parameters
    assert "entry_point" not in parameters


def test_privileged_entrypoint_verifies_all_authorities_before_replacement(monkeypatch, tmp_path: Path):
    calls: list[object] = []
    request = SimpleNamespace(product_id="bke-air-stack", platform="windows", architecture="x64")
    update = object()
    target = object()
    authorized = object()
    plan = object()

    class RequestVerifier:
        def __init__(self, trusted_keys, *, consume_request_id):
            calls.append(("request-config", trusted_keys, callable(consume_request_id)))
        def verify(self, document):
            calls.append(("request", document))
            return request

    class UpdateVerifier:
        def __init__(self, trusted_keys):
            calls.append(("update-config", trusted_keys))
        def verify(self, document, **kwargs):
            calls.append(("update", document, kwargs))
            return update

    class TargetVerifier:
        def __init__(self, trusted_keys, *, approved_roots):
            calls.append(("target-config", trusted_keys, approved_roots))
        def verify(self, document, **kwargs):
            calls.append(("target", document, kwargs))
            return target

    monkeypatch.setattr(entrypoint, "PrivilegedRequestVerifier", RequestVerifier)
    monkeypatch.setattr(entrypoint, "PolicyVerifier", UpdateVerifier)
    monkeypatch.setattr(entrypoint, "TargetInstallPolicyVerifier", TargetVerifier)
    monkeypatch.setattr(entrypoint, "compose_authority", lambda *args: calls.append(("authority", args)) or authorized)
    monkeypatch.setattr(entrypoint, "compose_helper_plan", lambda value, **kwargs: calls.append(("plan", value, kwargs)) or plan)
    monkeypatch.setattr(entrypoint, "replace_and_launch", lambda value, pid: calls.append(("replace", value, pid)) or 0)

    result = entrypoint.execute_privileged_update(
        config=_config(tmp_path),
        request_document={"request": True},
        update_policy_document={"update": True},
        target_policy_document={"target": True},
        artifact_path=tmp_path / "artifact.zip",
        staged_root=tmp_path / "stage",
        backup_root=tmp_path / "backup",
        wait_pid=42,
    )

    assert result == 0
    update_call = next(call for call in calls if call[0] == "update")
    assert update_call[2] == {
        "product_id": "bke-air-stack",
        "platform": "windows",
        "architecture": "x64",
        "channel": "stable",
        "last_revision": 7,
    }
    target_call = next(call for call in calls if call[0] == "target")
    assert target_call[2] == {"last_revision": 3}
    assert [call[0] for call in calls if call[0] in {"request", "update", "target", "authority", "plan", "replace"}] == [
        "request", "update", "target", "authority", "plan", "replace"
    ]


def test_privileged_entrypoint_fails_before_replacement_on_policy_error(monkeypatch, tmp_path: Path):
    request = SimpleNamespace(product_id="bke-air-stack", platform="windows", architecture="x64")

    class RequestVerifier:
        def __init__(self, *args, **kwargs): pass
        def verify(self, document): return request

    class RejectingUpdateVerifier:
        def __init__(self, *args, **kwargs): pass
        def verify(self, document, **kwargs): raise ValueError("bad policy")

    monkeypatch.setattr(entrypoint, "PrivilegedRequestVerifier", RequestVerifier)
    monkeypatch.setattr(entrypoint, "PolicyVerifier", RejectingUpdateVerifier)
    monkeypatch.setattr(entrypoint, "replace_and_launch", lambda *args, **kwargs: pytest.fail("replacement must not execute"))

    with pytest.raises(ValueError, match="bad policy"):
        entrypoint.execute_privileged_update(
            config=_config(tmp_path),
            request_document={},
            update_policy_document={},
            target_policy_document={},
            artifact_path=tmp_path / "artifact.zip",
            staged_root=tmp_path / "stage",
            backup_root=tmp_path / "backup",
        )
