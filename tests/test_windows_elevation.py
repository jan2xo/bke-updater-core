from pathlib import Path

import pytest

from bke_updater_core.windows_elevation import (
    ElevationError,
    PrivilegedInvocationFiles,
    build_elevated_command,
    request_windows_elevation,
    validate_invocation_files,
)


def _files(root: Path) -> PrivilegedInvocationFiles:
    for name in ("trust.json", "request.json", "update.json", "target.json", "artifact.bin"):
        (root / name).write_text("{}", encoding="utf-8")
    (root / "staged").mkdir()
    return PrivilegedInvocationFiles(
        runtime_root=root,
        request_document=root / "request.json",
        update_policy_document=root / "update.json",
        target_policy_document=root / "target.json",
        artifact_path=root / "artifact.bin",
        staged_root=root / "staged",
        backup_root=root / "backup",
        transaction_root=root / "transactions",
    )


def test_elevation_contract_exposes_no_install_authority(tmp_path: Path):
    files = _files(tmp_path)
    helper = tmp_path / "helper.exe"
    helper.write_text("helper", encoding="utf-8")

    command = build_elevated_command(helper, files, wait_pid=123)

    assert "--install-root" not in command
    assert "--entry-point" not in command
    assert "--trust-config" not in command
    assert "--trusted-agent-key" not in command
    assert "--trusted-digital-key" not in command
    assert "--trusted-bke-key" not in command
    assert command[0] == str(helper.resolve())
    assert "--privileged-update" in command
    assert command[-2:] == ("--wait-pid", "123")


def test_invocation_rejects_authority_documents_outside_runtime_root(tmp_path: Path):
    root = tmp_path / "runtime"
    root.mkdir()
    files = _files(root)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ElevationError, match="request_document"):
        validate_invocation_files(
            PrivilegedInvocationFiles(**{**files.__dict__, "request_document": outside})
        )


def test_uac_uses_runas_and_quotes_parameters(tmp_path: Path):
    root = tmp_path / "runtime with spaces"
    root.mkdir()
    files = _files(root)
    helper = root / "BKE Updater Helper.exe"
    helper.write_text("helper", encoding="utf-8")
    command = build_elevated_command(helper, files)
    calls: list[tuple[str, str]] = []

    request_windows_elevation(command, shell_execute=lambda exe, args: calls.append((exe, args)) or 42)

    assert calls[0][0] == str(helper.resolve())
    assert '"' in calls[0][1]
    assert "--install-root" not in calls[0][1]


def test_uac_failure_is_fail_closed():
    with pytest.raises(ElevationError, match="failed"):
        request_windows_elevation(("helper.exe", "--privileged-update"), shell_execute=lambda _exe, _args: 5)


def test_wait_pid_must_be_positive(tmp_path: Path):
    files = _files(tmp_path)
    helper = tmp_path / "helper.exe"
    helper.write_text("helper", encoding="utf-8")

    with pytest.raises(ElevationError, match="wait_pid"):
        build_elevated_command(helper, files, wait_pid=0)
