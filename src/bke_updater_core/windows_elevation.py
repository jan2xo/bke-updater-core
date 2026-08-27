from __future__ import annotations

import ctypes
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


class ElevationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PrivilegedInvocationFiles:
    runtime_root: Path
    request_document: Path
    update_policy_document: Path
    target_policy_document: Path
    artifact_path: Path
    staged_root: Path
    backup_root: Path
    transaction_root: Path | None = None


def _resolve_under(root: Path, value: Path, field: str, *, must_exist: bool = True) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = value.resolve(strict=must_exist)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ElevationError(f"{field} must be inside the helper-owned runtime root") from exc
    return resolved


def validate_invocation_files(files: PrivilegedInvocationFiles) -> PrivilegedInvocationFiles:
    """Resolve only helper-owned ephemeral inputs before requesting elevation.

    Install root, entry point, trust-file selection, signing keys and release authority
    are deliberately absent from this contract. The elevated entrypoint loads the
    canonical `trust.json` from the helper-owned runtime root and derives authority
    from the signed documents.
    """

    root = files.runtime_root.resolve(strict=True)
    return PrivilegedInvocationFiles(
        runtime_root=root,
        request_document=_resolve_under(root, files.request_document, "request_document"),
        update_policy_document=_resolve_under(root, files.update_policy_document, "update_policy_document"),
        target_policy_document=_resolve_under(root, files.target_policy_document, "target_policy_document"),
        artifact_path=_resolve_under(root, files.artifact_path, "artifact_path"),
        staged_root=_resolve_under(root, files.staged_root, "staged_root"),
        backup_root=_resolve_under(root, files.backup_root, "backup_root", must_exist=False),
        transaction_root=(
            _resolve_under(root, files.transaction_root, "transaction_root", must_exist=False)
            if files.transaction_root is not None
            else None
        ),
    )


def build_elevated_command(
    helper_executable: Path,
    files: PrivilegedInvocationFiles,
    *,
    wait_pid: int | None = None,
) -> tuple[str, ...]:
    helper = helper_executable.resolve(strict=True)
    validated = validate_invocation_files(files)
    command = [
        str(helper),
        "--privileged-update",
        "--runtime-root", str(validated.runtime_root),
        "--request", str(validated.request_document),
        "--update-policy", str(validated.update_policy_document),
        "--target-policy", str(validated.target_policy_document),
        "--artifact", str(validated.artifact_path),
        "--staged-root", str(validated.staged_root),
        "--backup-root", str(validated.backup_root),
    ]
    if validated.transaction_root is not None:
        command.extend(("--transaction-root", str(validated.transaction_root)))
    if wait_pid is not None:
        if wait_pid <= 0:
            raise ElevationError("wait_pid must be positive")
        command.extend(("--wait-pid", str(wait_pid)))
    return tuple(command)


def request_windows_elevation(
    command: Sequence[str],
    *,
    shell_execute: Callable[[str, str], int] | None = None,
) -> None:
    """Request Windows UAC elevation with the `runas` verb."""

    if os.name != "nt" and shell_execute is None:
        raise ElevationError("Windows elevation is only available on Windows")
    if not command:
        raise ElevationError("empty elevated command")

    executable = str(command[0])
    parameters = subprocess.list2cmdline([str(value) for value in command[1:]])
    if shell_execute is None:
        result = int(ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, None, 1))
    else:
        result = int(shell_execute(executable, parameters))
    if result <= 32:
        raise ElevationError(f"Windows elevation request failed ({result})")


def read_json_document(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ElevationError(f"invalid JSON document: {path.name}") from exc
    if not isinstance(document, dict):
        raise ElevationError(f"invalid JSON document: {path.name}")
    return document
