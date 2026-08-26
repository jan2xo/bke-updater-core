from __future__ import annotations

import os
from pathlib import Path

from ..authority import AuthorizedUpdate
from .protocol import HelperPlan


class HelperCompositionError(ValueError):
    """Raised when helper-owned execution state cannot be safely composed."""


def _resolved_directory(path: Path, name: str) -> Path:
    value = path.expanduser().resolve()
    if not value.exists() or not value.is_dir() or value.parent == value:
        raise HelperCompositionError(f"invalid {name} root")
    return value


def _resolved_backup(path: Path) -> Path:
    value = path.expanduser().resolve()
    if value.parent == value or not value.parent.exists() or not value.parent.is_dir():
        raise HelperCompositionError("invalid backup root")
    return value


def _assert_distinct_non_overlapping(paths: tuple[Path, Path, Path]) -> None:
    if len(set(paths)) != len(paths):
        raise HelperCompositionError("helper roots must be distinct")
    for left, right in ((paths[0], paths[1]), (paths[0], paths[2]), (paths[1], paths[2])):
        if left in right.parents or right in left.parents:
            raise HelperCompositionError("helper roots overlap")


def compose_helper_plan(
    authorized: AuthorizedUpdate,
    *,
    staged_root: Path,
    backup_root: Path,
    transaction_root: Path | None = None,
    transaction_id: str | None = None,
    launch_args: tuple[str, ...] = (),
    ready_marker: str | None = None,
    startup_timeout: float = 10.0,
) -> HelperPlan:
    """Derive privileged replacement authority from a verified AuthorizedUpdate.

    The caller may choose only helper-owned ephemeral state. Installation root and
    executable identity are always derived from the already composed authorities.
    """
    install_root = authorized.install_root.expanduser().resolve()
    stage = _resolved_directory(staged_root, "stage")
    backup = _resolved_backup(backup_root)
    _assert_distinct_non_overlapping((install_root, stage, backup))

    entry_point = authorized.entry_point
    if entry_point.is_absolute():
        try:
            relative_entry = entry_point.relative_to(install_root)
        except ValueError as exc:
            raise HelperCompositionError("authorized entry point escapes install root") from exc
    else:
        relative_entry = entry_point

    if relative_entry == Path(".") or ".." in relative_entry.parts:
        raise HelperCompositionError("invalid authorized entry point")

    executable = (install_root / relative_entry).resolve()
    try:
        if os.path.commonpath((str(install_root), str(executable))) != str(install_root):
            raise HelperCompositionError("authorized entry point escapes install root")
    except ValueError as exc:
        raise HelperCompositionError("authorized entry point is on a different root") from exc

    staged_executable = (stage / relative_entry).resolve()
    try:
        if os.path.commonpath((str(stage), str(staged_executable))) != str(stage):
            raise HelperCompositionError("staged entry point escapes stage root")
    except ValueError as exc:
        raise HelperCompositionError("staged entry point is on a different root") from exc
    if not staged_executable.exists() or not staged_executable.is_file():
        raise HelperCompositionError("authorized staged executable is missing")

    return HelperPlan(
        install_root=install_root,
        staged_root=stage,
        backup_root=backup,
        executable=executable,
        transaction_root=transaction_root,
        transaction_id=transaction_id,
        launch_args=launch_args,
        ready_marker=ready_marker,
        startup_timeout=startup_timeout,
    )
