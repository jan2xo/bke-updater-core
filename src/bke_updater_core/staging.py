from __future__ import annotations

import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .executor import verify_artifact
from .models import SignedUpdatePolicy


class StagingError(ValueError):
    pass


def _safe_member(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or path.is_absolute() or ".." in path.parts:
        raise StagingError("archive member escapes staged root")
    if any(part in {"", "."} for part in path.parts):
        raise StagingError("archive member path is not canonical")
    return path


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def stage_verified_zip(
    artifact: Path,
    destination: Path,
    policy: SignedUpdatePolicy,
    *,
    executable_relative: str,
    max_files: int = 10_000,
    max_expanded_size: int = 2 * 1024 * 1024 * 1024,
) -> Path:
    """Verify a signed update artifact and expand a safe staged application tree.

    The package is data, never an executable installer. Archive entries are rooted at
    the future installation root. Links, traversal, duplicate paths, oversized
    archives, and packages that omit the expected executable are rejected.
    """
    verify_artifact(artifact, policy.artifact_sha256, policy.artifact_size)
    expected_executable = _safe_member(executable_relative)
    if destination.exists():
        raise StagingError("staged destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".bke-stage-", dir=destination.parent))
    seen: set[PurePosixPath] = set()
    expanded = 0
    files = 0
    try:
        with zipfile.ZipFile(artifact, "r") as archive:
            for info in archive.infolist():
                member = _safe_member(info.filename.rstrip("/")) if info.is_dir() else _safe_member(info.filename)
                if member in seen:
                    raise StagingError("duplicate archive member")
                seen.add(member)
                if _is_symlink(info):
                    raise StagingError("archive links are not allowed")
                target = temporary.joinpath(*member.parts)
                resolved_parent = target.parent.resolve()
                if os.path.commonpath((str(temporary.resolve()), str(resolved_parent))) != str(temporary.resolve()):
                    raise StagingError("archive member escapes staged root")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                files += 1
                if files > max_files:
                    raise StagingError("archive contains too many files")
                expanded += info.file_size
                if info.file_size < 0 or expanded > max_expanded_size:
                    raise StagingError("archive expanded size exceeds limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        executable = temporary.joinpath(*expected_executable.parts)
        if not executable.is_file():
            raise StagingError("staged package omits expected executable")
        os.replace(temporary, destination)
        return destination
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
