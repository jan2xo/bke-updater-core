from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

from .models import TransactionState, UpdatePlan
from .transaction import TransactionError, UpdateTransaction


class ArtifactError(ValueError):
    pass


def verify_artifact(path: Path, expected_sha256: str, expected_size: int) -> None:
    if not path.is_file() or expected_size < 0:
        raise ArtifactError("invalid artifact")
    if path.stat().st_size != expected_size:
        raise ArtifactError("artifact size mismatch")
    if len(expected_sha256) != 64:
        raise ArtifactError("artifact hash mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest().lower() != expected_sha256.lower():
        raise ArtifactError("artifact hash mismatch")


def _validated_executable(plan: UpdatePlan) -> tuple[Path, Path]:
    root = plan.target_install_root.resolve()
    relative = plan.executable.relative_to(plan.target_install_root)
    if relative.is_absolute() or ".." in relative.parts:
        raise TransactionError("executable escapes install root")
    target = (root / relative).resolve()
    if os.path.commonpath((str(root), str(target))) != str(root):
        raise TransactionError("executable escapes install root")
    return root, target


def replace_transaction(plan: UpdatePlan, *, health_timeout: float = 10.0,
                        health_probe: Callable[[Path], bool] | None = None,
                        interruption: Callable[[TransactionState], None] | None = None) -> TransactionState:
    tx = UpdateTransaction(plan.target_install_root.parent / ".bke-transactions", plan)
    try:
        verify_artifact(plan.staged_artifact, plan.expected_sha256, plan.expected_size)
        tx.transition(TransactionState.VERIFIED)
        if interruption:
            interruption(TransactionState.VERIFIED)
        root, installed_executable = _validated_executable(plan)
        backup = plan.backup_path.resolve()
        if backup == root or root in backup.parents or backup in root.parents:
            raise TransactionError("unsafe backup root")
        if root.exists():
            if plan.backup_path.exists():
                shutil.rmtree(plan.backup_path)
            shutil.copytree(root, plan.backup_path)
        tx.transition(TransactionState.STAGED)
        if interruption:
            interruption(TransactionState.STAGED)
        tx.transition(TransactionState.REPLACING)
        if interruption:
            interruption(TransactionState.REPLACING)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        installed_executable.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(plan.staged_artifact, installed_executable)
        os.chmod(installed_executable, 0o755)
        tx.transition(TransactionState.VERIFYING)
        if interruption:
            interruption(TransactionState.VERIFYING)
        probe = health_probe or _default_health_probe
        deadline = time.monotonic() + health_timeout
        while time.monotonic() < deadline:
            if probe(installed_executable):
                tx.commit()
                return TransactionState.COMMITTED
            time.sleep(0.05)
        raise TransactionError("health check failed")
    except Exception as exc:
        try:
            tx.rollback(str(exc))
            return TransactionState.ROLLED_BACK
        except Exception as rollback_error:
            tx.transition(TransactionState.FAILED, reason=f"{exc}; rollback failed: {rollback_error}")
            return TransactionState.FAILED


def _default_health_probe(executable: Path) -> bool:
    completed = subprocess.run([str(executable), "--health"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
    return completed.returncode == 0
