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
    if not path.is_file():
        raise ArtifactError("artifact is not a file")
    if path.stat().st_size != expected_size:
        raise ArtifactError("artifact size mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise ArtifactError("artifact hash mismatch")


def replace_transaction(
    plan: UpdatePlan,
    *,
    health_timeout: float = 10.0,
    health_probe: Callable[[Path], bool] | None = None,
    interruption: Callable[[TransactionState], None] | None = None,
) -> TransactionState:
    tx = UpdateTransaction(plan.target_install_root.parent / ".bke-transactions", plan)
    try:
        verify_artifact(plan.staged_artifact, plan.expected_sha256, plan.expected_size)
        tx.transition(TransactionState.VERIFIED)
        if interruption:
            interruption(TransactionState.VERIFIED)
        if plan.target_install_root.exists():
            if plan.backup_path.exists():
                shutil.rmtree(plan.backup_path)
            shutil.copytree(plan.target_install_root, plan.backup_path)
        tx.transition(TransactionState.STAGED)
        if interruption:
            interruption(TransactionState.STAGED)
        tx.transition(TransactionState.REPLACING)
        if interruption:
            interruption(TransactionState.REPLACING)
        if plan.target_install_root.exists():
            shutil.rmtree(plan.target_install_root)
        plan.target_install_root.mkdir(parents=True)
        installed_executable = plan.target_install_root / plan.executable.name
        shutil.copy2(plan.staged_artifact, installed_executable)
        os.chmod(installed_executable, 0o755)
        tx.transition(TransactionState.VERIFYING)
        if interruption:
            interruption(TransactionState.VERIFYING)
        probe = health_probe or _default_health_probe
        deadline = time.monotonic() + health_timeout
        while time.monotonic() < deadline:
            if probe(plan.target_install_root / plan.executable.name):
                tx.commit()
                return TransactionState.COMMITTED
            time.sleep(0.05)
        raise TransactionError("health check failed")
    except Exception as exc:
        try:
            tx.rollback(str(exc))
        except Exception:
            tx.transition(TransactionState.FAILED, reason=str(exc))
        return TransactionState.ROLLED_BACK


def _default_health_probe(executable: Path) -> bool:
    completed = subprocess.run(
        [str(executable), "--health"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    return completed.returncode == 0
