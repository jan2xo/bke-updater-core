from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .executor import verify_artifact
from .models import SignedUpdatePolicy
from .privileged import PrivilegedUpdateRequest
from .target_policy import TargetInstallPolicy


class AuthorityCompositionError(ValueError):
    pass


def _canonical_sha256(document: dict[str, object]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class AuthorizedUpdate:
    product_id: str
    current_version: str
    target_version: str
    platform: str
    architecture: str
    install_root: Path
    entry_point: Path
    artifact_sha256: str
    artifact_size: int


def compose_authority(
    request: PrivilegedUpdateRequest,
    update_policy: SignedUpdatePolicy,
    target_policy: TargetInstallPolicy,
    artifact_path: Path,
) -> AuthorizedUpdate:
    if request.product_id != update_policy.product_id or request.product_id != target_policy.product_id:
        raise AuthorityCompositionError("product identity mismatch")
    if request.current_version != update_policy.current_version:
        raise AuthorityCompositionError("current version mismatch")
    if request.target_version != update_policy.latest_version:
        raise AuthorityCompositionError("target version mismatch")
    if request.platform != update_policy.platform or request.platform != target_policy.platform:
        raise AuthorityCompositionError("platform mismatch")
    if request.architecture != update_policy.architecture or request.architecture != target_policy.architecture:
        raise AuthorityCompositionError("architecture mismatch")
    if request.install_root != target_policy.install_root:
        raise AuthorityCompositionError("install root mismatch")
    if request.entry_point != target_policy.entry_point:
        raise AuthorityCompositionError("entry point mismatch")
    if request.artifact_sha256.lower() != update_policy.artifact_sha256.lower():
        raise AuthorityCompositionError("artifact hash mismatch")
    if request.artifact_size != update_policy.artifact_size:
        raise AuthorityCompositionError("artifact size mismatch")
    if request.update_policy_sha256 != _canonical_sha256(update_policy.raw):
        raise AuthorityCompositionError("update policy hash mismatch")
    if request.target_policy_sha256 != target_policy.policy_sha256:
        raise AuthorityCompositionError("target policy hash mismatch")

    verify_artifact(artifact_path, request.artifact_sha256, request.artifact_size)

    install_root = Path(PureWindowsPath(target_policy.install_root))
    entry_point = Path(PureWindowsPath(target_policy.entry_point))
    return AuthorizedUpdate(
        product_id=request.product_id,
        current_version=request.current_version,
        target_version=request.target_version,
        platform=request.platform,
        architecture=request.architecture,
        install_root=install_root,
        entry_point=entry_point,
        artifact_sha256=request.artifact_sha256,
        artifact_size=request.artifact_size,
    )
