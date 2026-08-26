from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .authority import AuthorizedUpdate, compose_authority
from .helper.composition import compose_helper_plan
from .helper.main import replace_and_launch
from .privileged import FileReplayGuard, PrivilegedRequestVerifier
from .target_policy import TargetInstallPolicyVerifier
from .verifier import PolicyVerifier


@dataclass(frozen=True)
class PrivilegedExecutionConfig:
    """Trusted, helper-owned configuration for privileged update execution.

    These values must be provisioned by the installed BKE runtime, not supplied by
    an unprivileged application invocation. Key provisioning/protection is a
    separate deployment concern; this object is the boundary consumed by the
    privileged runtime once that trusted configuration has been loaded.
    """

    trusted_agent_keys: dict[str, bytes]
    trusted_digital_keys: dict[str, bytes]
    trusted_bke_keys: dict[str, bytes]
    approved_roots: tuple[str, ...]
    expected_channel: str
    replay_root: Path
    last_update_policy_revision: int | None = None
    last_target_policy_revision: int | None = None


def execute_privileged_update(
    *,
    config: PrivilegedExecutionConfig,
    request_document: dict[str, object],
    update_policy_document: dict[str, object],
    target_policy_document: dict[str, object],
    artifact_path: Path,
    staged_root: Path,
    backup_root: Path,
    transaction_root: Path | None = None,
    transaction_id: str | None = None,
    wait_pid: int | None = None,
    launch_args: tuple[str, ...] = (),
    ready_marker: str | None = None,
    startup_timeout: float = 10.0,
) -> int:
    """Verify every authority inside the privileged boundary, then replace.

    Installation root and executable identity are never accepted as invocation
    arguments here. They are derived from the signed Agent request, Digital update
    policy, and BKE target policy after all three authorities agree.
    """

    request = PrivilegedRequestVerifier(
        config.trusted_agent_keys,
        consume_request_id=FileReplayGuard(config.replay_root).consume,
    ).verify(request_document)

    update_policy = PolicyVerifier(config.trusted_digital_keys).verify(
        update_policy_document,
        product_id=request.product_id,
        platform=request.platform,
        architecture=request.architecture,
        channel=config.expected_channel,
        last_revision=config.last_update_policy_revision,
    )

    target_policy = TargetInstallPolicyVerifier(
        config.trusted_bke_keys,
        approved_roots=config.approved_roots,
    ).verify(
        target_policy_document,
        last_revision=config.last_target_policy_revision,
    )

    authorized: AuthorizedUpdate = compose_authority(
        request,
        update_policy,
        target_policy,
        artifact_path,
    )

    plan = compose_helper_plan(
        authorized,
        staged_root=staged_root,
        backup_root=backup_root,
        transaction_root=transaction_root,
        transaction_id=transaction_id,
        launch_args=launch_args,
        ready_marker=ready_marker,
        startup_timeout=startup_timeout,
    )
    return replace_and_launch(plan, wait_pid)
