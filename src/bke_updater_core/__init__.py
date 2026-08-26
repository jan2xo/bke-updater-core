"""Product-agnostic verified update transactions."""
from .models import Decision, ProductManifest, SignedUpdatePolicy, UpdatePlan, TransactionState
from .policy import decide_update
from .verifier import PolicyVerifier, VerificationError
from .executor import ArtifactError, replace_transaction, verify_artifact
from .staging import StagingError, stage_verified_zip
from .privileged import FileReplayGuard, PrivilegedRequestError, PrivilegedRequestVerifier, PrivilegedUpdateRequest
from .target_policy import TargetInstallPolicy, TargetInstallPolicyVerifier, TargetPolicyError, target_policy_sha256
from .authority import AuthorizedUpdate, AuthorityCompositionError, compose_authority
from .privileged_entrypoint import PrivilegedExecutionConfig, execute_privileged_update

__all__ = [
    "Decision",
    "ProductManifest",
    "SignedUpdatePolicy",
    "UpdatePlan",
    "TransactionState",
    "decide_update",
    "PolicyVerifier",
    "VerificationError",
    "ArtifactError",
    "replace_transaction",
    "verify_artifact",
    "StagingError",
    "stage_verified_zip",
    "FileReplayGuard",
    "PrivilegedRequestError",
    "PrivilegedRequestVerifier",
    "PrivilegedUpdateRequest",
    "TargetInstallPolicy",
    "TargetInstallPolicyVerifier",
    "TargetPolicyError",
    "target_policy_sha256",
    "AuthorizedUpdate",
    "AuthorityCompositionError",
    "compose_authority",
    "PrivilegedExecutionConfig",
    "execute_privileged_update",
]
