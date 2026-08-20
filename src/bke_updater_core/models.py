from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
class Decision(str,Enum):
    UP_TO_DATE="UP_TO_DATE"; UPDATE_AVAILABLE="UPDATE_AVAILABLE"; UPDATE_REQUIRED="UPDATE_REQUIRED"; UNSUPPORTED="UNSUPPORTED"
class TransactionState(str,Enum):
    CREATED="CREATED"; DOWNLOADING="DOWNLOADING"; VERIFIED="VERIFIED"; STAGED="STAGED"; WAITING_FOR_EXIT="WAITING_FOR_EXIT"; REPLACING="REPLACING"; VERIFYING="VERIFYING"; COMMITTED="COMMITTED"; ROLLING_BACK="ROLLING_BACK"; ROLLED_BACK="ROLLED_BACK"; FAILED="FAILED"
@dataclass(frozen=True)
class ProductManifest:
    product_id:str; version:str; platform:str; architecture:str; executable:str; install_root:Path; update_channel:str="stable"; health_check:str|None=None
@dataclass(frozen=True)
class SignedUpdatePolicy:
    schema:str; product_id:str; current_version:str; latest_version:str; minimum_supported_version:str; channel:str; platform:str; architecture:str; release_id:str; artifact_id:str; artifact_sha256:str; artifact_size:int; content_type:str; published_at:str; issued_at:str; revision:int; signing_key_id:str; algorithm:str; signature:str; raw:dict[str,Any]
@dataclass(frozen=True)
class UpdatePlan:
    product_id:str; target_install_root:Path; expected_current_version:str; target_version:str; staged_artifact:Path; backup_path:Path; executable:Path; target_pid:int|None=None; health_check:str|None=None