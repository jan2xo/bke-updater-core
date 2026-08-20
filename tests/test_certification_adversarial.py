import pytest
from pathlib import Path
from bke_updater_core import PolicyVerifier
from bke_updater_core.paths import UnsafePath, safe_extract_member, validate_manifest_paths
from bke_updater_core.models import UpdatePlan, TransactionState
from bke_updater_core.transaction import UpdateTransaction

def test_path_and_archive_escape_rejected(tmp_path):
    with pytest.raises(UnsafePath):
        validate_manifest_paths(tmp_path, "../outside")
    with pytest.raises(UnsafePath):
        safe_extract_member(tmp_path, "../../outside")
    with pytest.raises(UnsafePath):
        safe_extract_member(tmp_path, "/absolute")
    with pytest.raises(UnsafePath):
        safe_extract_member(tmp_path, "link", is_symlink=True)

def test_interrupted_pre_health_recovery_is_terminal(tmp_path):
    root=tmp_path/"install"; backup=tmp_path/"backup"; staged=tmp_path/"staged"
    root.mkdir(); backup.mkdir(); staged.write_bytes(b"candidate")
    plan=UpdatePlan("fixture",root,"1.0.0","2.0.0",staged,backup,root/"run")
    tx=UpdateTransaction(tmp_path/"state",plan,"pre-health")
    tx.transition(TransactionState.VERIFYING)
    assert tx.recover() is TransactionState.ROLLED_BACK

def test_interrupted_staging_recovery_is_fail_closed(tmp_path):
    root=tmp_path/"install"; backup=tmp_path/"backup"; staged=tmp_path/"staged"
    root.mkdir(); backup.mkdir(); staged.write_bytes(b"candidate")
    plan=UpdatePlan("fixture",root,"1.0.0","2.0.0",staged,backup,root/"run")
    tx=UpdateTransaction(tmp_path/"state",plan,"staging")
    tx.transition(TransactionState.STAGED)
    assert tx.recover() is TransactionState.FAILED
    assert not staged.exists()
