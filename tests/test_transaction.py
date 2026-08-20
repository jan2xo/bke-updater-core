from bke_updater_core.models import UpdatePlan,TransactionState
from bke_updater_core.transaction import UpdateTransaction
def test_interrupted_replacement_rolls_back(tmp_path):
    root=tmp_path/'install'; backup=tmp_path/'backup'; stage=tmp_path/'stage'; root.mkdir(); (root/'version').write_text('1.0.0')
    import shutil; shutil.copytree(root,backup)
    plan=UpdatePlan('mock',root,'1.0.0','2.0.0',stage,backup,root/'run.sh')
    tx=UpdateTransaction(tmp_path/'state',plan,'tx1'); tx.transition(TransactionState.REPLACING); tx.rollback('test interruption')
    assert (root/'version').read_text()=='1.0.0'; assert tx.recover() is TransactionState.ROLLED_BACK


def test_interrupted_before_replacement_fails_closed_and_cleans_stage(tmp_path):
    root=tmp_path/'install'; backup=tmp_path/'backup'; stage=tmp_path/'stage'
    root.mkdir(); backup.mkdir(); stage.write_text('staged')
    plan=UpdatePlan('mock',root,'1.0.0','2.0.0',stage,backup,root/'run.sh')
    tx=UpdateTransaction(tmp_path/'state',plan,'tx2')
    tx.transition(TransactionState.STAGED)
    assert tx.recover() is TransactionState.FAILED
    assert not stage.exists()
