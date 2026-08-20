from __future__ import annotations
import shutil, uuid
from pathlib import Path
from .models import TransactionState, UpdatePlan
from .state import TransactionStore
class TransactionError(RuntimeError): pass
class UpdateTransaction:
    def __init__(self, root:Path, plan:UpdatePlan, transaction_id:str|None=None):
        self.root=root; self.plan=plan; self.id=transaction_id or str(uuid.uuid4()); self.store=TransactionStore(root)
    def transition(self,state:TransactionState,**extra): self.store.write(self.id,state,{"product_id":self.plan.product_id,"target_version":self.plan.target_version,**extra})
    def recover(self):
        state=TransactionState(self.store.read(self.id)["state"])
        if state in {TransactionState.COMMITTED,TransactionState.ROLLED_BACK,TransactionState.FAILED}: return state
        if state in {TransactionState.CREATED,TransactionState.DOWNLOADING,TransactionState.VERIFIED,TransactionState.STAGED,TransactionState.WAITING_FOR_EXIT}: return state
        if state in {TransactionState.REPLACING,TransactionState.VERIFYING}: self.rollback("interrupted replacement"); return TransactionState.ROLLED_BACK
        raise TransactionError("unknown transaction state")
    def rollback(self,reason:str):
        self.transition(TransactionState.ROLLING_BACK,reason=reason)
        root=self.plan.target_install_root.resolve(); backup=self.plan.backup_path.resolve()
        if not backup.exists(): self.transition(TransactionState.FAILED,reason="backup unavailable"); raise TransactionError("backup unavailable")
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root); self.transition(TransactionState.ROLLED_BACK,reason=reason)
    def commit(self): self.transition(TransactionState.COMMITTED)
