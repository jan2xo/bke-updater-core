import json
from pathlib import Path
from .models import TransactionState
class TransactionStore:
    def __init__(self,root:Path): self.root=root
    def write(self,transaction_id,state:TransactionState,payload:dict):
        folder=self.root/transaction_id; folder.mkdir(parents=True,exist_ok=True)
        tmp=folder/"state.json.tmp"; tmp.write_text(json.dumps({"transaction_id":transaction_id,"state":state.value,**payload},sort_keys=True))
        tmp.replace(folder/"state.json")
    def read(self,transaction_id): return json.loads((self.root/transaction_id/"state.json").read_text())