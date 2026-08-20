from __future__ import annotations
import argparse, os, shutil, subprocess, time
from pathlib import Path
from .protocol import HelperPlan
from ..models import TransactionState
from ..state import TransactionStore
class UnsafeHelperPlan(ValueError): pass
def _root(path:Path,name:str)->Path:
    value=path.expanduser().resolve()
    if not value.exists() or not value.is_dir() or value.parent==value: raise UnsafeHelperPlan(f"invalid {name} root")
    return value
def _inside(root:Path,target:Path,name:str)->Path:
    resolved=target.resolve()
    if os.path.commonpath((str(root),str(resolved)))!=str(root): raise UnsafeHelperPlan(f"{name} escapes root")
    return resolved
def validate_plan(plan:HelperPlan)->tuple[Path,Path,Path,Path]:
    root,stage,backup=_root(plan.install_root,"install"),_root(plan.staged_root,"stage"),_root(plan.backup_root,"backup")
    if len({root,stage,backup})!=3: raise UnsafeHelperPlan("helper roots must be distinct")
    if any(a in b.parents or b in a.parents for a,b in ((root,stage),(root,backup),(stage,backup))): raise UnsafeHelperPlan("helper roots overlap")
    executable=_inside(root,plan.executable,"executable")
    _inside(stage,stage/executable.relative_to(root),"staged executable")
    return root,stage,backup,executable
def _terminal(plan:HelperPlan,state:TransactionState,**extra)->None:
    if plan.transaction_root and plan.transaction_id: TransactionStore(plan.transaction_root).write(plan.transaction_id,state,extra)
def wait_for_exit(pid:int|None,timeout:float=30.0):
    if pid is None:return
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            os.kill(pid,0)
            stat=Path(f"/proc/{pid}/stat")
            if stat.exists():
                fields=stat.read_text().split()
                if len(fields)>2 and fields[2]=="Z": return
        except OSError:return
        time.sleep(.1)
    raise TimeoutError("target process did not exit")
def replace_and_launch(plan:HelperPlan,wait_pid:int|None=None)->int:
    root,stage,backup,executable=validate_plan(plan)
    wait_for_exit(wait_pid)
    if backup.exists(): shutil.rmtree(backup)
    shutil.copytree(root,backup)
    try:
        shutil.rmtree(root); shutil.copytree(stage,root)
        target=root/executable.relative_to(root)
        if plan.launch:
            proc=subprocess.Popen([str(target)]); proc.wait(timeout=10)
            if proc.returncode!=0: raise RuntimeError("updated process failed startup")
        _terminal(plan,TransactionState.COMMITTED,target_version=plan.transaction_id or "")
        return 0
    except Exception as exc:
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root)
        _terminal(plan,TransactionState.ROLLED_BACK,reason=str(exc))
        raise
def main()->int:
    parser=argparse.ArgumentParser()
    for name in ("install-root","staged-root","backup-root","executable"): parser.add_argument("--"+name,required=True)
    parser.add_argument("--wait-pid",type=int); parser.add_argument("--transaction-root"); parser.add_argument("--transaction-id")
    args=parser.parse_args()
    plan=HelperPlan(Path(args.install_root),Path(args.staged_root),Path(args.backup_root),Path(args.executable),transaction_root=Path(args.transaction_root) if args.transaction_root else None,transaction_id=args.transaction_id)
    return replace_and_launch(plan,args.wait_pid)
if __name__=="__main__": raise SystemExit(main())
