from __future__ import annotations
import argparse, os, shutil, subprocess, time
from pathlib import Path
from .protocol import HelperPlan

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
def wait_for_exit(pid:int|None,timeout:float=30.0):
    if pid is None:return
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try: os.kill(pid,0)
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
            proc=subprocess.Popen([str(target)]); time.sleep(.25)
            if proc.poll() is not None and proc.returncode!=0: raise RuntimeError("updated process failed startup")
        return 0
    except Exception:
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root); raise
def main()->int:
    parser=argparse.ArgumentParser()
    for name in ("install-root","staged-root","backup-root","executable"): parser.add_argument("--"+name,required=True)
    parser.add_argument("--wait-pid",type=int); args=parser.parse_args()
    return replace_and_launch(HelperPlan(Path(args.install_root),Path(args.staged_root),Path(args.backup_root),Path(args.executable)),args.wait_pid)
if __name__=="__main__": raise SystemExit(main())
