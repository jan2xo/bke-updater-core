from __future__ import annotations
import argparse, ctypes, os, queue, shutil, subprocess, threading, time
from pathlib import Path
from .protocol import HelperPlan
from ..models import TransactionState
from ..state import TransactionStore

class UnsafeHelperPlan(ValueError): pass

def _root(path:Path,name:str)->Path:
    value=path.expanduser().resolve()
    if not value.exists() or not value.is_dir() or value.parent==value:
        raise UnsafeHelperPlan(f"invalid {name} root")
    return value

def _backup_root(path:Path)->Path:
    value=path.expanduser().resolve()
    if value.parent==value or not value.parent.exists() or not value.parent.is_dir():
        raise UnsafeHelperPlan("invalid backup root")
    return value

def _inside(root:Path,target:Path,name:str)->Path:
    resolved=target.resolve()
    if os.path.commonpath((str(root),str(resolved)))!=str(root):
        raise UnsafeHelperPlan(f"{name} escapes root")
    return resolved

def validate_plan(plan:HelperPlan)->tuple[Path,Path,Path,Path]:
    root,stage,backup=(_root(plan.install_root,"install"),_root(plan.staged_root,"stage"),_backup_root(plan.backup_root))
    if len({root,stage,backup})!=3:
        raise UnsafeHelperPlan("helper roots must be distinct")
    if any(a in b.parents or b in a.parents for a,b in ((root,stage),(root,backup),(stage,backup))):
        raise UnsafeHelperPlan("helper roots overlap")
    executable=_inside(root,plan.executable,"executable")
    _inside(stage,stage/executable.relative_to(root),"staged executable")
    return root,stage,backup,executable

def _terminal(plan:HelperPlan,state:TransactionState,**extra)->None:
    if plan.transaction_root and plan.transaction_id:
        TransactionStore(plan.transaction_root).write(plan.transaction_id,state,extra)

def _wait_for_exit_windows(pid:int,timeout:float,kernel32=None)->None:
    api=kernel32 or ctypes.windll.kernel32
    synchronize=0x00100000
    wait_object_0=0x00000000
    wait_timeout=0x00000102
    handle=api.OpenProcess(synchronize,False,pid)
    if not handle:
        # The process already exited or cannot be opened. Treat an absent process
        # as complete; access-denied remains fail-closed when a handle is returned.
        return
    try:
        milliseconds=max(0,min(int(timeout*1000),0xFFFFFFFE))
        result=api.WaitForSingleObject(handle,milliseconds)
        if result==wait_object_0:
            return
        if result==wait_timeout:
            raise TimeoutError("target process did not exit")
        raise OSError(f"WaitForSingleObject failed: {result}")
    finally:
        api.CloseHandle(handle)

def wait_for_exit(pid:int|None,timeout:float=30.0):
    if pid is None: return
    if pid<=0: raise ValueError("pid must be positive")
    if os.name=="nt":
        _wait_for_exit_windows(pid,timeout)
        return
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            os.kill(pid,0)
            stat=Path(f"/proc/{pid}/stat")
            if stat.exists():
                fields=stat.read_text().split()
                if len(fields)>2 and fields[2]=="Z": return
        except OSError:
            return
        time.sleep(.1)
    raise TimeoutError("target process did not exit")

def _launch_and_verify(executable:Path, plan:HelperPlan)->subprocess.Popen|None:
    if not plan.launch: return None
    process=subprocess.Popen([str(executable),*plan.launch_args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
    if plan.ready_marker is None:
        deadline=time.monotonic()+plan.startup_timeout
        while time.monotonic()<deadline:
            code=process.poll()
            if code is not None:
                if code!=0: raise RuntimeError(f"updated process failed startup: {code}")
                return process
            time.sleep(.05)
        return process
    lines:queue.Queue[str]=queue.Queue()
    def read_output():
        assert process.stdout is not None
        for line in process.stdout:
            lines.put(line)
    threading.Thread(target=read_output,daemon=True).start()
    deadline=time.monotonic()+plan.startup_timeout
    while time.monotonic()<deadline:
        code=process.poll()
        if code is not None:
            raise RuntimeError(f"updated process exited before readiness: {code}")
        try:
            if plan.ready_marker in lines.get(timeout=.05):
                time.sleep(0.2)
                code=process.poll()
                if code is not None:
                    raise RuntimeError(f"updated process exited after readiness: {code}")
                return process
        except queue.Empty:
            pass
    raise TimeoutError("updated process did not report readiness")

def _stop(process:subprocess.Popen|None)->None:
    if process is None or process.poll() is not None: return
    process.terminate()
    try: process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=3)

def replace_and_launch(plan:HelperPlan,wait_pid:int|None=None)->int:
    root,stage,backup,executable=validate_plan(plan)
    wait_for_exit(wait_pid)
    if backup.exists(): shutil.rmtree(backup)
    shutil.copytree(root,backup)
    launched=None
    try:
        shutil.rmtree(root)
        shutil.copytree(stage,root)
        target=root/executable.relative_to(root)
        launched=_launch_and_verify(target,plan)
        _terminal(plan,TransactionState.COMMITTED,target_version=plan.transaction_id or "")
        return 0
    except Exception as exc:
        _stop(launched)
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root)
        restored=root/executable.relative_to(root)
        try:
            _launch_and_verify(restored,plan)
        except Exception as restore_error:
            _terminal(plan,TransactionState.FAILED,reason=f"{exc}; restoration failed: {restore_error}")
            raise
        _terminal(plan,TransactionState.ROLLED_BACK,reason=str(exc))
        raise

def main()->int:
    parser=argparse.ArgumentParser()
    for name in ("install-root","staged-root","backup-root","executable"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--wait-pid",type=int)
    parser.add_argument("--transaction-root")
    parser.add_argument("--transaction-id")
    parser.add_argument("--launch-arg",action="append",default=[])
    parser.add_argument("--ready-marker")
    parser.add_argument("--startup-timeout",type=float,default=10.0)
    args=parser.parse_args()
    plan=HelperPlan(Path(args.install_root),Path(args.staged_root),Path(args.backup_root),Path(args.executable),
        transaction_root=Path(args.transaction_root) if args.transaction_root else None,
        transaction_id=args.transaction_id,launch_args=tuple(args.launch_arg),
        ready_marker=args.ready_marker,startup_timeout=args.startup_timeout)
    return replace_and_launch(plan,args.wait_pid)

if __name__=="__main__": raise SystemExit(main())
