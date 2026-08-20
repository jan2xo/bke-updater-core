import argparse,os,shutil,subprocess,time
from pathlib import Path
from .protocol import HelperPlan
def wait_for_exit(pid:int|None,timeout:float=30.0):
    if pid is None:return
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try: os.kill(pid,0)
        except OSError:return
        time.sleep(.1)
    raise TimeoutError("target process did not exit")
def replace_and_launch(plan:HelperPlan,wait_pid:int|None=None)->int:
    root,stage,backup=map(lambda p:p.resolve(),(plan.install_root,plan.staged_root,plan.backup_root))
    if root in (stage,backup) or root==stage.parent: raise ValueError("unsafe update roots")
    wait_for_exit(wait_pid)
    if backup.exists(): shutil.rmtree(backup)
    backup.mkdir(parents=True,exist_ok=True)
    shutil.copytree(root,backup,dirs_exist_ok=True)
    try:
        for item in root.iterdir(): shutil.rmtree(item) if item.is_dir() else item.unlink()
        for item in stage.iterdir(): shutil.move(str(item),str(root/item.name))
        if plan.launch:
            proc=subprocess.Popen([str(plan.executable)]); time.sleep(.25)
            if proc.poll() is not None and proc.returncode!=0: raise RuntimeError("updated process failed health startup")
        return 0
    except Exception:
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root)
        raise
if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--install-root",required=True); p.add_argument("--staged-root",required=True); p.add_argument("--backup-root",required=True); p.add_argument("--executable",required=True); p.add_argument("--wait-pid",type=int)
    a=p.parse_args(); raise SystemExit(replace_and_launch(HelperPlan(Path(a.install_root),Path(a.staged_root),Path(a.backup_root),Path(a.executable)),a.wait_pid))
