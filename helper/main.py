import shutil,subprocess,time
from pathlib import Path
from .protocol import HelperPlan
def replace_and_launch(plan:HelperPlan)->int:
    root,stage,backup=map(lambda p:p.resolve(),(plan.install_root,plan.staged_root,plan.backup_root))
    if root in (stage,backup) or root==stage.parent: raise ValueError("unsafe update roots")
    backup.mkdir(parents=True,exist_ok=True); shutil.copytree(root,backup,dirs_exist_ok=True)
    try:
        for item in root.iterdir(): shutil.rmtree(item) if item.is_dir() else item.unlink()
        for item in stage.iterdir(): shutil.move(str(item),str(root/item.name))
        if plan.launch:
            proc=subprocess.Popen([str(plan.executable)]); time.sleep(.25)
            if proc.poll() is not None and proc.returncode!=0: raise RuntimeError("health startup failed")
        return 0
    except Exception:
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup,root); raise