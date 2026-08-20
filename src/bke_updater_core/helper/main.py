from __future__ import annotations
import argparse, os, shutil, subprocess, time
from pathlib import Path
from .protocol import HelperPlan

def wait_for_exit(pid: int | None, timeout: float = 30.0) -> None:
    if pid is None: return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try: os.kill(pid, 0)
        except OSError: return
        time.sleep(0.1)
    raise TimeoutError("target process did not exit")

def replace_and_launch(plan: HelperPlan, wait_pid: int | None = None) -> int:
    root, stage, backup = (p.resolve() for p in (plan.install_root, plan.staged_root, plan.backup_root))
    if root == stage or root == backup or root in stage.parents or root in backup.parents or stage in root.parents or backup in root.parents:
        raise ValueError("unsafe update roots")
    if not root.exists() or not stage.is_dir(): raise ValueError("invalid install or stage root")
    wait_for_exit(wait_pid)
    if backup.exists(): shutil.rmtree(backup)
    shutil.copytree(root, backup)
    try:
        shutil.rmtree(root)
        shutil.copytree(stage, root)
        if plan.launch:
            process = subprocess.Popen([str(plan.executable)])
            time.sleep(0.25)
            if process.poll() is not None and process.returncode != 0: raise RuntimeError("updated process failed startup")
        return 0
    except Exception:
        if root.exists(): shutil.rmtree(root)
        shutil.copytree(backup, root)
        raise

def main() -> int:
    parser=argparse.ArgumentParser()
    for name in ("install-root","staged-root","backup-root","executable"): parser.add_argument("--"+name, required=True)
    parser.add_argument("--wait-pid", type=int)
    args=parser.parse_args()
    return replace_and_launch(HelperPlan(Path(args.install_root),Path(args.staged_root),Path(args.backup_root),Path(args.executable)),args.wait_pid)

if __name__ == "__main__": raise SystemExit(main())
