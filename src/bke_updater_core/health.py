from __future__ import annotations
import os, subprocess
from pathlib import Path
class HealthCheckError(RuntimeError): pass
def check_executable(executable:Path, timeout:float=5.0)->None:
    if not executable.is_file() or not os.access(executable,os.X_OK): raise HealthCheckError("executable is not launchable")
    try: result=subprocess.run([str(executable)],capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc: raise HealthCheckError("health check failed") from exc
    if result.returncode!=0: raise HealthCheckError(f"health check exit {result.returncode}")
