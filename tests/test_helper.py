from pathlib import Path
import os
import subprocess
import pytest
from bke_updater_core.helper.main import replace_and_launch
from bke_updater_core.helper.protocol import HelperPlan

def program(path: Path, code: int):
    path.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(%d)\n" % code)
    path.chmod(0o755)

def service(path: Path, marker: Path, pid_file: Path, code: int = 0):
    if code:
        body = f"#!/usr/bin/env python3\nimport os\nfrom pathlib import Path\nPath({str(pid_file)!r}).write_text(str(os.getpid()))\nPath({str(marker)!r}).write_text('READY')\nraise SystemExit({code})\n"
    else:
        body = f"#!/usr/bin/env python3\nimport os, time\nfrom pathlib import Path\nPath({str(pid_file)!r}).write_text(str(os.getpid()))\nPath({str(marker)!r}).write_text('READY')\ntime.sleep(60)\n"
    path.write_text(body)
    path.chmod(0o755)

def stop(pid_file: Path):
    if pid_file.exists():
        subprocess.run(["kill", pid_file.read_text()], check=False)

def test_external_helper_replaces_and_launches(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"
    root.mkdir(); stage.mkdir(); program(root/"agent",0); program(stage/"agent",0)
    expected=(stage/"agent").read_bytes()
    replace_and_launch(HelperPlan(root,stage,backup,root/"agent"))
    assert (root/"agent").read_bytes()==expected

def test_long_running_ready_agent_commits_without_termination(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"; marker=tmp_path/"ready"; pid=tmp_path/"pid"
    root.mkdir(); stage.mkdir(); service(root/"agent",marker,pid); service(stage/"agent",marker,pid)
    try:
        replace_and_launch(HelperPlan(root,stage,backup,root/"agent",ready_marker="READY"))
        assert marker.read_text()=="READY"
        assert int(pid.read_text())>0
    finally:
        stop(pid)

def test_external_helper_relaunches_restored_agent_on_failed_startup(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"; marker=tmp_path/"ready"; pid=tmp_path/"pid"
    root.mkdir(); stage.mkdir(); service(root/"agent",marker,pid); service(stage/"agent",marker,pid,code=1)
    try:
        with pytest.raises(RuntimeError):
            replace_and_launch(HelperPlan(root,stage,backup,root/"agent",ready_marker="READY"))
        assert marker.read_text()=="READY"
        assert int(pid.read_text())>0
    finally:
        stop(pid)
