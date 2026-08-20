from pathlib import Path
import subprocess
import pytest
from bke_updater_core.helper.main import replace_and_launch
from bke_updater_core.helper.protocol import HelperPlan

def program(path: Path, code: int):
    path.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(%d)\n" % code)
    path.chmod(0o755)

def service(path: Path, marker: Path, code: int = 0):
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import os, time\n"
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('READY')\n"
        f"raise SystemExit({code})\n" if code else
        "#!/usr/bin/env python3\n"
        "import os, time\n"
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('READY')\n"
        "time.sleep(60)\n"
    )
    path.chmod(0o755)

def test_external_helper_replaces_and_launches(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"
    root.mkdir(); stage.mkdir(); program(root/"agent",0); program(stage/"agent",0)
    expected=(stage/"agent").read_bytes()
    replace_and_launch(HelperPlan(root,stage,backup,root/"agent"))
    assert (root/"agent").read_bytes()==expected

def test_long_running_ready_agent_commits_without_termination(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"; marker=tmp_path/"ready"
    root.mkdir(); stage.mkdir(); service(root/"agent",marker); service(stage/"agent",marker)
    replace_and_launch(HelperPlan(root,stage,backup,root/"agent",ready_marker="READY"))
    assert marker.read_text()=="READY"
    assert (root/"agent").exists()

def test_external_helper_relaunches_restored_agent_on_failed_startup(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"; marker=tmp_path/"ready"
    root.mkdir(); stage.mkdir(); service(root/"agent",marker); service(stage/"agent",marker,code=1)
    with pytest.raises(RuntimeError):
        replace_and_launch(HelperPlan(root,stage,backup,root/"agent",ready_marker="READY"))
    assert marker.read_text()=="READY"
    restored=subprocess.run(["pkill","-f",str(root/"agent")],check=False)
    assert restored.returncode in (0,1)
