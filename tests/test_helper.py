from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).parents[1]))
from helper.main import replace_and_launch
from helper.protocol import HelperPlan

def program(path: Path, code: int):
    path.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(%d)\n" % code)
    path.chmod(0o755)

def test_external_helper_replaces_and_launches(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"
    root.mkdir(); stage.mkdir(); program(root/"agent",0); program(stage/"agent",0)
    expected=(stage/"agent").read_bytes()
    replace_and_launch(HelperPlan(root,stage,backup,root/"agent"))
    assert (root/"agent").read_bytes()==expected

def test_external_helper_restores_on_failed_startup(tmp_path):
    root=tmp_path/"agent"; stage=tmp_path/"stage"; backup=tmp_path/"backup"
    root.mkdir(); stage.mkdir(); program(root/"agent",0); program(stage/"agent",1)
    with pytest.raises(RuntimeError):
        replace_and_launch(HelperPlan(root,stage,backup,root/"agent"))
    assert (root/"agent").exists()
    assert (root/"agent").read_text().endswith("0)\n")
