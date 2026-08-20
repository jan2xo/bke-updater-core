import hashlib
import os
from pathlib import Path

from bke_updater_core import TransactionState, UpdatePlan, replace_transaction

def _program(path: Path, version: str, healthy: bool = True):
    path.write_text("#!/usr/bin/env python3\nimport sys\nprint('%s')\nsys.exit(0 if '--health' in sys.argv and %s else 1)\n" % (version, healthy))
    path.chmod(0o755)

def test_real_replacement_commits_and_runs_health(tmp_path):
    root=tmp_path/"install"; root.mkdir()
    old=root/"run"; _program(old,"v1")
    artifact=tmp_path/"v2"; _program(artifact,"v2")
    plan=UpdatePlan("python-fixture",root,"1.0.0","2.0.0",artifact,tmp_path/"backup",root/"run",
                    expected_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    expected_size=artifact.stat().st_size)
    assert replace_transaction(plan) is TransactionState.COMMITTED
    assert os.popen(f"{root/'run'}").read().strip()=="v2"

def test_broken_candidate_restores_previous_install(tmp_path):
    root=tmp_path/"install"; root.mkdir()
    old=root/"run"; _program(old,"v1")
    artifact=tmp_path/"broken"; _program(artifact,"broken",False)
    plan=UpdatePlan("fixture",root,"1.0.0","2.0.0",artifact,tmp_path/"backup",root/"run",
                    expected_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    expected_size=artifact.stat().st_size)
    assert replace_transaction(plan, health_timeout=0.2) is TransactionState.ROLLED_BACK
    assert os.popen(f"{root/'run'}").read().strip()=="v1"
