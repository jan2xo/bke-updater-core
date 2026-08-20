from pathlib import Path
from bke_updater_core.models import Decision
from bke_updater_core.policy import decide_update
from bke_updater_core.paths import safe_extract_member,UnsafePath
def test_decisions():
    assert decide_update("1.0.0","1.2.0","1.0.0")==Decision.UPDATE_AVAILABLE
    assert decide_update("1.0.0","1.2.0","1.1.0")==Decision.UPDATE_REQUIRED
    assert decide_update("1.2.0","1.2.0","1.0.0")==Decision.UP_TO_DATE
    assert decide_update("2.0.0","1.2.0","1.0.0")==Decision.UNSUPPORTED
def test_paths():
    try: safe_extract_member(Path("/tmp/stage"),"../evil"); assert False
    except UnsafePath: pass