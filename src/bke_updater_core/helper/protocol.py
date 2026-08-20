from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class HelperPlan:
    install_root: Path
    staged_root: Path
    backup_root: Path
    executable: Path
    launch: bool = True
