from .models import Decision
from .versioning import VersionError, parse_version

def decide_update(installed: str, latest: str, minimum_supported: str) -> Decision:
    try:
        current, target, minimum = map(parse_version, (installed, latest, minimum_supported))
    except VersionError:
        return Decision.UNSUPPORTED
    if current < minimum:
        return Decision.UPDATE_REQUIRED
    if current == target:
        return Decision.UP_TO_DATE
    if current < target:
        return Decision.UPDATE_AVAILABLE
    return Decision.UNSUPPORTED
