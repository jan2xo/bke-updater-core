import re
class VersionError(ValueError): pass
def parse_version(value:str)->tuple[int,int,int,int]:
    if not isinstance(value,str) or not re.fullmatch(r"0|[1-9][0-9]*(?:\.[0-9]+){0,3}",value):
        raise VersionError(value)
    parts=tuple(int(x) for x in value.split("."))
    return (parts+(0,0,0,0))[:4]