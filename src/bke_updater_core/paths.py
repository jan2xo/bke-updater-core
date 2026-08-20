from pathlib import Path, PurePosixPath
import os
class UnsafePath(ValueError): pass
def validate_manifest_paths(install_root:Path, executable:str):
    root=install_root.expanduser().resolve()
    rel=Path(executable)
    if rel.is_absolute() or ".." in rel.parts: raise UnsafePath("executable escapes install root")
    target=(root/rel).resolve()
    if os.path.commonpath((str(root),str(target)))!=str(root): raise UnsafePath("executable escapes install root")
    return root,target
def safe_extract_member(staging_root:Path, member_name:str, is_symlink=False, is_device=False):
    name=PurePosixPath(member_name)
    if is_symlink or is_device or name.is_absolute() or ".." in name.parts: raise UnsafePath("unsafe archive member")
    root=staging_root.resolve(); target=(root/Path(*name.parts)).resolve()
    if os.path.commonpath((str(root),str(target)))!=str(root): raise UnsafePath("archive escape")
    return target