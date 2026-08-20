import hashlib,tempfile
from pathlib import Path
from urllib.request import Request,urlopen
from .models import SignedUpdatePolicy
class DownloadError(RuntimeError): pass
def download_verified(url:str,policy:SignedUpdatePolicy,destination:Path,timeout:float=30.0):
    destination.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".bke-",dir=destination.parent); Path(tmp).unlink(missing_ok=True)
    temp=Path(tmp); total=0; digest=hashlib.sha256()
    try:
        with urlopen(Request(url,method="GET"),timeout=timeout) as response,temp.open("wb") as out:
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>policy.artifact_size: raise DownloadError("size exceeded")
                digest.update(chunk); out.write(chunk)
        if total!=policy.artifact_size or digest.hexdigest()!=policy.artifact_sha256: raise DownloadError("artifact verification failed")
        temp.replace(destination); return destination
    except Exception: temp.unlink(missing_ok=True); raise