import base64,json,re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .models import SignedUpdatePolicy
from .versioning import VersionError,parse_version
class VerificationError(ValueError): pass
class PolicyVerifier:
    def __init__(self,trusted_keys:dict[str,bytes]): self.trusted_keys=trusted_keys
    def verify(self,document:dict,*,product_id:str,platform:str,architecture:str,channel:str,last_revision:int|None=None):
        required={"schema","product_id","current_version","latest_version","minimum_supported_version","channel","platform","architecture","release_id","artifact_id","artifact_sha256","artifact_size","content_type","published_at","issued_at","revision","signing_key_id","algorithm","signature"}
        if set(document)!=required or document["schema"]!="bke.update-policy.v1" or document["algorithm"]!="Ed25519": raise VerificationError("unsupported policy contract")
        for field,expected in (("product_id",product_id),("platform",platform),("architecture",architecture),("channel",channel)):
            if document[field]!=expected: raise VerificationError(f"{field} mismatch")
        try:
            current=parse_version(document["current_version"]); latest=parse_version(document["latest_version"]); minimum=parse_version(document["minimum_supported_version"])
        except (VersionError,TypeError): raise VerificationError("invalid semantic version")
        if minimum>latest: raise VerificationError("minimum version exceeds latest version")
        if not isinstance(document["artifact_size"],int) or document["artifact_size"]<0: raise VerificationError("invalid artifact size")
        if not isinstance(document["artifact_sha256"],str) or not re.fullmatch(r"[0-9a-fA-F]{64}",document["artifact_sha256"]): raise VerificationError("invalid artifact hash")
        if not isinstance(document["revision"],int) or document["revision"]<0: raise VerificationError("invalid policy revision")
        if last_revision is not None and document["revision"]<=last_revision: raise VerificationError("stale policy")
        key=self.trusted_keys.get(document["signing_key_id"])
        if key is None: raise VerificationError("unknown signing key")
        unsigned={k:v for k,v in document.items() if k!="signature"}
        canonical=json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        try: Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(document["signature"],validate=True),canonical)
        except Exception as exc: raise VerificationError("invalid policy signature") from exc
        return SignedUpdatePolicy(raw=document,**document)
