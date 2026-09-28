from __future__ import annotations
import os,base64,hashlib,httpx
def timestamp_bind_hash(bind_hash:str)->dict:
    url=os.getenv("SHIELD_RFC3161_GATEWAY_URL")
    required=os.getenv("SHIELD_TIMESTAMP_REQUIRED","false").lower()=="true"
    digest=hashlib.sha256(bind_hash.encode()).hexdigest()
    if not url:
        if required: raise RuntimeError("trusted_timestamp_required")
        return {"status":"not_configured","digest_sha256":digest}
    try:
        r=httpx.post(url,json={"digest_sha256":digest},timeout=10); r.raise_for_status()
        return {"status":"issued","digest_sha256":digest,"token_der_b64":base64.b64encode(r.content).decode()}
    except Exception:
        if required: raise RuntimeError("trusted_timestamp_unavailable")
        return {"status":"unavailable","digest_sha256":digest}
