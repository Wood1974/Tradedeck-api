from __future__ import annotations
import hashlib,json
from enum import StrEnum
PROTOCOL_VERSION="shield-evidence-v1"
CHALLENGE_TTL_SECONDS=120
class LocationVerdict(StrEnum):
    CONSISTENT="consistent"; FLAG="flag"; REJECT="reject"
def _require_text(name,value):
    if not isinstance(value,str) or not value:raise ValueError(f"{name}_required")
    return value
def sha256_bytes(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def canonical_note(location_stated:str,purpose:str)->bytes:
    location=_require_text("location_stated",location_stated).strip(); why=_require_text("purpose",purpose).strip()
    if not location:raise ValueError("no_location_stated")
    if not why:raise ValueError("no_purpose")
    return json.dumps({"location_stated":location,"purpose":why},ensure_ascii=False,separators=(",",":")).encode("utf-8")
def note_sha256(location_stated,purpose):return sha256_bytes(canonical_note(location_stated,purpose))
def bind_payload(photo_sha256,note_sha256,job_id,point_id,nonce,account_id)->bytes:
    fields=(_require_text("photo_sha256",photo_sha256),_require_text("note_sha256",note_sha256),_require_text("job_id",job_id),_require_text("point_id",point_id),_require_text("nonce",nonce),_require_text("account_id",account_id))
    return "".join(fields).encode("utf-8")
def bind_hash(photo_sha256,note_sha256,job_id,point_id,nonce,account_id)->str:return sha256_bytes(bind_payload(photo_sha256,note_sha256,job_id,point_id,nonce,account_id))
def validate_hash(value,field="hash"):
    value=_require_text(field,value).lower()
    if len(value)!=64:raise ValueError(f"{field}_invalid")
    try:bytes.fromhex(value)
    except ValueError as exc:raise ValueError(f"{field}_invalid") from exc
    return value
def validate_capture_identity(job_id,point_id,nonce,account_id):
    for n,v in (("job_id",job_id),("point_id",point_id),("nonce",nonce),("account_id",account_id)):_require_text(n,v)
def capture_bind(photo_bytes,location_stated,purpose,job_id,point_id,nonce,account_id):
    validate_capture_identity(job_id,point_id,nonce,account_id); ph=sha256_bytes(photo_bytes); nh=note_sha256(location_stated,purpose)
    return {"photo_sha256":ph,"note_sha256":nh,"bind_hash":bind_hash(ph,nh,job_id,point_id,nonce,account_id)}
