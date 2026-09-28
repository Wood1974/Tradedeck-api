from __future__ import annotations
from .protocol import sha256_bytes,bind_hash
from .attestation_sheet import AttestationSheet
SEALED_STATES={"sealed","amended","voided"}
def verify_record(row,stored_original,supplied_original=None,location_stated=None,purpose=None,state_history=None,custody_events=None):
    checks={}
    if stored_original is None:photo_hash=None;checks["stored_original"]={"ok":False,"reason":"original_missing"}
    else:photo_hash=sha256_bytes(stored_original);checks["stored_original"]={"ok":photo_hash==row["photo_sha256"]}
    if supplied_original is not None:
        photo_hash=sha256_bytes(supplied_original);checks["supplied_original"]={"ok":photo_hash==row["photo_sha256"],"sha256":photo_hash}
    supplied_note=None
    if location_stated is not None or purpose is not None:
        try:
            supplied_note=AttestationSheet.from_user_input(location_stated,purpose).sha256;checks["attestation_sheet"]={"ok":supplied_note==row["note_sha256"],"sha256":supplied_note}
        except ValueError as exc:checks["attestation_sheet"]={"ok":False,"reason":str(exc)}
    else:checks["attestation_sheet"]={"ok":None,"reason":"not_supplied"}
    if photo_hash is not None:
        rb=bind_hash(photo_hash,supplied_note or row["note_sha256"],row["job_id"],row["point_id"],row["nonce"],row["account_id"]);checks["bind_hash"]={"ok":rb==row["bind_hash"],"recomputed":rb}
    else:checks["bind_hash"]={"ok":False,"reason":"photo_unavailable"}
    history=list(state_history or []);state=row["state"];checks["state_history"]={"ok":state in SEALED_STATES and bool(history) and history[-1]["to_state"]==state,"state":state,"events":len(history)}
    custody=list(custody_events or []);sealed=[e for e in custody if e["event_type"]=="sealed"];ok=bool(sealed)
    if sealed:
        import json
        try:
            d=json.loads(sealed[-1]["details_json"] or "{}");ok=d.get("photo_sha256")==row["photo_sha256"] and d.get("note_sha256")==row["note_sha256"] and d.get("bind_hash")==row["bind_hash"]
        except Exception:ok=False
    checks["custody_seal"]={"ok":ok,"sealed_events":len(sealed)};failed=[k for k,v in checks.items() if v.get("ok") is False]
    return {"ok":not failed,"evidence_id":row["id"],"protocol":"shield-evidence-v1","state":state,"written_at":row["written_at"],"checks":checks,"failed_checks":failed,"limitations":["Verification proves consistency with the Shield record; it does not prove the truth of the human statement.","Location is a signal and is never reported as GPS-verified.","Trusted third-party timestamping is not included until Section 16."]}
