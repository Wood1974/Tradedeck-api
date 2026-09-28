from __future__ import annotations
from datetime import datetime,timezone
import json,os,uuid
from fastapi import FastAPI,File,Form,HTTPException,UploadFile,Request
from pydantic import BaseModel
from .protocol import sha256_bytes,bind_hash
from .store import Store
from .attestation import AttestationVerifier
from .play_integrity import PlayIntegrityVerifier
from .auth import actor_for
from .location import evaluate_location
from .attestation_sheet import AttestationSheet
from .verification import verify_record
from .permissions import authorize_job,AuthorizationError
from .timestamping import timestamp_bind_hash
from .security import enforce_rate_limit
app=FastAPI(title="TradeDeck Shield Evidence API",version="2.0.0",docs_url=None,redoc_url=None)
MAX_PHOTO_BYTES=int(os.getenv("SHIELD_MAX_PHOTO_BYTES","15728640"));ALLOWED={"image/jpeg","image/jpg"}
store=Store(os.getenv("SHIELD_DATABASE_URL","sqlite:////data/shield.db"),os.getenv("SHIELD_STORAGE_ROOT","/data/storage"))
att_mode=os.getenv("SHIELD_ATTESTATION_MODE","development");att=AttestationVerifier(att_mode,os.getenv("SHIELD_APP_ID",""),store=store);play=PlayIntegrityVerifier(os.getenv("SHIELD_PLAY_INTEGRITY_MODE",att_mode),os.getenv("SHIELD_PLAY_PACKAGE_NAME","com.tradedeck.shield"));TTL=int(os.getenv("SHIELD_CHALLENGE_TTL_SECONDS","120"))
@app.middleware("http")
async def security_middleware(request,call_next):
 enforce_rate_limit(request);response=await call_next(request);response.headers["X-Content-Type-Options"]="nosniff";response.headers["Referrer-Policy"]="no-referrer";response.headers["Cache-Control"]="no-store";return response
def token_for(request):
 h=request.headers.get("authorization","");return h[7:].strip() if h.startswith("Bearer ") else None
@app.get("/health")
@app.get("/shield/v1/health")
def health():return {"ok":True,"service":"tradedeck-shield","protocol":"shield-evidence-v1","api":"2.0"}
@app.post("/shield/jobs/{job_id}/challenge")
def challenge(request:Request,job_id:str,point_id:str=Form(...),account_id:str|None=Form(None)):
 actor=actor_for(request,account_id)
 try:authorize_job(actor.account_id,job_id,point_id,token_for(request))
 except AuthorizationError as e:raise HTTPException(403,str(e))
 n,exp=store.challenge(job_id,point_id,actor.account_id,TTL);return {"job_id":job_id,"point_id":point_id,"nonce":n,"expires_at":exp}
@app.post("/shield/attest/challenge")
def attest_challenge(request:Request,account_id:str|None=Form(None)):
 actor=actor_for(request,account_id);n,exp=store.attestation_challenge(actor.account_id,TTL);return {"nonce":n,"expires_at":exp}
@app.post("/shield/attest")
def register_attestation(request:Request,account_id:str|None=Form(None),key_id:str=Form(...),nonce:str=Form(...),attestation:str=Form(...)):
 actor=actor_for(request,account_id)
 try:store.consume_attestation_challenge(nonce,actor.account_id)
 except ValueError as e:raise HTTPException(409,str(e))
 result=att.verify_attestation(attestation,key_id,nonce.encode())
 if result.get("trusted") is not True:raise HTTPException(422,result.get("status","attestation_rejected"))
 store.save_attestation_key(key_id,actor.account_id,result["public_key_der_b64"],result["environment"],result.get("receipt_b64",""))
 return {"trusted":True,"status":"attested","key_id":key_id,"environment":result["environment"]}
@app.post("/shield/jobs/{job_id}/photos")
async def capture(request:Request,job_id:str,point_id:str=Form(...),account_id:str|None=Form(None),nonce:str=Form(...),location_stated:str|None=Form(None),purpose:str|None=Form(None),captured_at:str=Form(...),lat:float|None=Form(None),lng:float|None=Form(None),accuracy_m:float|None=Form(None),location_observed_at:str|None=Form(None),mock_flag:bool|None=Form(None),attestation_key_id:str|None=Form(None),attestation_assertion:str|None=Form(None),play_integrity_token:str|None=Form(None),photo:UploadFile=File(...)):
 actor=actor_for(request,account_id);account_id=actor.account_id
 try:authorize_job(account_id,job_id,point_id,token_for(request))
 except AuthorizationError as e:raise HTTPException(403,str(e))
 if photo.content_type not in ALLOWED:raise HTTPException(415,"unsupported_photo_type")
 raw=await photo.read(MAX_PHOTO_BYTES+1)
 if not raw:raise HTTPException(400,"empty_photo")
 if len(raw)>MAX_PHOTO_BYTES:raise HTTPException(413,"photo_too_large")
 try:sheet=AttestationSheet.from_user_input(location_stated,purpose)
 except ValueError as e:raise HTTPException(422,str(e))
 ph=sha256_bytes(raw);nh=sha256_bytes(sheet.canonical_bytes);bh=bind_hash(ph,nh,job_id,point_id,nonce,account_id);client_hash=sha256_bytes(bh.encode())
 apple=att.verify_assertion(attestation_assertion,client_hash,attestation_key_id,account_id=account_id,commit_counter=False)
 android=play.verify(play_integrity_token,bh) if play_integrity_token else {"trusted":False,"status":"missing_play_integrity_token"}
 if att_mode=="production" and apple.get("trusted") is not True and android.get("trusted") is not True:raise HTTPException(422,"platform_attestation_required")
 try:store.consume(nonce,job_id,point_id,account_id)
 except ValueError as e:raise HTTPException(409,str(e))
 if apple.get("trusted") is True and not att.update_counter(attestation_key_id,apple["counter"]):raise HTTPException(409,"attestation_counter_update_failed")
 loc=evaluate_location(lat=lat,lng=lng,accuracy_m=accuracy_m,observed_at=location_observed_at,expected_lat=None,expected_lng=None,mock_flag=mock_flag)
 eid=str(uuid.uuid4());written=datetime.now(timezone.utc).isoformat()
 try:ts=timestamp_bind_hash(bh)
 except RuntimeError as e:raise HTTPException(503,str(e))
 rel=store.save_original(eid,job_id,account_id,raw)
 store.create_evidence(id=eid,job_id=job_id,point_id=point_id,account_id=account_id,nonce=nonce,photo_sha256=ph,note_sha256=nh,bind_hash=bh,captured_at=captured_at,written_at=written,location_json=json.dumps({"lat":lat,"lng":lng,"accuracy_m":accuracy_m,"observed_at":location_observed_at,**loc},sort_keys=True),attestation_json=json.dumps({"apple":apple,"play_integrity":android,"trusted_timestamp":ts},sort_keys=True),original_path=rel,status="sealed",state="sealed",actor_id=account_id,state_history=["capture_received","verified","sealed"])
 return {"evidence_id":eid,"status":"sealed","photo_sha256":ph,"note_sha256":nh,"bind_hash":bh,"written_at":written,"attestation_sheet":sheet.public_dict(),"location":loc,"attestation":{"apple":apple,"play_integrity":android},"trusted_timestamp":ts}
@app.get("/shield/evidence/{evidence_id}/state")
def state(request:Request,evidence_id:str):
 actor=actor_for(request,None);row=store.get(evidence_id)
 if not row:raise HTTPException(404,"evidence_not_found")
 if row["account_id"]!=actor.account_id:raise HTTPException(403,"evidence_access_denied")
 return {"evidence_id":evidence_id,"state":row["state"],"status":row["status"],"history":[dict(x) for x in store.state_history(evidence_id)]}
@app.get("/shield/evidence/{evidence_id}/verify")
def owner_verify(request:Request,evidence_id:str):
 actor=actor_for(request,None);row=store.get(evidence_id)
 if not row:raise HTTPException(404,"evidence_not_found")
 if row["account_id"]!=actor.account_id:raise HTTPException(403,"evidence_access_denied")
 p=store.root/row["original_path"];raw=p.read_bytes() if p.exists() else None
 return verify_record(row,raw,state_history=store.state_history(evidence_id),custody_events=store.custody_history(evidence_id))
@app.post("/shield/v1/verify")
async def independent_verify(evidence_id:str=Form(...),location_stated:str|None=Form(None),purpose:str|None=Form(None),photo:UploadFile|None=File(None)):
 row=store.get(evidence_id)
 if not row:raise HTTPException(404,"evidence_not_found")
 supplied=await photo.read(MAX_PHOTO_BYTES+1) if photo else None
 if supplied is not None and len(supplied)>MAX_PHOTO_BYTES:raise HTTPException(413,"photo_too_large")
 p=store.root/row["original_path"];raw=p.read_bytes() if p.exists() else None
 return verify_record(row,raw,supplied,location_stated,purpose,state_history=store.state_history(evidence_id),custody_events=store.custody_history(evidence_id))
