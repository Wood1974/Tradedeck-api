from __future__ import annotations
import json,os,time,httpx
from google.auth.transport.requests import Request
from google.oauth2 import service_account
SCOPE="https://www.googleapis.com/auth/playintegrity"
def _creds():
    raw=os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON","").strip();path=os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE","").strip()
    if raw:return service_account.Credentials.from_service_account_info(json.loads(raw),scopes=[SCOPE])
    if path:return service_account.Credentials.from_service_account_file(path,scopes=[SCOPE])
    raise RuntimeError("play_integrity_service_account_not_configured")
class PlayIntegrityVerifier:
    def __init__(self,mode="development",package_name=""):
        self.mode=mode;self.package_name=package_name;self.max_age_seconds=int(os.getenv("SHIELD_PLAY_MAX_TOKEN_AGE_SECONDS","300"));self.require_license=os.getenv("SHIELD_PLAY_REQUIRE_LICENSED","false").lower()=="true";self.require_device=os.getenv("SHIELD_PLAY_REQUIRE_DEVICE_INTEGRITY","true").lower()=="true";self.require_strong=os.getenv("SHIELD_PLAY_REQUIRE_STRONG_INTEGRITY","false").lower()=="true"
    def _decode(self,token):
        c=_creds();c.refresh(Request());r=httpx.post(f"https://playintegrity.googleapis.com/v1/{self.package_name}:decodeIntegrityToken",headers={"Authorization":f"Bearer {c.token}","Content-Type":"application/json"},json={"integrity_token":token},timeout=15);r.raise_for_status();return r.json().get("tokenPayloadExternal") or {}
    def verify(self,token,expected_request_hash,now_ms=None):
        if not token:return {"trusted":False,"status":"missing_play_integrity_token"}
        if not self.package_name:return {"trusted":False,"status":"play_integrity_package_not_configured"}
        try:
            p=self._decode(token);d=p.get("requestDetails") or {};a=p.get("appIntegrity") or {};dv=p.get("deviceIntegrity") or {};ac=p.get("accountDetails") or {}
            if d.get("requestPackageName")!=self.package_name:raise ValueError("play_package_mismatch")
            if d.get("requestHash")!=expected_request_hash:raise ValueError("play_request_hash_mismatch")
            ts=int(d.get("timestampMillis","0"));now_ms=now_ms or int(time.time()*1000);age=(now_ms-ts)/1000.0
            if age < -60:raise ValueError("play_token_from_future")
            if age>self.max_age_seconds:raise ValueError("play_token_expired")
            av=a.get("appRecognitionVerdict");dvs=dv.get("deviceRecognitionVerdict") or [];lv=ac.get("appLicensingVerdict")
            if av!="PLAY_RECOGNIZED":raise ValueError("play_app_not_recognized")
            if self.require_device and "MEETS_DEVICE_INTEGRITY" not in dvs:raise ValueError("play_device_integrity_failed")
            if self.require_strong and "MEETS_STRONG_INTEGRITY" not in dvs:raise ValueError("play_strong_integrity_required")
            if self.require_license and lv!="LICENSED":raise ValueError("play_license_required")
            return {"trusted":True,"status":"verified","request_timestamp_ms":ts,"request_age_seconds":round(age,3),"app_recognition_verdict":av,"device_recognition_verdict":dvs,"app_licensing_verdict":lv,"package_name":self.package_name}
        except Exception as exc:return {"trusted":False,"status":str(exc)}
