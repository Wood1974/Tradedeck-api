from __future__ import annotations
import os,httpx
class AuthorizationError(Exception): pass
def authorize_job(account_id:str,job_id:str,point_id:str,bearer_token:str|None=None)->dict:
    mode=os.getenv("SHIELD_AUTHZ_MODE","development").lower()
    url=os.getenv("SUPABASE_URL","").rstrip("/")
    api_key=os.getenv("SHIELD_SUPABASE_PUBLISHABLE_KEY","")
    if mode!="production": return {"authorized":True,"source":"development"}
    if not url or not api_key or not bearer_token: raise AuthorizationError("job_authorization_not_configured")
    try:
        r=httpx.post(f"{url}/rest/v1/rpc/shield_authorize_capture",
          json={"p_shield_job_id":job_id,"p_point_id":point_id},
          headers={"Authorization":f"Bearer {bearer_token}","apikey":api_key,"Content-Type":"application/json"},timeout=5.0)
        if r.status_code!=200: raise AuthorizationError("job_authorization_unavailable")
        if r.json() is not True: raise AuthorizationError("job_access_denied")
        return {"authorized":True,"source":"supabase"}
    except AuthorizationError: raise
    except Exception as exc: raise AuthorizationError("job_authorization_unavailable") from exc
