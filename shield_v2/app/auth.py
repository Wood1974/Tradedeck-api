from __future__ import annotations
import os,time,httpx,jwt
from dataclasses import dataclass
from typing import Any
from fastapi import HTTPException,Request
@dataclass(frozen=True)
class Actor:
    account_id:str
    claims:dict[str,Any]
class SupabaseJWTVerifier:
    def __init__(self):
        self.url=os.getenv("SUPABASE_URL","").rstrip("/")
        self.issuer=os.getenv("SUPABASE_JWT_ISSUER",f"{self.url}/auth/v1" if self.url else "")
        self.jwks_url=os.getenv("SUPABASE_JWKS_URL",f"{self.issuer}/.well-known/jwks.json" if self.issuer else "")
        self.audience=os.getenv("SUPABASE_JWT_AUDIENCE","authenticated");self.cache_seconds=int(os.getenv("SHIELD_JWKS_CACHE_SECONDS","600"));self._jwks=None;self._loaded_at=0.0
    def _keys(self):
        now=time.time()
        if self._jwks and now-self._loaded_at<self.cache_seconds:return self._jwks
        if not self.jwks_url:raise HTTPException(503,"supabase_jwt_not_configured")
        try:
            r=httpx.get(self.jwks_url,timeout=5.0);r.raise_for_status();data=r.json()
            if not isinstance(data,dict) or not isinstance(data.get("keys"),list):raise ValueError("invalid_jwks")
            self._jwks=data;self._loaded_at=now;return data
        except Exception as exc:
            if self._jwks:return self._jwks
            raise HTTPException(503,"supabase_jwks_unavailable") from exc
    def verify(self,token):
        try:
            header=jwt.get_unverified_header(token);kid=header.get("kid");alg=header.get("alg")
            if not kid or alg not in {"RS256","ES256","ES384","ES512"}:raise ValueError("unsupported_jwt")
            keys=self._keys()["keys"];jwk=next((k for k in keys if k.get("kid")==kid),None)
            if not jwk:self._jwks=None;keys=self._keys()["keys"];jwk=next((k for k in keys if k.get("kid")==kid),None)
            if not jwk:raise ValueError("unknown_kid")
            claims=jwt.decode(token,jwt.PyJWK(jwk).key,algorithms=[alg],audience=self.audience,issuer=self.issuer,options={"require":["exp","sub","iss","aud"]})
            aid=claims.get("sub")
            if not isinstance(aid,str) or not aid:raise ValueError("subject_required")
            return Actor(aid,claims)
        except HTTPException:raise
        except Exception as exc:raise HTTPException(401,"invalid_access_token") from exc
verifier=SupabaseJWTVerifier()
def actor_for(request:Request,supplied_account_id:str|None):
    mode=os.getenv("SHIELD_API_AUTH_MODE","development").lower();auth=request.headers.get("authorization","")
    if auth.startswith("Bearer "):
        actor=verifier.verify(auth[7:].strip())
        if supplied_account_id and mode=="production" and supplied_account_id!=actor.account_id:raise HTTPException(403,"account_context_mismatch")
        return actor
    if mode=="production":raise HTTPException(401,"authorization_required")
    if supplied_account_id:return Actor(supplied_account_id,{"sub":supplied_account_id,"development":True})
    aid=request.headers.get("x-shield-account-id")
    if not aid:raise HTTPException(401,"authorization_required")
    return Actor(aid,{"sub":aid,"development":True})
