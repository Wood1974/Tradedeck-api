from __future__ import annotations
from dataclasses import dataclass
from .protocol import canonical_note, sha256_bytes
MAX_LOCATION_CHARS=500
MAX_PURPOSE_CHARS=1000
@dataclass(frozen=True)
class AttestationSheet:
    location_stated:str
    purpose:str
    @classmethod
    def from_user_input(cls,location_stated:str|None,purpose:str|None)->"AttestationSheet":
        if location_stated is None or purpose is None: raise ValueError("attestation_sheet_required")
        location=location_stated.strip(); why=purpose.strip()
        if not location: raise ValueError("location_stated_required")
        if not why: raise ValueError("purpose_required")
        if len(location)>MAX_LOCATION_CHARS: raise ValueError("location_stated_too_long")
        if len(why)>MAX_PURPOSE_CHARS: raise ValueError("purpose_too_long")
        canonical_note(location,why)
        return cls(location,why)
    @property
    def canonical_bytes(self)->bytes: return canonical_note(self.location_stated,self.purpose)
    @property
    def sha256(self)->str: return sha256_bytes(self.canonical_bytes)
    def public_dict(self)->dict[str,str]: return {"location_stated":self.location_stated,"purpose":self.purpose}
