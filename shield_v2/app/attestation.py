from __future__ import annotations
import base64,hashlib,os,struct
from dataclasses import dataclass
from datetime import datetime,timezone
from pathlib import Path
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.x509.oid import ObjectIdentifier
APPLE_NONCE_OID=ObjectIdentifier("1.2.840.113635.100.8.2")
APPLE_ROOT_PEM=Path(__file__).with_name("Apple_App_Attestation_Root_CA.pem")
PROD_AAGUID=b"appattest"+b"\x00"*7
DEV_AAGUID=b"appattestdevelop"
def _b64decode(value):
    raw=value.encode("ascii");raw+=b"="*(-len(raw)%4)
    try:return base64.urlsafe_b64decode(raw)
    except Exception:return base64.b64decode(raw,validate=True)
def _b64encode(value):return base64.b64encode(value).decode("ascii")
def _der_read(data,pos=0):
    if pos>=len(data):raise ValueError("der_truncated")
    tag=data[pos];pos+=1
    if pos>=len(data):raise ValueError("der_truncated_length")
    first=data[pos];pos+=1
    if first&0x80:
        n=first&0x7f
        if n==0 or pos+n>len(data):raise ValueError("der_bad_length")
        length=int.from_bytes(data[pos:pos+n],"big");pos+=n
    else:length=first
    end=pos+length
    if end>len(data):raise ValueError("der_truncated_value")
    return tag,data[pos:end],end
def _find_octet_string(data,expected=None):
    pos=0
    while pos<len(data):
        try:tag,value,end=_der_read(data,pos)
        except ValueError:return None
        if tag==0x04 and (expected is None or value==expected):return value
        if tag&0x20:
            found=_find_octet_string(value,expected)
            if found is not None:return found
        pos=end
    return None
def _verify_cert_signature(cert,issuer):
    pub=issuer.public_key()
    if not isinstance(pub,ec.EllipticCurvePublicKey):raise ValueError("unsupported_issuer_key")
    pub.verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(cert.signature_hash_algorithm))
def _validate_chain(x5c,now):
    if len(x5c)<2:raise ValueError("attestation_certificate_chain_too_short")
    root=x509.load_pem_x509_certificate(APPLE_ROOT_PEM.read_bytes());certs=[x509.load_der_x509_certificate(c) for c in x5c]
    for c in certs:
        if c.not_valid_before_utc>now or c.not_valid_after_utc<now:raise ValueError("attestation_certificate_expired")
    if certs[-1].issuer!=root.subject:raise ValueError("attestation_chain_wrong_root")
    for child,issuer in zip(certs,certs[1:]):
        if child.issuer!=issuer.subject:raise ValueError("attestation_chain_issuer_mismatch")
        _verify_cert_signature(child,issuer)
    _verify_cert_signature(certs[-1],root);return certs[0]
def _parse_auth_data(data,attestation):
    if len(data)<37:raise ValueError("authenticator_data_too_short")
    out={"rp_id_hash":data[:32],"flags":data[32],"counter":struct.unpack(">I",data[33:37])[0]}
    if attestation:
        if len(data)<55:raise ValueError("attestation_authenticator_data_too_short")
        aaguid=data[37:53];cl=struct.unpack(">H",data[53:55])[0];end=55+cl
        if end>len(data):raise ValueError("credential_id_truncated")
        out.update(aaguid=aaguid,credential_id=data[55:end],credential_public_key=cbor2.loads(data[end:]))
    elif len(data)>37:out["extensions"]=cbor2.loads(data[37:])
    return out
def _credential_public_key_from_cert(cert):
    pub=cert.public_key()
    if not isinstance(pub,ec.EllipticCurvePublicKey) or pub.curve.name!="secp256r1":raise ValueError("attested_key_not_p256")
    return pub.public_bytes(Encoding.X962,PublicFormat.UncompressedPoint),pub
def _key_id_bytes(key_id):return _b64decode(key_id)
class AttestationVerifier:
    def __init__(self,mode,app_id,store=None,expected_bundle_version=None):
        self.mode=mode;self.app_id=app_id;self.store=store;self.expected_bundle_version=expected_bundle_version or os.getenv("SHIELD_IOS_BUNDLE_VERSION");self.expected_validation_category=os.getenv("SHIELD_IOS_VALIDATION_CATEGORY")
    def verify_attestation(self,attestation_b64,key_id,challenge):
        try:
            obj=cbor2.loads(base64.b64decode(attestation_b64,validate=True))
            if obj.get("fmt")!="apple-appattest":raise ValueError("unexpected_attestation_format")
            stmt=obj["attStmt"];auth=obj["authData"];x5c=stmt["x5c"]
            if not isinstance(x5c,list) or not all(isinstance(x,bytes) for x in x5c):raise ValueError("invalid_x5c")
            leaf=_validate_chain(x5c,datetime.now(timezone.utc));ad=_parse_auth_data(auth,True);client_hash=hashlib.sha256(challenge).digest();nonce=hashlib.sha256(auth+client_hash).digest();ext=leaf.extensions.get(APPLE_NONCE_OID)
            if ext is None or _find_octet_string(ext.value,nonce)!=nonce:raise ValueError("attestation_nonce_mismatch")
            raw_pub,_=_credential_public_key_from_cert(leaf)
            if hashlib.sha256(raw_pub).digest()!=_key_id_bytes(key_id):raise ValueError("key_id_mismatch")
            if ad["rp_id_hash"]!=hashlib.sha256(self.app_id.encode()).digest():raise ValueError("app_id_hash_mismatch")
            if ad["counter"]!=0:raise ValueError("attestation_counter_not_zero")
            if ad["aaguid"]!=(PROD_AAGUID if self.mode=="production" else DEV_AAGUID):raise ValueError("aaguid_mismatch")
            if ad["credential_id"]!=_key_id_bytes(key_id):raise ValueError("credential_id_mismatch")
            return {"trusted":True,"status":"attested","environment":self.mode,"key_id":key_id,"public_key_der_b64":_b64encode(leaf.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)),"receipt_b64":_b64encode(stmt.get("receipt",b""))}
        except Exception as e:return {"trusted":False,"status":str(e)}
    def update_counter(self,key_id,counter):return bool(key_id and self.store and self.store.update_attestation_counter(key_id,counter))
    def verify_assertion(self,assertion_b64,client_data_hash_hex,key_id,challenge=None,account_id=None,commit_counter=True):
        if not assertion_b64 or not key_id:return {"trusted":False,"status":"missing_assertion" if self.mode=="production" else "development_missing_assertion"}
        try:
            client_hash=bytes.fromhex(client_data_hash_hex)
            if len(client_hash)!=32:raise ValueError("invalid_client_data_hash")
            assertion=cbor2.loads(base64.b64decode(assertion_b64,validate=True));auth_data=assertion["authenticatorData"];signature=assertion["signature"];ad=_parse_auth_data(auth_data,False)
            key=self.store.get_attestation_key(key_id) if self.store else None
            if not key:raise ValueError("unregistered_attestation_key")
            if account_id is not None and key["account_id"]!=account_id:raise ValueError("attestation_key_account_mismatch")
            pub=serialization.load_der_public_key(base64.b64decode(key["public_key_der_b64"]))
            if ad["rp_id_hash"]!=hashlib.sha256(self.app_id.encode()).digest():raise ValueError("assertion_app_id_hash_mismatch")
            if ad["counter"]<=int(key["counter"]):raise ValueError("assertion_counter_not_increasing")
            pub.verify(signature,hashlib.sha256(auth_data+client_hash).digest(),ec.ECDSA(hashes.SHA256()))
            ext=ad.get("extensions") or {}
            if commit_counter and not self.store.update_attestation_counter(key_id,ad["counter"]):raise ValueError("assertion_counter_update_failed")
            return {"trusted":True,"status":"verified","counter":ad["counter"],"extensions":ext}
        except Exception as e:return {"trusted":False,"status":str(e)}
