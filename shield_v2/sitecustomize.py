# Compatibility shim for the App Attest verifier's certificate extension lookup.
from cryptography import x509
if not hasattr(x509.Extensions,"get"):
    def _get(self,oid):
        return self.get_extension_for_oid(oid).value
    x509.Extensions.get=_get
