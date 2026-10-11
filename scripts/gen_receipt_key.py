"""Generate the key that signs ID-check receipts. Run once, by the owner.

Prints a private key (PEM) for the IDENTITY_RECEIPT_KEY environment variable in Render, and the public key plus key id
to pin in the Shield app (shield-app/src/identity/trust.ts). Never commit or paste the private key anywhere else.
Writes nothing to disk.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from identity_core import receipt_public

key = ec.generate_private_key(ec.SECP256R1())
pub, kid = receipt_public(key)
print("# 1. Set this in Render as IDENTITY_RECEIPT_KEY (keep it secret):")
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
print("# 2. Pin this in shield-app/src/identity/trust.ts:")
print(f'  "{kid}": "{pub}",')
