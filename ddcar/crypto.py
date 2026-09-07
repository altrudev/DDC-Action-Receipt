import base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .canonical import canonical_bytes

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def b64u_decode(s):
    if not isinstance(s,str) or not __import__('re').fullmatch(r'[A-Za-z0-9_-]+',s): raise ValueError('invalid base64url')
    b=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    if b64u(b)!=s: raise ValueError('noncanonical base64url')
    return b

def sha256_bytes(data): return 'sha256:'+hashlib.sha256(data).hexdigest()
def sha256_digest(obj): return sha256_bytes(canonical_bytes(obj))
def generate_keypair():
    sk=Ed25519PrivateKey.generate()
    return b64u(sk.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())), b64u(sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
def public_from_private(private):
    return b64u(Ed25519PrivateKey.from_private_bytes(b64u_decode(private)).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
def sign_obj(obj,private,domain):
    return b64u(Ed25519PrivateKey.from_private_bytes(b64u_decode(private)).sign(b'DDCAR\0'+domain.encode('ascii')+b'\0'+canonical_bytes(obj)))
def verify_obj(obj,signature,public,domain):
    Ed25519PublicKey.from_public_bytes(b64u_decode(public)).verify(b64u_decode(signature),b'DDCAR\0'+domain.encode('ascii')+b'\0'+canonical_bytes(obj))
