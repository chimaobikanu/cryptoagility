"""Sample payment service — deliberately mixes quantum-vulnerable and modern crypto."""
import hashlib
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3


def make_signing_key():
    # quantum-vulnerable: RSA-2048
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_legacy_key():
    # quantum-vulnerable: EC P-256
    return ec.generate_private_key(ec.SECP256R1())


def make_modern_key():
    # quantum-vulnerable under Shor, despite being modern
    return ed25519.Ed25519PrivateKey.generate()


def hash_password(pw: bytes) -> str:
    return hashlib.md5(pw).hexdigest()          # broken


def legacy_hash(pw: bytes) -> str:
    return hashlib.sha1(pw).hexdigest()          # broken


def session_key():
    return DES3.new(b"0" * 24, DES3.MODE_ECB)    # broken


def issue_token(claims, key):
    return jwt.encode(claims, key, algorithm="RS256")   # RSA via JWT


def encrypt_payload(data: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))  # symmetric, adequate
    return cipher.encryptor()
