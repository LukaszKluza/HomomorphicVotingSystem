from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import settings

FS_BITS = 256
RSA_KEY_SIZE = 3072
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TOKEN_BYTES = 32


def canonical_json(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


def now() -> int:
    return int(time.time())


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_rsa_keypair():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    return priv, priv.public_key()


def rsa_pss_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        return False


def rsa_oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    nonce = secrets.token_bytes(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        None,
    )

    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None,
    )


def random_token() -> str:
    return secrets.token_hex(TOKEN_BYTES)


def generate_secure_r(n: int) -> int:
    while True:
        r = secrets.randbelow(n)

        if r > 0 and math.gcd(r, n) == 1:
            return r
        
def get_zk_binding_hash(encrypted_vote: int) -> int:
    ciphertext_bytes = encrypted_vote.to_bytes((encrypted_vote.bit_length() + 7) // 8, 'big')
    h = hashlib.sha256(ciphertext_bytes).hexdigest()
    return int(h, 16) % settings.Settings.SNARK_FIELD_PRIME