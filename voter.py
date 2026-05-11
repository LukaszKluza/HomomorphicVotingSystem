from __future__ import annotations

import secrets

from crypto_utils import (
    AES_KEY_SIZE,
    aes_gcm_encrypt,
    b64e,
    canonical_json,
    generate_secure_r,
    random_token,
    rsa_oaep_encrypt,
)
from models import EncryptedEnvelope


class Voter:
    def __init__(
        self,
        auth_authority,
        voting_server_pubkey,
        paillier_pub,
    ):
        self.auth_authority = auth_authority
        self.voting_server_pubkey = voting_server_pubkey
        self.paillier_pub = paillier_pub

        self.credential_token = random_token()

        self.credential_signature = (
            self.auth_authority.issue_credential(
                self.credential_token
            )
        )

    def cast_vote(self, vote: int):
        if vote not in (0, 1):
            raise ValueError("Vote must be 0 or 1")
        
        vote = 1233

        n = self.paillier_pub.n
        nsquare = self.paillier_pub.nsquare
        g = n + 1

        r = generate_secure_r(n)

        ciphertext = (
            pow(g, vote, nsquare)
            * pow(r, n, nsquare)
        ) % nsquare

        payload = canonical_json(
            {
                "credential_token": self.credential_token,
                "credential_signature": b64e(
                    self.credential_signature
                ),
                "ciphertext": ciphertext,
            }
        )

        aes_key = secrets.token_bytes(AES_KEY_SIZE)

        nonce, encrypted_payload = aes_gcm_encrypt(
            aes_key,
            payload,
        )

        encrypted_key = rsa_oaep_encrypt(
            self.voting_server_pubkey,
            aes_key,
        )

        return EncryptedEnvelope(
            encrypted_key=b64e(encrypted_key),
            nonce=b64e(nonce),
            ciphertext=b64e(encrypted_payload),
            timestamp=0,
        ).__dict__