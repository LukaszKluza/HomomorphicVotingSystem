from __future__ import annotations

from phe.paillier import EncryptedNumber

from bulletin_board import BulletinBoard
from crypto_utils import (
    aes_gcm_decrypt,
    b64d,
    canonical_json,
    generate_rsa_keypair,
    rsa_oaep_decrypt,
    rsa_pss_verify,
    sha256_hex,
)
from replay_db import ReplayProtectionDB

class VotingServer:
    def __init__(
        self,
        auth_public_key,
        paillier_pub,
    ):
        self.private_key, self.public_key = generate_rsa_keypair()

        self.auth_public_key = auth_public_key
        self.paillier_pub = paillier_pub

        self.replay_db = ReplayProtectionDB()
        self.board = BulletinBoard()

        self.encrypted_votes = []

    def verify_credential(
        self,
        token: str,
        signature: bytes,
    ) -> bool:
        return rsa_pss_verify(
            self.auth_public_key,
            signature,
            canonical_json({"token": token}),
        )

    def process_ballot(self, envelope: dict):
        try:
            encrypted_key = b64d(
                envelope["encrypted_key"]
            )

            nonce = b64d(envelope["nonce"])

            ciphertext = b64d(
                envelope["ciphertext"]
            )

        except Exception:
            return "INVALID_ENVELOPE"

        try:
            aes_key = rsa_oaep_decrypt(
                self.private_key,
                encrypted_key,
            )

            plaintext = aes_gcm_decrypt(
                aes_key,
                nonce,
                ciphertext,
            )

        except Exception:
            return "CRYPTO_FAILURE"

        try:
            import json

            payload = json.loads(plaintext)

            token = payload["credential_token"]
            signature = b64d(
                payload["credential_signature"]
            )
            encrypted_vote = int(payload["ciphertext"])

        except Exception:
            return "MALFORMED_PAYLOAD"

        if not self.verify_credential(token, signature):
            return "INVALID_CREDENTIAL"

        if not self.replay_db.consume_token(token):
            return "DOUBLE_VOTE"

        ballot = {
            "ciphertext": encrypted_vote,
            "token_hash": sha256_hex(
                token.encode()
            ),
        }

        ballot_hash = self.board.publish(ballot)

        self.encrypted_votes.append(
            EncryptedNumber(
                self.paillier_pub,
                encrypted_vote,
            )
        )

        return {
            "status": "ACCEPTED",
            "ballot_hash": ballot_hash,
        }

    def encrypted_tally(self):
        if not self.encrypted_votes:
            return EncryptedNumber(
                self.paillier_pub,
                0,
            )

        total = self.encrypted_votes[0]

        for vote in self.encrypted_votes[1:]:
            total += vote

        return total