from __future__ import annotations
import json

from models import EncryptedEnvelope
from phe.paillier import EncryptedNumber
import subprocess
from vote_result import VoteResult

from bulletin_board import BulletinBoard
from crypto_utils import (
    aes_gcm_decrypt,
    b64d,
    canonical_json,
    generate_rsa_keypair,
    get_zk_binding_hash,
    rsa_oaep_decrypt,
    rsa_pss_verify,
    sha256_hex,
)
from replay_db import ReplayProtectionDB
from settings import settings


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

    def _verify_credential(
        self,
        token: str,
        signature: bytes,
    ) -> bool:
        return rsa_pss_verify(
            self.auth_public_key,
            signature,
            canonical_json({"token": token}),
        )
    
    @staticmethod
    def _verify_proof(voter_uuid):        
        result = subprocess.run([
            "cmd", "/c", "snarkjs", "groth16", "verify",
            "verification_key.json",
            f'{settings.publics_dir}/public_{voter_uuid}.json',
            f'{settings.proofs_dir}/proof_{voter_uuid}.json',
        ], capture_output=True, text=True)

        return result.returncode == 0

    @staticmethod
    def _load_zk_public_signals(voter_uuid: str):
        public_path =  f'{settings.publics_dir}/public_{voter_uuid}.json'
        try:
            with open(public_path, "r") as f:
                signals = json.load(f)
                
            return [int(s) for s in signals]
        except FileNotFoundError:
            print(f"Error: public file not found: {public_path}")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None

    def process_ballot(self, envelope: EncryptedEnvelope):
        try:
            encrypted_key = b64d(envelope.encrypted_key)
            nonce = b64d(envelope.nonce)
            ciphertext = b64d(envelope.ciphertext)

            assert envelope.proof_path is not None
        except Exception:
            return VoteResult.INVALID_ENVELOPE

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
            self.board.update_stats(VoteResult.CRYPTO_FAILURE)
            return VoteResult.CRYPTO_FAILURE

        try:
            payload = json.loads(plaintext)
            token = payload['credential_token']
            signature = b64d(payload['credential_signature'])
            encrypted_vote = int(payload['ciphertext'])
        except Exception as e:
            self.board.update_stats(VoteResult.MALFORMED_PAYLOAD)
            return VoteResult.MALFORMED_PAYLOAD

        if not self._verify_credential(token, signature):
            self.board.update_stats(VoteResult.INVALID_CREDENTIAL)
            return VoteResult.INVALID_CREDENTIAL
        
        zk_public_signals = self._load_zk_public_signals(envelope.voter_uuid)
        h_int = get_zk_binding_hash(encrypted_vote)
        
        if not self._verify_proof(envelope.voter_uuid) or int(zk_public_signals[1]) != h_int:
            self.board.update_stats(VoteResult.INVALID_PROOF)
            return VoteResult.INVALID_PROOF

        if not self.replay_db.consume_token(token):
            self.board.update_stats(VoteResult.DOUBLE_VOTE)
            return VoteResult.DOUBLE_VOTE

        ballot = {
            'ciphertext': encrypted_vote,
            'token_hash': sha256_hex(
                token.encode()
            ),
            'proof_path': envelope.proof_path,
            'voter_uuid': str(envelope.voter_uuid),
        }

        ballot_hash = self.board.publish(ballot)

        self.encrypted_votes.append(
            EncryptedNumber(
                self.paillier_pub,
                encrypted_vote,
            )
        )

        self.board.update_stats(VoteResult.ACCEPTED)
        return {
            "status": VoteResult.ACCEPTED,
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