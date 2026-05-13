from __future__ import annotations
import base64
import hashlib
import json
import os

from models import EncryptedEnvelope
from phe.paillier import EncryptedNumber
import subprocess

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
            "public.json",
            f'{settings.proofs_dir}/proof_{voter_uuid}.json'
        ], capture_output=True, text=True)
        return result.returncode == 0

    def load_zk_public_signals(self, proof_path: str):
        """
        Wczytuje sygnały publiczne powiązane z danym dowodem.
        Zakłada, że dla pliku 'proof_123.json' istnieje 'public_123.json' 
        lub korzysta ze stałego pliku public.json.
        """
        # Jeśli proof_path to np. 'proofs/proof_uuid.json', 
        # to public signals zazwyczaj są w tej samej lokalizacji
        public_path = proof_path.replace("proof_", "public_")
        
        if not os.path.exists(public_path):
            # Jeśli nie używasz unikalnych nazw, spróbuj domyślnej
            public_path = "public.json"

        try:
            with open(public_path, "r") as f:
                signals = json.load(f)
                
            # Snarkjs zapisuje liczby jako stringi, warto je zamienić na int
            return [int(s) for s in signals]
        except FileNotFoundError:
            print(f"Błąd: Nie znaleziono pliku sygnałów publicznych: {public_path}")
            return None
        except Exception as e:
            print(f"Błąd podczas wczytywania sygnałów: {e}")
            return None

    # PRZYKŁAD UŻYCIA NA SERWERZE:
    # public_signals[0] -> to nasz 'commitment' (wynik Poseidona)
    # public_signals[1] -> to nasz 'ciphertextHash' (public input do obwodu)

    def process_ballot(self, envelope: EncryptedEnvelope):
        try:
            encrypted_key = b64d(
                envelope["encrypted_key"]
            )

            nonce = b64d(envelope["nonce"])

            ciphertext = b64d(
                envelope["ciphertext"]
            )

            assert envelope["proof_path"] is not None
        except Exception:
            return "INVALID_ENVELOPE"
        
        print(f"S1: {base64.b64decode(envelope['ciphertext'])}")

        ciphertext_int = int.from_bytes(ciphertext, 'big')
        print(f"S2: {ciphertext_int}")


        # 3. LICZENIE HASHA - tutaj musisz podać BAJTY szyfrogramu
        h = hashlib.sha256(ciphertext_int).hexdigest()
        print(f"S3: {h}")

        # 4. Reszta pozostaje bez zmian
        SNARK_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        h_int = int(h, 16) % SNARK_FIELD_PRIME
        
        # 3. Sprawdź czy dowód ZK został wystawiony dla TEJ kotwicy
        # Pobierz sygnały publiczne z dowodu
        print(envelope['proof_path'])
        zk_public_signals = self.load_zk_public_signals(envelope['proof_path'])

        print(zk_public_signals, h_int)

        if int(zk_public_signals[1]) != h_int:
            return "ATAK: Dowód ZK nie pasuje do tego szyfrogramu!"

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

        if not self._verify_credential(token, signature):
            return "INVALID_CREDENTIAL"
        
        if not self._verify_proof(envelope["proof_path"]):
            return "INVALID_PROOF"

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