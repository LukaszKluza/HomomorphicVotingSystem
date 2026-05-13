from __future__ import annotations

import hashlib
import secrets
import subprocess
import json
import uuid

from invalid_vote_exception import InvalidVoteException
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
from settings import settings


class Voter:
    def __init__(
        self,
        auth_authority,
        voting_server_pubkey,
        paillier_pub,
    ):
        self.voter_uuid = uuid.uuid4()
        self.auth_authority = auth_authority
        self.voting_server_pubkey = voting_server_pubkey
        self.paillier_pub = paillier_pub

        self.credential_token = random_token()

        self.credential_signature = (
            self.auth_authority.issue_credential(
                self.credential_token
            )
        )

    def _generate_vote(self, vote, encrypted_vote):        
        # 2. Skonwertuj hash na int i ogranicz go do zakresu pola Circom (modulo prime)
        # To jest ta magiczna liczba p dla krzywej BN128
        # Zamiast str(ciphertext).encode()
        print(f"C1: {encrypted_vote}")
        ciphertext_bytes = int(encrypted_vote).to_bytes((int(encrypted_vote).bit_length() + 7) // 8, 'big')
        print(f"C2: {ciphertext_bytes}")
        h = hashlib.sha256(ciphertext_bytes).hexdigest()
        print(f"C3: {h}")
        h_int = int(h, 16) % 21888242871839275222246405745257275088548364400416034343698204186575808495617
        file_name = f'input_{self.voter_uuid}.json'
        with open(f'{settings.votes_dir}/{file_name}', "w") as f:
            json.dump({"vote": vote, "randomness": 1, "ciphertextHash": str(h_int)}, f)

    def _generate_witness(self):
        file_name = f'witness_{self.voter_uuid}.wtns'
        input_file = f'input_{self.voter_uuid}.json'
        
        try:
            subprocess.run([
                "node",
                "vote_js/generate_witness.js",
                "vote_js/vote.wasm",
                f'{settings.votes_dir}/{input_file}',
                f'{settings.witnesses_dir}/{file_name}'
            ], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            if "Assert Failed" in e.stderr:
                raise InvalidVoteException()
            print(f"Node Error Output: {e.stderr}")
            raise e

    def _generate_proof(self):
        file_name = f'proof_{self.voter_uuid}.json'
        subprocess.run([
            "cmd", "/c", "snarkjs", "groth16", "prove",
            "vote_final.zkey",
            f'{settings.witnesses_dir}/witness_{self.voter_uuid}.wtns',
            f'{settings.proofs_dir}/{file_name}',
            "public.json"
        ], check=True)

        return file_name
    
    def generate_proof(self, vote, encrypted_vote):
        self._generate_vote(vote, encrypted_vote)
        self._generate_witness()
        return self._generate_proof()

    def cast_vote(self, vote: int):
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

        proof = None

        try:
            proof = self.generate_proof(vote, ciphertext)
        except InvalidVoteException:
            pass

        return EncryptedEnvelope(
            encrypted_key=b64e(encrypted_key),
            nonce=b64e(nonce),
            ciphertext=b64e(encrypted_payload),
            timestamp=0,
            proof_path=proof
        ).__dict__