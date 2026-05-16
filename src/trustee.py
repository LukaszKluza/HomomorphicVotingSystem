import subprocess

from phe import paillier

from bulletin_board import BulletinBoard
from crypto_utils import sha256_hex, canonical_json
from settings import settings


class Trustee:
    def __init__(self, trustee_id: str, public_key: paillier.PaillierPublicKey):
        self.trustee_id = trustee_id
        self.public_key = public_key

    def approve_tally(self, bulletin_board: BulletinBoard, proof: dict, ciphertext: int) -> dict:
        accepted = (
            self._verify_voting_process(bulletin_board)
            and self._verify_chaum_pedersen(proof, ciphertext)
        )

        return {
            "trustee": self.trustee_id,
            "approved": accepted,
        }

    def _verify_voting_process(self, bulletin_board: BulletinBoard) -> bool:
        for entry in bulletin_board.list_ballots():
            ballot = entry["ballot"]
            ballot_hash = entry["hash"]

            if not self._verify_ballot_signature(ballot, ballot_hash):
                return False

            if not self._verify_single_proof(ballot["voter_uuid"]):
                return False

        return True

    def _verify_ballot_signature(self, ballot: dict, ballot_hash: str) -> bool:
        return sha256_hex(canonical_json(ballot)) == ballot_hash

    def _verify_single_proof(self, voter_uuid: str) -> bool:
        result = subprocess.run([
            "cmd", "/c", "snarkjs", "groth16", "verify",
            "verification_key.json",
            f'{settings.publics_dir}/public_{voter_uuid}.json',
            f'{settings.proofs_dir}/proof_{voter_uuid}.json',
        ], capture_output=True, text=True)

        return result.returncode == 0

    def _verify_chaum_pedersen(self, proof: dict, ciphertext: int) -> bool:
        v, a, A, B, e, s, m = (
            proof["v"], proof["a"], proof["A"], proof["B"],
            proof["e"], proof["s"], proof["m"]
        )
        n, nsquare, g = self.public_key.n, self.public_key.nsquare, self.public_key.g

        calculated_e = int(sha256_hex(canonical_json([g, ciphertext, v, a, A, B])), 16)
        if calculated_e != e:
            return False

        if (pow(g, s, nsquare) * pow(v, e, nsquare)) % nsquare != A:
            return False

        if (pow(ciphertext, s, nsquare) * pow(a, e, nsquare)) % nsquare != B:
            return False

        L_a = (a - 1) // n
        L_v = (v - 1) // n
        mu = pow(L_v, -1, n)
        if (L_a * mu) % n != m:
            return False

        return True
