import math
import secrets
from phe import paillier, EncryptedNumber

from crypto_utils import canonical_json, generate_rsa_keypair, rsa_pss_sign, sha256_hex


class AuthenticationAuthority:
    def __init__(self):
        self.private_key, self.public_key = generate_rsa_keypair()

    def issue_credential(self, token: str) -> bytes:
        return rsa_pss_sign(
            self.private_key,
            canonical_json({"token": token}),
        )


class TallyAuthority:
    def __init__(self):
        self.paillier_pub, self._paillier_priv = (
            paillier.generate_paillier_keypair(n_length=3072)
        )
        self.lambda_value = math.lcm(self._paillier_priv.p - 1, self._paillier_priv.q - 1)
        self.v = pow(self.paillier_pub.g, self.lambda_value, self.paillier_pub.nsquare)

    def decrypt_tally(self, encrypted_sum: EncryptedNumber) -> int:
        return self._paillier_priv.decrypt(encrypted_sum)

    def chaum_pedersen_prove(self, ciphertext: int) -> dict:
        n, nsquare, g = self.paillier_pub.n, self.paillier_pub.nsquare, self.paillier_pub.g
        k = secrets.randbelow(n - 1) + 1
        a = pow(ciphertext, self.lambda_value, nsquare)
        A = pow(g, k, nsquare)
        B = pow(ciphertext, k, nsquare)
        e = int(sha256_hex(canonical_json([g, ciphertext, self.v, a, A, B])), 16)
        s = k - e * self.lambda_value
        L_v = (self.v - 1) // n
        mi = pow(L_v, -1, n)
        m = (((a - 1) // n) * mi) % n

        return {"v": self.v, "a": a, "A": A, "B": B, "e": e, "s": s, "m": m}
