from phe import paillier

from crypto_utils import canonical_json, generate_rsa_keypair, rsa_pss_sign


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

    def decrypt_tally(self, encrypted_sum):
        return self._paillier_priv.decrypt(encrypted_sum)