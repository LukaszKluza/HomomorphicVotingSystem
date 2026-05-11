from crypto_utils import sha256_hex, canonical_json


class BulletinBoard:
    def __init__(self):
        self.ballots = []

    def publish(self, ballot: dict):
        ballot_hash = sha256_hex(canonical_json(ballot))

        self.ballots.append(
            {
                "hash": ballot_hash,
                "ballot": ballot,
            }
        )

        return ballot_hash

    def list_ballots(self):
        return self.ballots