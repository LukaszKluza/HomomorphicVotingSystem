from crypto_utils import sha256_hex, canonical_json
from models import BallotStats
from vote_result import VoteResult


class BulletinBoard:
    def __init__(self):
        self.ballots = []
        self.stats = BallotStats()

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
    
    def update_stats(self, status: VoteResult):
        self.stats.increment_by_status(status)