from dataclasses import dataclass
from uuid import UUID

from vote_result import VoteResult


@dataclass
class BlindCredential:
    token: str
    signature: str


@dataclass
class EncryptedEnvelope:
    encrypted_key: str
    nonce: str
    ciphertext: str
    timestamp: int
    proof_path: str
    voter_uuid: UUID


@dataclass
class BallotRecord:
    ballot_hash: str
    ciphertext: int
    credential_token: str


@dataclass
class BallotStats:
    votes: int = 0
    accepted_votes: int = 0
    invalid_envelopes: int = 0
    crypto_failures: int = 0
    malformed_payloads: int = 0
    invalid_credentials: int = 0
    invalid_proofs: int = 0
    double_votes: int = 0

    def increment_by_status(self, status: VoteResult):
        self.votes += 1
        mapping = {
            VoteResult.INVALID_ENVELOPE: "invalid_envelopes",
            VoteResult.CRYPTO_FAILURE: "crypto_failures",
            VoteResult.MALFORMED_PAYLOAD: "malformed_payloads",
            VoteResult.INVALID_CREDENTIAL: "invalid_credentials",
            VoteResult.INVALID_PROOF: "invalid_proofs",
            VoteResult.DOUBLE_VOTE: "double_votes",
            VoteResult.ACCEPTED: "accepted_votes"
        }

        field_name = mapping.get(status)
        if field_name and hasattr(self, field_name):
            current_value = getattr(self, field_name)
            setattr(self, field_name, current_value + 1)

