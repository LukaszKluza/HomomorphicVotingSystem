from enum import Enum

class VoteResult(Enum):
    INVALID_ENVELOPE = 1
    CRYPTO_FAILURE = 2
    DOUBLE_VOTE = 3
    INVALID_CREDENTIAL = 4
    MALFORMED_PAYLOAD  = 5
    INVALID_PROOF = 6
    ACCEPTED = 7