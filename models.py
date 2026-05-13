from dataclasses import dataclass


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


@dataclass
class BallotRecord:
    ballot_hash: str
    ciphertext: int
    credential_token: str


@dataclass
class BallotStats:
    invalid_envelopes: int = 0
    crypto_failures: int = 0
    malformed_pyloads: int = 0
    invalid_credentials: int = 0
    invalid_proofs: int = 0
    double_votes: int = 0

