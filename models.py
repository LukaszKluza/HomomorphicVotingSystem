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


@dataclass
class BallotRecord:
    ballot_hash: str
    ciphertext: int
    credential_token: str