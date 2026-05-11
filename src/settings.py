from typing import ClassVar

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    votes_dir: str = 'votes'
    witnesses_dir: str = 'witnesses'
    proofs_dir: str = 'proofs'
    publics_dir: str = 'publics'
    SNARK_FIELD_PRIME: ClassVar[int] = 21888242871839275222246405745257275088548364400416034343698204186575808495617


settings = Settings()
