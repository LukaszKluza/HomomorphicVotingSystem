from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    votes_dir: str = 'votes'
    witnesses_dir: str = 'witnesses'
    proofs_dir: str = 'proofs'

settings = Settings()
