from pydantic import BaseSettings

class Settings(BaseSettings):
    SOLANA_RPC_URL: str
    PROGRAM_ID: str
    IPFS_GATEWAY: str
    SECRET_KEY: str

    class Config:
        env_file = ".env"

settings = Settings()
