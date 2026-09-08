from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Backend API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Have I Been Pwned (HIBP) Configuration
    HIBP_API_KEY: str = ""
    HIBP_USER_AGENT: str = "OSINT-Intel-Platform/1.0"
    HIBP_API_BASE_URL: str = "https://haveibeenpwned.com/api/v3"
    HIBP_TIMEOUT_SECONDS: float = 10.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
