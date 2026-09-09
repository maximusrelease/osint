from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Backend API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # XposedOrNot Configuration
    XPOSEDORNOT_API_BASE_URL: str = "https://api.xposedornot.com/v1"
    XPOSEDORNOT_TIMEOUT_SECONDS: float = 10.0
    XPOSEDORNOT_ENABLE_MOCK_FALLBACK: bool = True

    # Holehe OSINT Configuration
    HOLEHE_ENABLED: bool = True
    HOLEHE_TIMEOUT_SECONDS: float = 8.0
    HOLEHE_MAX_CONCURRENCY: int = 30
    HOLEHE_ONLY_DETECTED: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
