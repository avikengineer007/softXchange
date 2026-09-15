from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_listings.db"

    # Upstream Services
    AUTH_SERVICE_URL: str = "http://localhost:8001"
    SCAN_SERVICE_URL: str = "http://localhost:8002"
    PAYMENTS_SERVICE_URL: str = "http://localhost:8004"
    INTERNAL_SERVICE_SECRET: str = "softxchange-internal-hmac-secret-dev"

    # JWKS Key Cache Lifespan (seconds)
    JWKS_CACHE_TTL_SECONDS: int = 3600

    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://localhost:8001",
        "http://localhost:8002",
        "http://localhost:8003",
        "https://softxchange-production.up.railway.app",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
