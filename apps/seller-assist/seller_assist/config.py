"""
apps/seller-assist/seller_assist/config.py

Configuration settings for seller-assist service.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_listings.db"
    LISTINGS_SERVICE_URL: str = "http://localhost:8003"
    AUTH_SERVICE_URL: str = "http://localhost:8001"
    SCAN_SERVICE_URL: str = "http://localhost:8002"

    JWKS_URL: str = "http://localhost:8001/.well-known/jwks.json"

    DEFAULT_K_COMPARABLES: int = 3
    DEFAULT_CURRENCY: str = "USD"
    DEFAULT_REGION: str = "US"

    PORT: int = 8006

    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://localhost:8001",
        "http://localhost:8002",
        "http://localhost:8003",
        "http://localhost:8004",
        "http://localhost:8005",
        "http://localhost:8006",
        "https://softxchange-production.up.railway.app",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
