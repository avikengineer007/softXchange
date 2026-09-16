"""
apps/buyer-assist/buyer_assist/config.py

Configuration for the softXchange buyer-assist service.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_listings.db"
    LISTINGS_SERVICE_URL: str = "http://localhost:8003"
    SCAN_SERVICE_URL: str = "http://localhost:8002"

    # Default similarity threshold to prune unrelated false-positive noise
    DEFAULT_MIN_SCORE: float = 0.25
    DEFAULT_SEARCH_LIMIT: int = 10

    PORT: int = 8005

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
        "https://softxchange-production.up.railway.app",
        "https://softxchange.pages.dev",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
