"""
apps/broker/broker/config.py

Configuration settings for softXchange broker service.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_listings.db"
    LISTINGS_SERVICE_URL: str = "http://localhost:8003"
    BUYER_ASSIST_URL: str = "http://localhost:8005"
    SELLER_ASSIST_URL: str = "http://localhost:8006"
    SCAN_SERVICE_URL: str = "http://localhost:8002"
    AUTH_SERVICE_URL: str = "http://localhost:8001"

    PORT: int = 8007

    # Rolling window duration in days for demand signals
    DEMAND_WINDOW_DAYS: int = 7

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
        "http://localhost:8007",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
