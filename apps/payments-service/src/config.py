from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_payments.db"

    # Stripe Configuration (payments-service is the sole custodian)
    STRIPE_SECRET_KEY: str = "sk_test_softxchange_mock_secret"
    STRIPE_PUBLISHABLE_KEY: str = "pk_test_softxchange_mock_pub"
    STRIPE_WEBHOOK_SECRET: str = "whsec_softxchange_mock_webhook_secret"

    # Inter-Service Communication
    AUTH_SERVICE_URL: str = "http://localhost:8001"
    LISTINGS_SERVICE_URL: str = "http://localhost:8003"
    FRONTEND_URL: str = "http://localhost:8000"
    INTERNAL_SERVICE_SECRET: str = "softxchange-internal-hmac-secret-dev"

    # Economics & Fee Configuration
    PLATFORM_FEE_PERCENT: float = 8.0  # 8% flat marketplace fee

    # Storage & Secure Download Signing
    DOWNLOAD_LINK_TTL_SECONDS: int = 900  # 15 minutes
    DOWNLOAD_SIGNING_SECRET: str = "softxchange-download-hmac-secret-dev"

    # JWKS Caching
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
        "http://localhost:8004",
        "http://127.0.0.1:8004",
        "https://softxchange-production.up.railway.app",
        "https://softxchange.pages.dev",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
