from typing import List, Optional, Literal
import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./softxchange_auth.db"

    # -------------------------------------------------------------------------
    # JWT & Cryptographic Key Management
    # -------------------------------------------------------------------------
    # RS256 (asymmetric) is preferred so downstream services (listings-service,
    # payments-service) only need the public key to verify tokens and never hold
    # the signing secret.
    #
    # GUARDRAIL: HS256 is strictly for local dev/isolated testing fallback.
    # In multi-service deployments, HS256 must NOT be used because sharing a
    # symmetric secret across services violates isolation principles.
    JWT_ALGORITHM: str = "RS256"

    # PEM-encoded RSA keys (inline string or file paths)
    JWT_PRIVATE_KEY: Optional[str] = None
    JWT_PUBLIC_KEY: Optional[str] = None
    JWT_PRIVATE_KEY_PATH: Optional[str] = None
    JWT_PUBLIC_KEY_PATH: Optional[str] = None

    # Fallback symmetric secret (only used when JWT_ALGORITHM is HS256 in dev/test)
    JWT_SECRET_KEY: str = "dev-secret-manifest-softxchange-replace-in-production"

    # Token Lifespans
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Short-lived access tokens (15 min)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7     # Server-side tracked refresh tokens

    # Inter-Service HMAC Secret (for payments-service webhook bridge)
    INTERNAL_SERVICE_SECRET: str = "softxchange-internal-hmac-secret-dev"

    # Refresh Token Cookie Settings
    # In production, COOKIE_SECURE must be True.
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    COOKIE_PATH: str = "/auth"

    # Rate Limiting (per-IP and per-email)
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Verification Tokens Lifespans
    EMAIL_VERIFY_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
    ]

    # -------------------------------------------------------------------------
    # Admin Role & Code-Gated Provisioning Settings (Prompt 3)
    # -------------------------------------------------------------------------
    ADMIN_PROVISIONING_CODE: Optional[str] = "sx_admin_sec_9f7a28e4c19d4b8e8f2a1b3c4d5e6f7a"
    ADMIN_PROVISIONING_CODE_HASH: Optional[str] = None
    ADMIN_PROVISION_MAX_ATTEMPTS: int = 3
    ADMIN_PROVISION_WINDOW_HOURS: int = 1
    ADMIN_CODE_EXPLICITLY_ROTATED: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

# Automatically enforce secure cookies in production if not explicitly overridden
if settings.ENVIRONMENT.lower() == "production" and not settings.COOKIE_SECURE:
    settings.COOKIE_SECURE = True
