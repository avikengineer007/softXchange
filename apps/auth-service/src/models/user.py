import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from sqlalchemy import String, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Normalize datetime to timezone-aware UTC datetime."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class UserRole(str, Enum):
    CUSTOMER = "customer"
    SELLER = "seller"
    ADMIN = "admin"


class KYCStatus(str, Enum):
    NOT_STARTED = "not_started"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Roles: a user can be "customer", "seller", or both (list of strings)
    roles: Mapped[List[str]] = mapped_column(JSON, default=lambda: ["customer"], nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    verification_tokens: Mapped[List["VerificationToken"]] = relationship("VerificationToken", back_populates="user", cascade="all, delete-orphan")
    seller_profile: Mapped[Optional["SellerProfile"]] = relationship("SellerProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")

    @property
    def role(self) -> str:
        """Backward compatibility helper returning primary role string."""
        if self.roles and len(self.roles) > 0:
            return self.roles[0]
        return UserRole.CUSTOMER.value

    @property
    def kyc_status(self) -> str:
        """Helper to get KYC status from seller profile if exists, else not_started."""
        if self.seller_profile:
            return self.seller_profile.kyc_status
        return KYCStatus.NOT_STARTED.value


class RefreshToken(Base):
    """Server-side revocable refresh tokens hashed with SHA-256."""
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")


class SellerProfile(Base):
    """Seller KYC profile and payout gating state machine."""
    __tablename__ = "seller_profiles"

    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    kyc_status: Mapped[str] = mapped_column(String(32), default=KYCStatus.NOT_STARTED.value, nullable=False, index=True)
    payout_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    payout_account_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    kyc_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="seller_profile")


class VerificationToken(Base):
    """Single-use hashed tokens for email verification and password reset."""
    __tablename__ = "verification_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # 'email_verify' or 'password_reset'
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="verification_tokens")


# ============================================================================
# Pydantic Schemas
# ============================================================================

class UserSignup(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    roles: Optional[List[str]] = Field(default=None, description="Roles to register as: customer, seller, or both")
    role: Optional[str] = Field(default=None, description="Legacy single role field")
    display_name: Optional[str] = None

    @field_validator("roles", mode="before")
    @classmethod
    def validate_roles(cls, v):
        if v is None:
            return None
        valid_roles = {UserRole.CUSTOMER.value, UserRole.SELLER.value, UserRole.ADMIN.value}
        if isinstance(v, str):
            v = [v]
        cleaned = [r.lower().strip() for r in v]
        for r in cleaned:
            if r not in valid_roles:
                raise ValueError(f"Invalid role: {r}. Must be 'customer' or 'seller'")
        return cleaned


# Keep UserCreate as alias for UserSignup for backward compat
UserCreate = UserSignup


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    roles: List[str]
    role: Optional[str] = None
    email_verified: bool
    display_name: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs):
        resp = super().model_validate(obj, **kwargs)
        if hasattr(obj, "role") and not resp.role:
            resp.role = getattr(obj, "role")
        return resp


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class SignupSuccessResponse(BaseModel):
    message: str
    user_id: str
    email: str
    email_verified: bool = False
    verification_token: Optional[str] = None  # Returned only in dev/test mode


class MessageResponse(BaseModel):
    message: str


class EmailVerifyRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, description="New password (min 8 characters)")


class KYCStartResponse(BaseModel):
    message: str
    user_id: str
    kyc_status: str
    onboarding_url: Optional[str] = None


class KYCStatusResponse(BaseModel):
    user_id: str
    kyc_status: str
    payout_enabled: bool
    details: Optional[Dict[str, Any]] = None


class KYCWebhookPayload(BaseModel):
    user_id: str
    event: str
    status: str  # "verified" or "rejected"
    details: Optional[Dict[str, Any]] = None
