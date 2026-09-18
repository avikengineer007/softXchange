from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SellerPaymentProfile(Base):
    """
    Stores seller Razorpay Route linked account linkage.
    
    SINGLE SOURCE OF TRUTH:
    This table strictly does NOT store kyc_status or payout_enabled.
    Those flags remain exclusively owned by auth-service's SellerProfile.
    """
    __tablename__ = "seller_payment_profiles"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    razorpay_account_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
