from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid
from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from pydantic import BaseModel, ConfigDict, Field

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class OrderStatus(str, Enum):
    PENDING_PAYMENT = "pending_payment"
    PAID = "paid"
    REFUNDED = "refunded"
    DISPUTED = "disputed"


class HoldStatus(str, Enum):
    NONE = "none"
    HELD = "held"
    RELEASED = "released"
    REFUNDED = "refunded"


class Order(Base):
    """
    Represents a buyer's purchase of an immutable, vetted software listing version.
    """
    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    listing_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    # Pinned to exact version purchased for version immutability guarantee
    listing_version_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    buyer_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    seller_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    platform_fee_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    seller_payout_cents: Mapped[int] = mapped_column(Integer, nullable=False)

    status: Mapped[str] = mapped_column(String(32), default=OrderStatus.PENDING_PAYMENT.value, nullable=False, index=True)
    
    # Per-order isolated fraud hold
    hold_status: Mapped[str] = mapped_column(String(32), default=HoldStatus.NONE.value, nullable=False, index=True)
    hold_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    held_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    stripe_payment_intent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    stripe_transfer_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    @property
    def amount_usd(self) -> float:
        return round(float(self.amount_cents) / 100.0, 2)


# ============================================================================
# Pydantic Schemas
# ============================================================================

class OrderCreateRequest(BaseModel):
    listing_id: str = Field(..., description="ID of the listing to purchase")


class OrderResponse(BaseModel):
    id: str
    listing_id: str
    listing_version_id: str
    buyer_id: str
    seller_id: str
    amount_cents: int
    amount_usd: float = 0.0
    platform_fee_cents: int
    seller_payout_cents: int
    status: str
    hold_status: str
    hold_reason: Optional[str] = None
    held_at: Optional[datetime] = None
    stripe_payment_intent_id: Optional[str] = None
    client_secret: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_order(cls, order: Order, client_secret: Optional[str] = None) -> "OrderResponse":
        return cls(
            id=order.id,
            listing_id=order.listing_id,
            listing_version_id=order.listing_version_id,
            buyer_id=order.buyer_id,
            seller_id=order.seller_id,
            amount_cents=order.amount_cents,
            amount_usd=round(float(order.amount_cents) / 100.0, 2),
            platform_fee_cents=order.platform_fee_cents,
            seller_payout_cents=order.seller_payout_cents,
            status=order.status,
            hold_status=order.hold_status,
            hold_reason=order.hold_reason,
            held_at=order.held_at,
            stripe_payment_intent_id=order.stripe_payment_intent_id,
            client_secret=client_secret,
            created_at=order.created_at,
            updated_at=order.updated_at,
        )


class HeldOrderResponse(BaseModel):
    id: str
    listing_id: str
    buyer_id: str
    seller_id: str
    amount_cents: int
    amount_usd: float
    hold_status: str
    hold_reason: Optional[str] = None
    held_at: datetime
    hours_held: float
    sla_breached: bool  # > 48 hours
