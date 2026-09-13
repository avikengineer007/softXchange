import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NotificationType(str, Enum):
    SCAN_PASSED = "scan_passed"
    SCAN_FAILED = "scan_failed"
    ORDER_PAID = "order_paid"
    QUESTION_ASKED = "question_asked"
    QUESTION_ANSWERED = "question_answered"
    KYC_VERIFIED = "kyc_verified"
    KYC_REJECTED = "kyc_rejected"
    LISTING_REVIEW_RECEIVED = "listing_review_received"
    GITHUB_CONNECTED = "github_connected"
    GITHUB_DISCONNECTED = "github_disconnected"


ALL_NOTIFICATION_TYPES = {t.value for t in NotificationType}


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


# ============================================================================
# Pydantic Schemas
# ============================================================================

class NotificationEmitRequest(BaseModel):
    user_id: str
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class NotificationResponse(BaseModel):
    id: str
    user_id: str
    type: str
    payload: Dict[str, Any]
    read_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NotificationListResponse(BaseModel):
    notifications: List[NotificationResponse]
    total: int
    unread_count: int


class UnreadCountResponse(BaseModel):
    unread_count: int
