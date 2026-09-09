from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from pydantic import BaseModel, ConfigDict

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EntitlementStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class Entitlement(Base):
    """
    Proves a buyer purchased a specific immutable software listing version
    and is authorized to download it.
    """
    __tablename__ = "entitlements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    buyer_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    listing_version_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default=EntitlementStatus.ACTIVE.value, nullable=False, index=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class EntitlementResponse(BaseModel):
    id: str
    order_id: str
    buyer_id: str
    listing_version_id: str
    status: str
    created_at: datetime
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
