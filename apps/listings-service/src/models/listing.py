import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ListingStatus(str, Enum):
    DRAFT = "draft"
    PENDING_SCAN = "pending_scan"
    SCAN_PASSED_AWAITING_KYC = "scan_passed_awaiting_kyc"
    SCAN_PASSED_VERIFICATION_UNAVAILABLE = "scan_passed_verification_unavailable"
    LIVE = "live"
    SCAN_FAILED = "scan_failed"
    SUSPENDED = "suspended"
    WITHDRAWN = "withdrawn"


class ScanStatus(str, Enum):
    PENDING_SCAN = "pending_scan"
    PASSED = "passed"
    SCAN_FAILED = "scan_failed"
    ERROR = "error"


class Listing(Base):
    __tablename__ = "listings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    seller_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)
    # Price stored strictly as integer in cents (e.g. 4900 = $49.00)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(64), default=ListingStatus.DRAFT.value, nullable=False, index=True)
    status_message: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    current_version_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    versions: Mapped[List["ListingVersion"]] = relationship(
        "ListingVersion",
        back_populates="listing",
        cascade="all, delete-orphan",
        order_by="desc(ListingVersion.created_at)",
    )
    questions: Mapped[List["BuyerQuestion"]] = relationship(
        "BuyerQuestion",
        back_populates="listing",
        cascade="all, delete-orphan",
        order_by="desc(BuyerQuestion.created_at)",
    )


class ListingVersion(Base):
    __tablename__ = "listing_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    listing_id: Mapped[str] = mapped_column(String(36), ForeignKey("listings.id", ondelete="CASCADE"), nullable=False, index=True)
    version_label: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    scan_status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING_SCAN.value, nullable=False, index=True)
    scan_job_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    storage_location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    findings_summary: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    findings_detail: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    listing: Mapped["Listing"] = relationship("Listing", back_populates="versions")


class BuyerQuestion(Base):
    __tablename__ = "buyer_questions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    listing_id: Mapped[str] = mapped_column(String(36), ForeignKey("listings.id", ondelete="CASCADE"), nullable=False, index=True)
    buyer_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    question_text: Mapped[str] = mapped_column(String(2000), nullable=False)
    seller_response: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    listing: Mapped["Listing"] = relationship("Listing", back_populates="questions")



# ============================================================================
# Pydantic Schemas
# ============================================================================

class ListingCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=255)
    description: str = Field(..., min_length=10, max_length=2000)
    price_cents: int = Field(..., ge=0, description="Price in cents (e.g. 4900 for $49.00, 0 for Free)")
    category: str = Field(..., min_length=2, max_length=64)
    version_label: Optional[str] = "1.0.0"


class ListingUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = Field(None, min_length=10, max_length=2000)
    price_cents: Optional[int] = Field(None, ge=0)
    category: Optional[str] = Field(None, min_length=2, max_length=64)


class ListingVersionResponse(BaseModel):
    id: str
    listing_id: str
    version_label: str
    scan_status: str
    scan_job_id: Optional[str] = None
    storage_location: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ListingResponse(BaseModel):
    id: str
    seller_id: str
    title: str
    description: str
    price_cents: int
    price_usd: float
    category: str
    status: str
    status_message: Optional[str] = None
    current_version_id: Optional[str] = None
    current_version_label: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_listing(cls, listing: Listing) -> "ListingResponse":
        current_label = None
        if listing.versions:
            if listing.current_version_id:
                for v in listing.versions:
                    if v.id == listing.current_version_id:
                        current_label = v.version_label
                        break
            if not current_label and listing.versions:
                current_label = listing.versions[0].version_label

        return cls(
            id=listing.id,
            seller_id=listing.seller_id,
            title=listing.title,
            description=listing.description,
            price_cents=listing.price_cents,
            price_usd=round(listing.price_cents / 100.0, 2),
            category=listing.category,
            status=listing.status,
            status_message=listing.status_message,
            current_version_id=listing.current_version_id,
            current_version_label=current_label,
            created_at=listing.created_at,
            updated_at=listing.updated_at,
        )


class ListingDetailResponse(BaseModel):
    id: str
    seller_id: str
    title: str
    description: str
    price_cents: int
    price_usd: float
    category: str
    status: str
    status_message: Optional[str] = None
    vetted: bool
    badge: str
    current_version: Optional[ListingVersionResponse] = None
    created_at: datetime
    updated_at: datetime


class SellerListingItemResponse(BaseModel):
    id: str
    title: str
    price_cents: int
    price_usd: float
    category: str
    status: str
    status_message: Optional[str] = None
    version_label: Optional[str] = None
    severity_summary: Optional[Dict[str, int]] = None
    next_action: str
    created_at: datetime
    updated_at: datetime


class VersionSubmitRequest(BaseModel):
    version_label: str = Field(..., min_length=1, max_length=32)
    source_type: str = Field("upload", description="'upload' or 'github'")
    git_url: Optional[str] = None
    package_content: Optional[str] = None


class FindingsDetailResponse(BaseModel):
    listing_id: str
    version_id: str
    version_label: str
    scan_status: str
    findings: List[Dict[str, Any]]


class QuestionCreate(BaseModel):
    question_text: str = Field(..., min_length=2, max_length=2000)


class QuestionReply(BaseModel):
    response_text: str = Field(..., min_length=1, max_length=2000)


class QuestionResponse(BaseModel):
    id: str
    listing_id: str
    buyer_id: str
    question_text: str
    seller_response: Optional[str] = None
    created_at: datetime
    responded_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

