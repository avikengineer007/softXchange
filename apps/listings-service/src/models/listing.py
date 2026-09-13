import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator
from sqlalchemy import String, Integer, Boolean, DateTime, JSON, ForeignKey, UniqueConstraint
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
    reviews: Mapped[List["Review"]] = relationship(
        "Review",
        back_populates="listing",
        cascade="all, delete-orphan",
        order_by="desc(Review.created_at)",
    )
    saved_by: Mapped[List["SavedListing"]] = relationship(
        "SavedListing",
        back_populates="listing",
        cascade="all, delete-orphan",
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
    draft_reply: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    listing: Mapped["Listing"] = relationship("Listing", back_populates="questions")


class SearchEvent(Base):
    """
    Search event log for demand signal aggregation.
    Guarantees strict buyer privacy: stores ZERO buyer IDs or user identity information.
    """
    __tablename__ = "buyer_search_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    query_text: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    matched_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class Review(Base):
    """
    Verified-purchase buyer review for a software listing.
    One review per (buyer_id, listing_id); resubmissions update in-place.
    """
    __tablename__ = "listing_reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    listing_id: Mapped[str] = mapped_column(String(36), ForeignKey("listings.id", ondelete="CASCADE"), nullable=False, index=True)
    listing_version_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    buyer_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    rating: Mapped[int] = mapped_column(Integer, nullable=False)
    review_text: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    listing: Mapped["Listing"] = relationship("Listing", back_populates="reviews")

    __table_args__ = (
        UniqueConstraint("buyer_id", "listing_id", name="uq_buyer_listing_review"),
    )


class SavedListing(Base):
    """
    Wishlist bookmark joining a buyer to a saved listing.
    Idempotent: unique on (buyer_id, listing_id).
    """
    __tablename__ = "saved_listings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    buyer_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    listing_id: Mapped[str] = mapped_column(String(36), ForeignKey("listings.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    listing: Mapped["Listing"] = relationship("Listing", back_populates="saved_by")

    __table_args__ = (
        UniqueConstraint("buyer_id", "listing_id", name="uq_buyer_saved_listing"),
    )




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
    average_rating: Optional[float] = None
    review_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_listing(
        cls,
        listing: Listing,
        average_rating: Optional[float] = None,
        review_count: Optional[int] = None,
    ) -> "ListingResponse":
        current_label = None
        if listing.versions:
            if listing.current_version_id:
                for v in listing.versions:
                    if v.id == listing.current_version_id:
                        current_label = v.version_label
                        break
            if not current_label and listing.versions:
                current_label = listing.versions[0].version_label

        if average_rating is None and hasattr(listing, "reviews") and listing.reviews:
            ratings = [r.rating for r in listing.reviews]
            if ratings:
                average_rating = round(sum(ratings) / len(ratings), 2)
                review_count = len(ratings)
        if review_count is None:
            review_count = len(listing.reviews) if (hasattr(listing, "reviews") and listing.reviews) else 0

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
            average_rating=average_rating,
            review_count=review_count,
            created_at=listing.created_at,
            updated_at=listing.updated_at,
        )


class SellerGitHubBadgeResponse(BaseModel):
    github_username: str
    github_user_id: Optional[str] = None
    account_created_at: Optional[datetime] = None
    public_repo_count: int = 0
    connected_at: Optional[datetime] = None
    account_age_years: float = 0.0

    model_config = ConfigDict(from_attributes=True)


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
    average_rating: Optional[float] = None
    review_count: int = 0
    seller_github: Optional[SellerGitHubBadgeResponse] = None
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
    average_rating: Optional[float] = None
    review_count: int = 0
    created_at: datetime
    updated_at: datetime


class ReviewCreate(BaseModel):
    rating: int = Field(..., ge=1, le=5, description="Rating between 1 and 5 stars")
    review_text: Optional[str] = Field(None, max_length=2000, description="Optional buyer review text")


class ReviewResponse(BaseModel):
    id: str
    listing_id: str
    listing_version_id: Optional[str] = None
    buyer_id: str
    rating: int
    review_text: Optional[str] = None
    is_edited: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_review(cls, r: Review) -> "ReviewResponse":
        is_edited = getattr(r, "is_edited", False)
        if not is_edited and r.updated_at and r.created_at:
            is_edited = (r.updated_at > r.created_at)

        return cls(
            id=r.id,
            listing_id=r.listing_id,
            listing_version_id=r.listing_version_id,
            buyer_id=r.buyer_id,
            rating=r.rating,
            review_text=r.review_text,
            is_edited=is_edited,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )


class ReviewListResponse(BaseModel):
    items: List[ReviewResponse] = Field(default_factory=list)
    reviews: List[ReviewResponse] = Field(default_factory=list)
    total: int
    page: int = 1
    limit: int = 50
    average_rating: Optional[float] = None
    review_count: int = 0


class VersionSubmitRequest(BaseModel):
    version_label: Optional[str] = Field(None, min_length=1, max_length=32)
    version: Optional[str] = Field(None, min_length=1, max_length=32)
    source_type: str = Field("upload", description="'upload' or 'github'")
    git_url: Optional[str] = None
    package_path: Optional[str] = None
    package_content: Optional[str] = None
    changelog: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def reconcile_version_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Reconcile version_label / version
            v_val = data.get("version_label") or data.get("version")
            if v_val is not None:
                data["version_label"] = str(v_val).strip()
                data["version"] = str(v_val).strip()

            # Reconcile git_url / package_path
            raw_path = str(data.get("package_path") or data.get("git_url") or "").strip()
            if raw_path:
                path_lower = raw_path.lower()
                is_git = (
                    path_lower.startswith("http://")
                    or path_lower.startswith("https://")
                    or path_lower.startswith("git@")
                    or "github.com" in path_lower
                    or path_lower.endswith(".git")
                )
                if is_git:
                    data["source_type"] = "github"
                    data["git_url"] = raw_path
        return data


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
    draft_reply: Optional[str] = None
    created_at: datetime
    responded_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

