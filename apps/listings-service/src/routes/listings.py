import uuid
import httpx
from typing import Optional, List
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from src.database import get_db
from src.config import settings
from src.models.listing import (
    Listing,
    ListingVersion,
    ListingStatus,
    ScanStatus,
    ListingCreate,
    ListingUpdate,
    ListingResponse,
    ListingDetailResponse,
    SellerGitHubBadgeResponse,
    ListingVersionResponse,
    SellerListingItemResponse,
    VersionSubmitRequest,
    FindingsDetailResponse,
    BuyerQuestion,
    QuestionCreate,
    QuestionReply,
    QuestionResponse,
    Review,
    SavedListing,
    ReviewCreate,
    ReviewResponse,
    ReviewListResponse,
    utc_now,
)
from src.auth import require_auth, require_seller, require_admin, get_optional_auth, AuthContext

from src.scanner_client import scanner_client
from src.gate import evaluate_publish_gate, sync_seller_kyc
from src.indexer import remove_listing_embedding
from src.notifications_client import emit_notification

logger = logging.getLogger("listings-service.routes.listings")

router = APIRouter(prefix="/listings", tags=["Listings"])


def _compute_next_action(status: str) -> str:
    """Return seller next-action hint per listing status."""
    mapping = {
        ListingStatus.DRAFT.value: "submit package for security scan",
        ListingStatus.PENDING_SCAN.value: "scanning in progress",
        ListingStatus.SCAN_FAILED.value: "view findings and resubmit",
        ListingStatus.SCAN_PASSED_AWAITING_KYC.value: "complete seller verification",
        ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value: "retry verification check",
        ListingStatus.LIVE.value: "listing is active",
        ListingStatus.WITHDRAWN.value: "listing is withdrawn",
        ListingStatus.SUSPENDED.value: "listing is suspended",
    }
    return mapping.get(status, "manage listing")


# ============================================================================
# Prompt 1: Core Listing Model + Authenticated CRUD
# ============================================================================

@router.post(
    "",
    response_model=ListingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new draft listing (Seller only)",
)
def create_listing(
    data: ListingCreate,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Creates a new draft listing owned by the authenticated seller.
    Rejects if user lacks 'seller' role.
    """
    new_listing = Listing(
        seller_id=auth_ctx.user_id,
        title=data.title.strip(),
        description=data.description.strip(),
        price_cents=data.price_cents,
        category=data.category.strip().lower(),
        status=ListingStatus.DRAFT.value,
        status_message="Draft created. Submit a version package for security scanning.",
    )
    db.add(new_listing)
    db.flush()

    # Create initial draft version
    initial_version = ListingVersion(
        listing_id=new_listing.id,
        version_label=data.version_label or "1.0.0",
        scan_status=ScanStatus.PENDING_SCAN.value,
    )
    db.add(initial_version)
    db.commit()
    db.refresh(new_listing)

    return ListingResponse.from_orm_listing(new_listing)


@router.patch(
    "/{listing_id}",
    response_model=ListingResponse,
    summary="Edit listing draft fields (Owner only)",
)
def update_listing(
    listing_id: str,
    data: ListingUpdate,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Updates draft fields (title, description, price_cents, category).
    
    VERSION IMMUTABILITY:
    Editing a listing that already has a live version creates a new draft version
    rather than mutating the approved live version in place.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot edit another seller's listing")

    if listing.status == ListingStatus.WITHDRAWN.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit a withdrawn listing")

    # If the listing is already LIVE, editing creates a new draft version to preserve live version immutability
    if listing.status == ListingStatus.LIVE.value:
        # Create a new draft version preserving existing live version untouched
        latest_ver = (
            db.query(ListingVersion)
            .filter(ListingVersion.listing_id == listing.id)
            .order_by(ListingVersion.created_at.desc())
            .first()
        )
        new_label = "1.0.1"
        if latest_ver and "." in latest_ver.version_label:
            parts = latest_ver.version_label.split(".")
            try:
                parts[-1] = str(int(parts[-1]) + 1)
                new_label = ".".join(parts)
            except ValueError:
                new_label = f"{latest_ver.version_label}-draft"

        new_draft_ver = ListingVersion(
            listing_id=listing.id,
            version_label=new_label,
            scan_status=ScanStatus.PENDING_SCAN.value,
        )
        db.add(new_draft_ver)
        # Note: listing.status stays live while the new draft version is prepared

    if data.title is not None:
        listing.title = data.title.strip()
    if data.description is not None:
        listing.description = data.description.strip()
    if data.price_cents is not None:
        listing.price_cents = data.price_cents
    if data.category is not None:
        listing.category = data.category.strip().lower()

    listing.updated_at = utc_now()
    db.commit()
    db.refresh(listing)

    return ListingResponse.from_orm_listing(listing)


# ============================================================================
# Prompt 1 & 4: Seller Dashboard Endpoints
# ============================================================================

@router.get(
    "/mine",
    response_model=List[SellerListingItemResponse],
    summary="Get seller's own listings across all statuses with next-action hints",
)
def get_my_listings(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns seller's listings across all statuses.
    
    LAZY SELF-HEALING:
    Automatically evaluates sync_seller_kyc for any of this seller's listings
    waiting on KYC clearance, promoting them to 'live' immediately without background jobs.
    """
    # 1. Trigger lazy self-healing for waiting listings
    sync_seller_kyc(auth_ctx.user_id, db)

    # 2. Query listings
    listings = (
        db.query(Listing)
        .filter(Listing.seller_id == auth_ctx.user_id)
        .order_by(Listing.updated_at.desc())
        .all()
    )

    items = []
    for l in listings:
        latest_ver = (
            db.query(ListingVersion)
            .filter(ListingVersion.listing_id == l.id)
            .order_by(ListingVersion.created_at.desc())
            .first()
        )
        avg_rating = None
        rev_count = 0
        if hasattr(l, "reviews") and l.reviews:
            ratings = [r.rating for r in l.reviews]
            if ratings:
                avg_rating = round(sum(ratings) / len(ratings), 2)
                rev_count = len(ratings)

        items.append(
            SellerListingItemResponse(
                id=l.id,
                title=l.title,
                price_cents=l.price_cents,
                price_usd=round(l.price_cents / 100.0, 2),
                category=l.category,
                status=l.status,
                status_message=l.status_message,
                version_label=latest_ver.version_label if latest_ver else None,
                severity_summary=latest_ver.findings_summary if latest_ver else {},
                average_rating=avg_rating,
                review_count=rev_count,
                next_action=_compute_next_action(l.status),
                created_at=l.created_at,
                updated_at=l.updated_at,
            )
        )
    return items


# ============================================================================
# Prompt 4: Admin Moderation
# ============================================================================

@router.get(
    "/admin/all",
    response_model=List[ListingResponse],
    summary="List all listings across all statuses for administrative moderation",
)
def list_all_listings_admin(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by listing status"),
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Administrative overview of all marketplace listings across all statuses.
    Requires admin role.
    """
    query = db.query(Listing)
    if status_filter:
        query = query.filter(Listing.status == status_filter.strip().lower())
    listings = query.order_by(Listing.created_at.desc()).all()
    return [ListingResponse.from_orm_listing(l) for l in listings]


# ============================================================================
# Prompt 3 & 5: Public Browse & Search
# ============================================================================

@router.get(
    "",
    response_model=List[ListingResponse],
    summary="Public catalog browse and search (Only returns 'live' listings)",
)
def browse_public_listings(
    category: Optional[str] = Query(None, description="Filter by category"),
    min_price_cents: Optional[int] = Query(None, description="Minimum price in cents"),
    max_price_cents: Optional[int] = Query(None, description="Maximum price in cents"),
    search: Optional[str] = Query(None, description="Search query over title and description"),
    db: Session = Depends(get_db),
):
    """
    Public marketplace catalog.
    Strictly returns listings where status == 'live'.
    Non-live listings are completely invisible to the public.
    """
    query = db.query(Listing).filter(Listing.status == ListingStatus.LIVE.value)

    if category:
        query = query.filter(Listing.category == category.strip().lower())

    if min_price_cents is not None:
        query = query.filter(Listing.price_cents >= min_price_cents)

    if max_price_cents is not None:
        query = query.filter(Listing.price_cents <= max_price_cents)

    if search:
        term = f"%{search.strip()}%"
        query = query.filter(or_(Listing.title.ilike(term), Listing.description.ilike(term)))

    listings = query.order_by(Listing.updated_at.desc()).all()
    return [ListingResponse.from_orm_listing(l) for l in listings]


# ============================================================================
# Wishlist / Saved Listings: Fetch Saved
# ============================================================================

@router.get(
    "/saved",
    response_model=List[ListingResponse],
    summary="Get authenticated buyer's saved wishlist listings",
)
def get_saved_listings(
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Returns saved wishlist listings for the authenticated buyer.
    Preserves withdrawn/suspended items with honest status.
    """
    saved_entries = (
        db.query(SavedListing)
        .filter(SavedListing.buyer_id == auth_ctx.user_id)
        .order_by(SavedListing.created_at.desc())
        .all()
    )
    result = []
    for entry in saved_entries:
        listing = db.query(Listing).filter(Listing.id == entry.listing_id).first()
        if listing:
            result.append(ListingResponse.from_orm_listing(listing))
    return result


def fetch_seller_public_trust(seller_id: str, timeout: float = 2.0) -> Optional[SellerGitHubBadgeResponse]:
    """
    Fetches seller's public trust signals from auth-service with resilient fallback.
    If auth-service is slow or unavailable, returns None without blocking the listing query.
    """
    url = f"{settings.AUTH_SERVICE_URL}/auth/seller/{seller_id}/public-trust"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                gh_data = data.get("github")
                if gh_data:
                    return SellerGitHubBadgeResponse(
                        github_username=gh_data.get("github_username", ""),
                        github_user_id=gh_data.get("github_user_id"),
                        account_created_at=gh_data.get("account_created_at"),
                        public_repo_count=gh_data.get("public_repo_count", 0),
                        connected_at=gh_data.get("connected_at"),
                        account_age_years=float(gh_data.get("account_age_years", 0.0)),
                    )
    except Exception as exc:
        logger.debug(f"Could not fetch public trust for seller {seller_id}: {exc}")
    return None


@router.get(
    "/{listing_id}",
    response_model=ListingDetailResponse,
    summary="Get listing detail view (Owner sees any status; public sees 'live' only)",
)
def get_listing_detail(
    listing_id: str,
    auth_ctx: Optional[AuthContext] = Depends(get_optional_auth),
    db: Session = Depends(get_db),
):
    """
    Public and owner detail view.
    - Owner can see their listing in any status.
    - Anyone else can only view if status == 'live'.
    - Returns vetted badge for live software packages.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    is_owner = auth_ctx is not None and (auth_ctx.user_id == listing.seller_id or auth_ctx.has_role("admin"))

    if not is_owner and listing.status != ListingStatus.LIVE.value:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    # Load active/current version
    current_ver = None
    if listing.current_version_id:
        ver_obj = db.query(ListingVersion).filter(ListingVersion.id == listing.current_version_id).first()
        if ver_obj:
            current_ver = ListingVersionResponse.model_validate(ver_obj)
    elif listing.versions:
        current_ver = ListingVersionResponse.model_validate(listing.versions[0])

    is_live = listing.status == ListingStatus.LIVE.value
    badge = "Scanned — 0 critical findings" if is_live else "Unvetted Draft"

    avg_rating = None
    rev_count = 0
    if hasattr(listing, "reviews") and listing.reviews:
        ratings = [r.rating for r in listing.reviews]
        if ratings:
            avg_rating = round(sum(ratings) / len(ratings), 2)
            rev_count = len(ratings)

    seller_github = fetch_seller_public_trust(listing.seller_id)

    return ListingDetailResponse(
        id=listing.id,
        seller_id=listing.seller_id,
        title=listing.title,
        description=listing.description,
        price_cents=listing.price_cents,
        price_usd=round(listing.price_cents / 100.0, 2),
        category=listing.category,
        status=listing.status,
        status_message=listing.status_message,
        vetted=is_live,
        badge=badge,
        current_version=current_ver,
        average_rating=avg_rating,
        review_count=rev_count,
        seller_github=seller_github,
        created_at=listing.created_at,
        updated_at=listing.updated_at,
    )


# ============================================================================
# Prompt 2: Submission to Scan-Service + Status Polling
# ============================================================================

@router.post(
    "/{listing_id}/versions",
    response_model=ListingVersionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a package or GitHub repository for scanning as a new version",
)
def submit_version(
    listing_id: str,
    data: VersionSubmitRequest,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Calls scan-service intake to enqueue security analysis.
    Translates request into call to scan-service interface.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot submit version for another seller's listing")

    v_label = data.version_label or data.version or "1.0.0"
    source_type = data.source_type
    git_url = data.git_url
    package_content = data.package_content

    # Auto-detect git vs upload from package_path or git_url
    raw_path = str(data.package_path or git_url or "").strip()
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
            source_type = "github"
            git_url = raw_path
        elif not package_content:
            import os, base64
            if os.path.exists(raw_path) and os.path.isfile(raw_path):
                try:
                    with open(raw_path, "rb") as f:
                        package_content = base64.b64encode(f.read()).decode("utf-8")
                except Exception as exc:
                    logger.debug(f"Could not read local package {raw_path}: {exc}")

    try:
        scan_res = scanner_client.submit_version(
            listing_id=listing.id,
            version=v_label,
            source_type=source_type,
            git_url=git_url,
            package_content=package_content,
        )
        job_id = scan_res.get("scan_job_id")
    except Exception as exc:
        logger.error(f"Failed to submit to scan-service: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Security scanner intake unavailable: {str(exc)}",
        )

    # Persist ListingVersion
    new_version = ListingVersion(
        listing_id=listing.id,
        version_label=v_label,
        scan_status=ScanStatus.PENDING_SCAN.value,
        scan_job_id=job_id,
    )
    db.add(new_version)

    listing.status = ListingStatus.PENDING_SCAN.value
    listing.status_message = "Package submitted for security scanning."
    listing.updated_at = utc_now()
    db.commit()
    db.refresh(new_version)

    return ListingVersionResponse.model_validate(new_version)


@router.get(
    "/{listing_id}/versions/{version_id}/status",
    response_model=ListingVersionResponse,
    summary="Poll security scan status and trigger publish gate evaluation",
)
def get_version_status(
    listing_id: str,
    version_id: str,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Queries scan-service for status, updates version, and evaluates the publish gate.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    version = db.query(ListingVersion).filter(ListingVersion.id == version_id, ListingVersion.listing_id == listing_id).first()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    # Query scan-service status over HTTP
    try:
        status_res = scanner_client.query_status(listing_id, version.version_label)
        raw_scan_status = status_res.get("scan_status", version.scan_status)
        version.scan_status = raw_scan_status
        version.storage_location = status_res.get("storage_location")
        version.findings_summary = status_res.get("severity_counts", {})
        version.findings_detail = status_res.get("findings", [])
        db.commit()
    except Exception as exc:
        logger.warning(f"Failed to query scan status from scan-service: {exc}")

    # Evaluate publish gate
    evaluate_publish_gate(listing, version, db)
    db.refresh(version)

    return ListingVersionResponse.model_validate(version)


# ============================================================================
# Prompt 4: Findings, Resubmit, and Withdrawal
# ============================================================================

@router.get(
    "/{listing_id}/versions/{version_id}/findings",
    response_model=FindingsDetailResponse,
    summary="Get redacted scan findings for a version (Owner only)",
)
def get_version_findings(
    listing_id: str,
    version_id: str,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Owner-only view of scan findings.
    Enforces the redacted-snippet-only guarantee.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    version = db.query(ListingVersion).filter(ListingVersion.id == version_id, ListingVersion.listing_id == listing_id).first()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    return FindingsDetailResponse(
        listing_id=listing.id,
        version_id=version.id,
        version_label=version.version_label,
        scan_status=version.scan_status,
        findings=version.findings_detail or [],
    )


@router.delete(
    "/{listing_id}",
    summary="Withdraw a listing (Owner only; removes immediately from public catalog)",
)
def withdraw_listing(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Soft-delete / withdrawal of a listing.
    Immediately hides from public browse.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    listing.status = ListingStatus.WITHDRAWN.value
    listing.status_message = "Listing withdrawn by seller."
    listing.updated_at = utc_now()
    db.commit()

    remove_listing_embedding(listing.id, db)

    return {"message": "Listing successfully withdrawn", "listing_id": listing.id}


@router.post(
    "/{listing_id}/resubmit",
    response_model=ListingVersionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Convenience endpoint to resubmit package after scan failure",
)
def resubmit_listing(
    listing_id: str,
    data: VersionSubmitRequest,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Convenience wrapper around submit_version for 'try again after scan_failed' flow.
    """
    return submit_version(listing_id=listing_id, data=data, auth_ctx=auth_ctx, db=db)


# ============================================================================
# Minimal Buyer Question Messaging
# ============================================================================

@router.post(
    "/{listing_id}/questions",
    response_model=QuestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a buyer question about a listing",
)
def create_buyer_question(
    listing_id: str,
    data: QuestionCreate,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    question = BuyerQuestion(
        listing_id=listing_id,
        buyer_id=auth_ctx.user_id,
        question_text=data.question_text.strip(),
    )
    db.add(question)
    db.commit()
    db.refresh(question)

    emit_notification(
        user_id=listing.seller_id,
        notification_type="question_asked",
        payload={
            "listing_id": listing.id,
            "listing_title": listing.title,
            "question_id": question.id,
            "buyer_id": auth_ctx.user_id,
        },
    )

    return QuestionResponse.model_validate(question)


@router.get(
    "/{listing_id}/questions",
    response_model=List[QuestionResponse],
    summary="List questions asked about a listing",
)
def list_buyer_questions(
    listing_id: str,
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    questions = (
        db.query(BuyerQuestion)
        .filter(BuyerQuestion.listing_id == listing_id)
        .order_by(BuyerQuestion.created_at.desc())
        .all()
    )
    return [QuestionResponse.model_validate(q) for q in questions]


@router.post(
    "/{listing_id}/questions/{question_id}/reply",
    response_model=QuestionResponse,
    summary="Seller replies to a buyer question (Owner only)",
)
def reply_buyer_question(
    listing_id: str,
    question_id: str,
    data: QuestionReply,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    question = db.query(BuyerQuestion).filter(BuyerQuestion.id == question_id, BuyerQuestion.listing_id == listing_id).first()
    if not question:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found")

    question.seller_response = data.response_text.strip()
    question.responded_at = utc_now()
    db.commit()
    db.refresh(question)

    emit_notification(
        user_id=question.buyer_id,
        notification_type="question_answered",
        payload={
            "listing_id": listing.id,
            "listing_title": listing.title,
            "question_id": question.id,
            "seller_id": auth_ctx.user_id,
        },
    )

    return QuestionResponse.model_validate(question)


# ============================================================================
# Wishlist / Saved Listings Endpoints
# ============================================================================

@router.post(
    "/{listing_id}/save",
    summary="Save listing to buyer's wishlist (Idempotent)",
)
def save_listing(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    existing = (
        db.query(SavedListing)
        .filter(SavedListing.buyer_id == auth_ctx.user_id, SavedListing.listing_id == listing_id)
        .first()
    )
    if not existing:
        saved = SavedListing(
            id=str(uuid.uuid4()),
            buyer_id=auth_ctx.user_id,
            listing_id=listing_id,
            created_at=utc_now(),
        )
        db.add(saved)
        db.commit()

    return {"saved": True, "listing_id": listing_id}


@router.delete(
    "/{listing_id}/save",
    summary="Remove listing from buyer's wishlist (Idempotent)",
)
def unsave_listing(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    existing = (
        db.query(SavedListing)
        .filter(SavedListing.buyer_id == auth_ctx.user_id, SavedListing.listing_id == listing_id)
        .first()
    )
    if existing:
        db.delete(existing)
        db.commit()

    return {"saved": False, "listing_id": listing_id}


@router.post(
    "/{listing_id}/toggle-save",
    summary="Toggle listing saved status in wishlist",
)
def toggle_save_listing(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    existing = (
        db.query(SavedListing)
        .filter(SavedListing.buyer_id == auth_ctx.user_id, SavedListing.listing_id == listing_id)
        .first()
    )
    if existing:
        db.delete(existing)
        db.commit()
        return {"saved": False, "listing_id": listing_id}
    else:
        saved = SavedListing(
            id=str(uuid.uuid4()),
            buyer_id=auth_ctx.user_id,
            listing_id=listing_id,
            created_at=utc_now(),
        )
        db.add(saved)
        db.commit()
        return {"saved": True, "listing_id": listing_id}


@router.get(
    "/{listing_id}/saved-status",
    summary="Check if listing is saved by authenticated user",
)
def check_saved_status(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(SavedListing)
        .filter(SavedListing.buyer_id == auth_ctx.user_id, SavedListing.listing_id == listing_id)
        .first()
    )
    return {"saved": existing is not None, "listing_id": listing_id}


# ============================================================================
# Reviews & Ratings Endpoints
# ============================================================================

def check_buyer_purchase_entitlement(buyer_id: str, listing_id: str) -> bool:
    """
    Calls payments-service to verify that the buyer purchased this listing.
    Requires X-Internal-Secret for inter-service authentication.
    """
    url = f"{settings.PAYMENTS_SERVICE_URL}/orders/check-entitlement/{buyer_id}/{listing_id}"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(
                url,
                headers={
                    "X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return bool(data.get("has_purchased"))
            elif resp.status_code in [401, 403, 404]:
                return False
            else:
                logger.warning(f"Payments service returned {resp.status_code} for entitlement check")
                return False
    except Exception as exc:
        logger.error(f"Failed to check buyer entitlement against payments-service: {exc}")
        return False


@router.post(
    "/{listing_id}/reviews",
    response_model=ReviewResponse,
    summary="Submit or update a review for a purchased listing (Buyer only)",
)
def submit_or_update_review(
    listing_id: str,
    data: ReviewCreate,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Authenticated buyer only, gated by real entitlement check against payments-service.
    One review per (buyer_id, listing_id) — resubmission updates, never duplicates.
    Bumps updated_at on edit, reflecting is_edited: True.
    Negative constraint: NEVER calls ml_shared.enforce_guardrails().
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    # Gate: verified purchase check against payments-service
    if not check_buyer_purchase_entitlement(auth_ctx.user_id, listing_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified purchase required to leave a review",
        )

    # Check for existing review
    existing = (
        db.query(Review)
        .filter(Review.listing_id == listing_id, Review.buyer_id == auth_ctx.user_id)
        .first()
    )

    ver_id = listing.current_version_id
    if not ver_id and listing.versions:
        ver_id = listing.versions[0].id

    clean_text = data.review_text.strip() if data.review_text else None

    # Negative constraint: No ml_shared.enforce_guardrails()
    if existing:
        existing.rating = data.rating
        existing.review_text = clean_text
        if ver_id:
            existing.listing_version_id = ver_id
        existing.is_edited = True
        existing.updated_at = utc_now()
        review = existing
    else:
        now = utc_now()
        review = Review(
            id=str(uuid.uuid4()),
            listing_id=listing_id,
            listing_version_id=ver_id or "unknown",
            buyer_id=auth_ctx.user_id,
            rating=data.rating,
            review_text=clean_text,
            created_at=now,
            updated_at=now,
        )
        db.add(review)

    db.commit()
    db.refresh(review)

    # Emit notification to seller
    emit_notification(
        user_id=listing.seller_id,
        notification_type="listing_review_received",
        payload={
            "listing_id": listing.id,
            "listing_title": listing.title,
            "review_id": review.id,
            "rating": review.rating,
            "buyer_id": review.buyer_id,
        },
    )

    return ReviewResponse.model_validate(review)


@router.get(
    "/{listing_id}/reviews",
    response_model=ReviewListResponse,
    summary="Get paginated reviews for a listing (Public, newest first)",
)
def get_listing_reviews(
    listing_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    total = db.query(Review).filter(Review.listing_id == listing_id).count()
    reviews = (
        db.query(Review)
        .filter(Review.listing_id == listing_id)
        .order_by(Review.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    ratings = [r.rating for r in db.query(Review.rating).filter(Review.listing_id == listing_id).all()]
    avg_rating = round(sum(ratings) / len(ratings), 2) if ratings else None

    rev_list = [ReviewResponse.model_validate(r) for r in reviews]
    page = (offset // limit) + 1 if limit > 0 else 1
    return ReviewListResponse(
        items=rev_list,
        reviews=rev_list,
        total=total,
        page=page,
        limit=limit,
        average_rating=avg_rating,
        review_count=total,
    )


# ============================================================================
# Prompt 4: Admin Listing Suspension
# ============================================================================

@router.post(
    "/{listing_id}/suspend",
    response_model=ListingResponse,
    summary="Admin suspension of listing and removal from search embeddings",
)
def suspend_listing_admin(
    listing_id: str,
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Suspends a listing immediately.
    Guarantees removal of embedding from the search index via remove_listing_embedding().
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")

    listing.status = ListingStatus.SUSPENDED.value
    listing.status_message = f"Suspended by platform admin ({auth_ctx.user_id})."
    listing.updated_at = utc_now()
    db.commit()

    # Reuse existing remove_listing_embedding to purge from vector search index
    removed = remove_listing_embedding(listing_id=listing.id, db=db)
    logger.info(f"Admin {auth_ctx.user_id} suspended listing {listing.id} (embedding removed: {removed})")

    db.refresh(listing)
    return ListingResponse.from_orm_listing(listing)

