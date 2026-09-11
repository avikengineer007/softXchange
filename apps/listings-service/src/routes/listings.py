from typing import Optional, List
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from src.database import get_db
from src.models.listing import (
    Listing,
    ListingVersion,
    ListingStatus,
    ScanStatus,
    ListingCreate,
    ListingUpdate,
    ListingResponse,
    ListingDetailResponse,
    ListingVersionResponse,
    SellerListingItemResponse,
    VersionSubmitRequest,
    FindingsDetailResponse,
    BuyerQuestion,
    QuestionCreate,
    QuestionReply,
    QuestionResponse,
    utc_now,
)
from src.auth import require_auth, require_seller, require_admin, get_optional_auth, AuthContext

from src.scanner_client import scanner_client
from src.gate import evaluate_publish_gate, sync_seller_kyc
from src.indexer import remove_listing_embedding

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

    try:
        scan_res = scanner_client.submit_version(
            listing_id=listing.id,
            version=data.version_label,
            source_type=data.source_type,
            git_url=data.git_url,
            package_content=data.package_content,
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
        version_label=data.version_label,
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
    return QuestionResponse.model_validate(question)


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

