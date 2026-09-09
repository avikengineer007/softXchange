from enum import Enum
import logging
from typing import Optional, Tuple, List
import httpx
from sqlalchemy.orm import Session

from src.config import settings
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus, utc_now
from src.indexer import sync_live_listing_embedding

logger = logging.getLogger("listings-service.gate")


class PayoutCheckResult(str, Enum):
    PAYOUT_ENABLED = "payout_enabled"
    PAYOUT_DISABLED = "payout_disabled"
    SYSTEM_UNAVAILABLE = "system_unavailable"


def check_seller_payout_status(seller_id: str, timeout: float = 4.0) -> PayoutCheckResult:
    """
    Fresh check to auth-service for seller KYC payout authorization.
    
    FAIL-CLOSED & DISTINCT-STATE GUARANTEE:
    - PAYOUT_ENABLED: Auth-service explicitly confirmed seller is verified and payout-enabled.
    - PAYOUT_DISABLED: Auth-service responded and seller has not completed KYC.
    - SYSTEM_UNAVAILABLE: Network error, timeout, or 5xx outage.
    """
    url = f"{settings.AUTH_SERVICE_URL}/kyc/seller/{seller_id}/payout-status"

    try:
        # We query the service endpoint using internal server call
        # Or mock/fastapi client in tests
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                url,
                headers={
                    "X-Internal-Caller": "listings-service",
                    "X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET,
                    "X-Seller-ID": seller_id,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("payout_enabled") is True:
                    return PayoutCheckResult.PAYOUT_ENABLED
                return PayoutCheckResult.PAYOUT_DISABLED
            elif resp.status_code in [401, 403, 404]:
                # Seller profile not verified or not found
                return PayoutCheckResult.PAYOUT_DISABLED
            else:
                logger.warning(f"Auth service returned status {resp.status_code} for seller {seller_id}")
                return PayoutCheckResult.SYSTEM_UNAVAILABLE
    except httpx.RequestError as exc:
        logger.error(f"Failed to connect to auth-service ({url}): {exc}")
        return PayoutCheckResult.SYSTEM_UNAVAILABLE
    except Exception as exc:
        logger.error(f"Unexpected error querying auth-service: {exc}", exc_info=True)
        return PayoutCheckResult.SYSTEM_UNAVAILABLE


def evaluate_publish_gate(
    listing: Listing,
    version: ListingVersion,
    db: Session,
    payout_override: Optional[PayoutCheckResult] = None,
) -> Listing:
    """
    Evaluates the complete publish gate state machine:
    1. If version.scan_status == "scan_failed":
       listing.status -> "scan_failed"
    2. If version.scan_status == "pending_scan":
       listing.status -> "pending_scan"
    3. If version.scan_status == "passed":
       Fresh KYC check:
       - If PAYOUT_ENABLED:
         listing.status -> "live"
         listing.current_version_id = version.id
       - If PAYOUT_DISABLED:
         listing.status -> "scan_passed_awaiting_kyc"
       - If SYSTEM_UNAVAILABLE:
         listing.status -> "scan_passed_verification_unavailable"
    """
    if version.scan_status == ScanStatus.SCAN_FAILED.value:
        listing.status = ListingStatus.SCAN_FAILED.value
        listing.status_message = "Security scan detected secrets or vulnerabilities. Review findings to resolve."
        listing.updated_at = utc_now()
        db.commit()
        return listing

    if version.scan_status == ScanStatus.PENDING_SCAN.value:
        listing.status = ListingStatus.PENDING_SCAN.value
        listing.status_message = "Package is currently undergoing automated security analysis."
        listing.updated_at = utc_now()
        db.commit()
        return listing

    if version.scan_status == ScanStatus.PASSED.value:
        payout_status = payout_override or check_seller_payout_status(listing.seller_id)

        if payout_status == PayoutCheckResult.PAYOUT_ENABLED:
            listing.status = ListingStatus.LIVE.value
            listing.current_version_id = version.id
            listing.status_message = "Listing is live in the marketplace."
        elif payout_status == PayoutCheckResult.PAYOUT_DISABLED:
            listing.status = ListingStatus.SCAN_PASSED_AWAITING_KYC.value
            listing.status_message = "Your listing passed security review. Complete seller identity verification to make it live."
        else:
            # SYSTEM_UNAVAILABLE: Fail-closed without falsely telling the seller they lack KYC
            listing.status = ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value
            listing.status_message = "Security scan passed. Verification service temporarily unavailable; status will auto-retry shortly."

        listing.updated_at = utc_now()
        db.commit()

        if listing.status == ListingStatus.LIVE.value:
            sync_live_listing_embedding(listing, version, db)

        return listing

    return listing


def sync_seller_kyc(
    seller_id: str,
    db: Session,
    payout_override: Optional[PayoutCheckResult] = None,
) -> List[Listing]:
    """
    Self-healing trigger:
    Re-checks payout authorization for any listings belonging to seller_id that are currently
    blocked in 'scan_passed_awaiting_kyc' or 'scan_passed_verification_unavailable'.
    Promotes them to 'live' immediately once KYC clears, without requiring a re-scan.
    """
    target_statuses = [
        ListingStatus.SCAN_PASSED_AWAITING_KYC.value,
        ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value,
    ]

    waiting_listings = (
        db.query(Listing)
        .filter(Listing.seller_id == seller_id, Listing.status.in_(target_statuses))
        .all()
    )

    if not waiting_listings:
        return []

    payout_status = payout_override or check_seller_payout_status(seller_id)
    promoted = []

    for listing in waiting_listings:
        # Find latest passed version
        passed_version = (
            db.query(ListingVersion)
            .filter(
                ListingVersion.listing_id == listing.id,
                ListingVersion.scan_status == ScanStatus.PASSED.value,
            )
            .order_by(ListingVersion.created_at.desc())
            .first()
        )
        if not passed_version:
            continue

        if payout_status == PayoutCheckResult.PAYOUT_ENABLED:
            listing.status = ListingStatus.LIVE.value
            listing.current_version_id = passed_version.id
            listing.status_message = "Listing is live in the marketplace."
            listing.updated_at = utc_now()
            promoted.append(listing)
            sync_live_listing_embedding(listing, passed_version, db)
        elif payout_status == PayoutCheckResult.PAYOUT_DISABLED:
            listing.status = ListingStatus.SCAN_PASSED_AWAITING_KYC.value
            listing.status_message = "Your listing passed security review. Complete seller identity verification to make it live."
            listing.updated_at = utc_now()
        else:
            listing.status = ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value
            listing.status_message = "Security scan passed. Verification service temporarily unavailable; status will auto-retry shortly."
            listing.updated_at = utc_now()

    if promoted:
        db.commit()
    return promoted
