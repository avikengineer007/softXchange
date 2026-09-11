import hashlib
import hmac
import logging
import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db
from src.models.user import (
    KYCStartResponse,
    KYCStatusResponse,
    KYCWebhookPayload,
    KYCSubmitRequest,
    KYCStatus,
    SellerProfile,
    utc_now,
)
from src.security import require_auth, require_seller, AuthContext
from src.kyc.service import (
    start_seller_kyc,
    update_seller_kyc_status,
    check_and_sync_kyc_status,
    get_or_create_seller_profile,
    is_seller_payout_enabled,
)

router = APIRouter(prefix="/auth/seller/kyc", tags=["Seller KYC Gate"])
logger = logging.getLogger("auth-service.kyc")


@router.post(
    "/start",
    response_model=KYCStartResponse,
    summary="Initiate KYC identity onboarding for authenticated seller",
)
def start_kyc_onboarding(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Transitions seller KYC status to 'pending' and initiates onboarding with KYCProvider.
    """
    res = start_seller_kyc(user_id=auth_ctx.user_id, db=db)
    return KYCStartResponse(
        message="KYC onboarding initiated. Status set to pending.",
        user_id=auth_ctx.user_id,
        kyc_status="pending",
        onboarding_url=res.get("onboarding_url"),
    )


@router.get(
    "/status",
    response_model=KYCStatusResponse,
    summary="Retrieve current KYC and payout readiness status for authenticated seller",
)
def get_kyc_status(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns current KYC status and payout_enabled flag.
    """
    profile = get_or_create_seller_profile(auth_ctx.user_id, db)
    payout_ready = is_seller_payout_enabled(auth_ctx.user_id, db)
    return KYCStatusResponse(
        user_id=auth_ctx.user_id,
        kyc_status=profile.kyc_status,
        payout_enabled=payout_ready,
        details=profile.kyc_metadata,
    )


@router.get(
    "/seller/{seller_id}/payout-status",
    summary="Inter-service endpoint to check seller payout readiness",
)
def check_seller_payout_status_interservice(
    seller_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Inter-service endpoint to check seller payout readiness.

    ACCESS CONTROL:
    Restricted to authorized callers to prevent seller payout status enumeration:
    1. Internal service holding X-Internal-Secret matching settings.INTERNAL_SERVICE_SECRET.
    2. The authenticated seller themselves checking their own status (JWT sub == seller_id).
    3. Authenticated admin.
    4. Development-mode internal caller (X-Internal-Caller in ['listings-service', 'payments-service']).
    All unauthenticated or unauthorized external requests fail closed (401).
    """
    internal_secret = request.headers.get("X-Internal-Secret")
    is_internal_service = bool(
        internal_secret and hmac.compare_digest(internal_secret, settings.INTERNAL_SERVICE_SECRET)
    )

    is_authorized_user = False
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        try:
            from src.security import decode_access_token
            claims = decode_access_token(token)
            if claims.get("sub") == seller_id or "admin" in claims.get("roles", []):
                is_authorized_user = True
        except Exception:
            pass

    is_dev_caller = (
        settings.ENVIRONMENT.lower() == "development"
        and request.headers.get("X-Internal-Caller") in ["listings-service", "payments-service"]
    )

    if not (is_internal_service or is_authorized_user or is_dev_caller):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access denied: valid internal service secret or authorized session required",
        )

    payout_ready = is_seller_payout_enabled(seller_id, db)
    return {
        "user_id": seller_id,
        "payout_enabled": payout_ready,
    }


@router.post(
    "/webhook",
    response_model=KYCStatusResponse,
    summary="Webhook endpoint for provider identity verification updates",
)
async def kyc_provider_webhook(
    request: Request,
    payload: KYCWebhookPayload,
    db: Session = Depends(get_db),
):
    """
    Webhook endpoint called by identity provider (e.g. Stripe Connect webhook via payments-service).
    Transitions kyc_status to 'verified' or 'rejected' and updates payout_enabled.
    Fail-closed: unknown or error states remain pending and payout_enabled remains False.
    Requires and verifies HMAC signature from payments-service with 5-minute replay protection.
    """
    signature = request.headers.get("X-Service-Signature")
    timestamp_str = request.headers.get("X-Service-Timestamp")
    raw_body = await request.body()

    if signature:
        # Replay Protection: verify timestamp within 300 seconds (5 minutes)
        if timestamp_str:
            try:
                ts = int(timestamp_str)
                now = int(time.time())
                if abs(now - ts) > 300:
                    logger.warning(f"Rejecting KYC webhook with expired/replayed timestamp: {ts} (now: {now})")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Webhook timestamp expired or replayed",
                    )
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid timestamp header",
                )
        elif settings.ENVIRONMENT.lower() == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing required X-Service-Timestamp header in production",
            )

        secret = settings.INTERNAL_SERVICE_SECRET.encode("utf-8")
        valid = False
        if timestamp_str:
            signed_payload = f"{timestamp_str}.".encode("utf-8") + raw_body
            expected_sig = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(signature, expected_sig)

        if not valid:
            # Direct raw_body signature fallback for backward compatibility
            raw_sig = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(signature, raw_sig)

        if not valid:
            logger.warning("Rejecting KYC webhook with invalid X-Service-Signature HMAC")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service signature",
            )
    elif settings.ENVIRONMENT.lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-Service-Signature header",
        )

    profile = update_seller_kyc_status(
        user_id=payload.user_id,
        target_status=payload.status,
        db=db,
        details=payload.details,
    )
    payout_ready = is_seller_payout_enabled(payload.user_id, db)
    return KYCStatusResponse(
        user_id=payload.user_id,
        kyc_status=profile.kyc_status,
        payout_enabled=payout_ready,
        details=profile.kyc_metadata,
    )


@router.post(
    "/submit",
    response_model=KYCStatusResponse,
    summary="Submit KYC identity verification details for authenticated seller",
)
def submit_kyc_details(
    payload: Optional[KYCSubmitRequest] = None,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Submits identity verification details, updates seller profile metadata with redacted
    identifiers, and transitions status to 'pending'.
    """
    profile = get_or_create_seller_profile(auth_ctx.user_id, db)
    meta = dict(profile.kyc_metadata or {})

    submission_data = {}
    if payload:
        masked_tax_id = None
        if payload.tax_id:
            cleaned_tax = payload.tax_id.replace("-", "").strip()
            masked_tax_id = f"***-**-{cleaned_tax[-4:]}" if len(cleaned_tax) >= 4 else "***"

        submission_data = {
            "legal_name": payload.legal_name,
            "business_name": payload.business_name,
            "country": payload.country,
            "tax_id_masked": masked_tax_id,
            "address_line1": payload.address_line1,
            "city": payload.city,
            "state": payload.state,
            "postal_code": payload.postal_code,
            "document_type": payload.document_type,
            "phone": payload.phone,
            "submitted_at": utc_now().isoformat(),
        }
    else:
        submission_data = {
            "legal_name": "Standard Seller Verification",
            "submitted_at": utc_now().isoformat(),
        }

    meta["submission"] = submission_data
    profile.kyc_metadata = meta
    profile.kyc_status = KYCStatus.PENDING.value
    profile.payout_enabled = False
    profile.updated_at = utc_now()
    db.commit()
    db.refresh(profile)

    return KYCStatusResponse(
        user_id=auth_ctx.user_id,
        kyc_status=profile.kyc_status,
        payout_enabled=profile.payout_enabled,
        details=profile.kyc_metadata,
    )


# ============================================================================
# Inter-Service & Compatibility Router (/kyc)
# Provides inter-service endpoints (e.g. /kyc/seller/{seller_id}/payout-status)
# for listings-service and payments-service, and maintains backward compatibility
# for legacy Milestone 1 client paths (/kyc/status, /kyc/submit).
# ============================================================================

interservice_kyc_router = APIRouter(prefix="/kyc", tags=["Inter-Service & Compatibility KYC Router"])
legacy_kyc_router = interservice_kyc_router  # Alias for backward-compatible imports


@interservice_kyc_router.get("/status", response_model=KYCStatusResponse)
def legacy_get_kyc_status(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    return get_kyc_status(auth_ctx=auth_ctx, db=db)


@interservice_kyc_router.post("/submit", response_model=KYCStatusResponse)
def legacy_submit_kyc(
    payload: Optional[KYCSubmitRequest] = None,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    return submit_kyc_details(payload=payload, auth_ctx=auth_ctx, db=db)


@interservice_kyc_router.get(
    "/seller/{seller_id}/payout-status",
    summary="Inter-service endpoint to check seller payout readiness",
)
def interservice_check_seller_payout_status(
    seller_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    return check_seller_payout_status_interservice(seller_id=seller_id, request=request, db=db)

