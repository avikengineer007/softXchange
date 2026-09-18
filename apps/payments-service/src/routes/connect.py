import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.database import get_db
from src.config import settings
from src.auth import require_seller, AuthContext
from src.models.seller_payment_profile import SellerPaymentProfile
from src.razorpay_client import razorpay_client

logger = logging.getLogger("payments-service.routes.connect")

router = APIRouter(prefix="/payments/seller/connect", tags=["Razorpay Route Onboarding"])


class ConnectStartResponse(BaseModel):
    user_id: str
    razorpay_account_id: str
    onboarding_url: str


class ConnectStatusResponse(BaseModel):
    user_id: str
    connected: bool
    razorpay_account_id: str | None = None
    payout_enabled: bool


@router.post(
    "/start",
    response_model=ConnectStartResponse,
    summary="Initiate Razorpay Route linked account onboarding for authenticated seller",
)
def start_connect_onboarding(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Creates a Razorpay Route linked account for the seller if not already present,
    and returns account onboarding information.
    """
    user_id = auth_ctx.user_id
    email = auth_ctx.claims.get("email")

    profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == user_id).first()

    if not profile:
        try:
            account_id = razorpay_client.create_linked_account(user_id=user_id, email=email)
            profile = SellerPaymentProfile(user_id=user_id, razorpay_account_id=account_id)
            db.add(profile)
            db.commit()
            db.refresh(profile)
        except Exception as exc:
            logger.error(f"Failed to create Razorpay Route linked account for {user_id}: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Razorpay Route linked account creation failed: {str(exc)}",
            )
    else:
        account_id = profile.razorpay_account_id

    # Razorpay Route portal / onboarding URL
    if account_id.startswith("acc_dev_mock"):
        onboarding_url = f"{settings.FRONTEND_URL}/seller-payouts.html?onboarded=1"
    else:
        onboarding_url = f"https://dashboard.razorpay.com/app/route/accounts/{account_id}"

    return ConnectStartResponse(
        user_id=user_id,
        razorpay_account_id=account_id,
        onboarding_url=onboarding_url,
    )


@router.post(
    "/onboard",
    response_model=ConnectStartResponse,
    summary="Initiate Razorpay Route onboarding for authenticated seller (alias for /start)",
)
def onboard_connect_alias(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    return start_connect_onboarding(auth_ctx=auth_ctx, db=db)


@router.get(
    "/status",
    response_model=ConnectStatusResponse,
    summary="Get Razorpay Route onboarding and payout readiness status",
)
def get_connect_status(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns seller's Razorpay Route linkage and checks payout authorization with auth-service.
    SINGLE SOURCE OF TRUTH: Payout readiness status is retrieved directly from auth-service.
    """
    user_id = auth_ctx.user_id
    profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == user_id).first()

    connected = profile is not None
    razorpay_account_id = profile.razorpay_account_id if profile else None
    payout_enabled = False

    if connected:
        # Check auth-service for payout authorization
        try:
            url = f"{settings.AUTH_SERVICE_URL}/kyc/seller/{user_id}/payout-status"
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(
                    url,
                    headers={
                        "X-Internal-Caller": "payments-service",
                        "X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET,
                        "X-Seller-ID": user_id,
                    },
                )
                if resp.status_code == 200:
                    payout_enabled = resp.json().get("payout_enabled", False)
        except Exception as exc:
            logger.warning(f"Could not verify payout status from auth-service for {user_id}: {exc}")

    return ConnectStatusResponse(
        user_id=user_id,
        connected=connected,
        razorpay_account_id=razorpay_account_id,
        payout_enabled=payout_enabled,
    )


# Additional router alias without /payments prefix
alias_router = APIRouter(prefix="/seller/connect", tags=["Razorpay Route Onboarding Alias"])
alias_router.add_api_route("/start", start_connect_onboarding, methods=["POST"], response_model=ConnectStartResponse)
alias_router.add_api_route("/onboard", start_connect_onboarding, methods=["POST"], response_model=ConnectStartResponse)
alias_router.add_api_route("/status", get_connect_status, methods=["GET"], response_model=ConnectStatusResponse)
