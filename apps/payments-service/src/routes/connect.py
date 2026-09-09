import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.database import get_db
from src.config import settings
from src.auth import require_seller, AuthContext
from src.models.seller_payment_profile import SellerPaymentProfile
from src.stripe_client import stripe_client

logger = logging.getLogger("payments-service.routes.connect")

router = APIRouter(prefix="/payments/seller/connect", tags=["Stripe Connect Onboarding"])


class ConnectStartResponse(BaseModel):
    user_id: str
    stripe_account_id: str
    onboarding_url: str


class ConnectStatusResponse(BaseModel):
    user_id: str
    connected: bool
    stripe_account_id: str | None = None
    payout_enabled: bool


@router.post(
    "/start",
    response_model=ConnectStartResponse,
    summary="Initiate Stripe Connect Express onboarding for authenticated seller",
)
def start_connect_onboarding(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Creates a Stripe Connect Express account for the seller if not already present,
    and returns an Account Link to Stripe's hosted onboarding interface.
    """
    user_id = auth_ctx.user_id
    email = auth_ctx.claims.get("email")

    profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == user_id).first()

    if not profile:
        try:
            account_id = stripe_client.create_connect_account(user_id=user_id, email=email)
            profile = SellerPaymentProfile(user_id=user_id, stripe_account_id=account_id)
            db.add(profile)
            db.commit()
            db.refresh(profile)
        except Exception as exc:
            logger.error(f"Failed to create Stripe Connect account for {user_id}: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Stripe Connect account creation failed: {str(exc)}",
            )
    else:
        account_id = profile.stripe_account_id

    # Generate hosted onboarding link
    refresh_url = f"http://localhost:8004/static/seller-payouts.html?reauth=1"
    return_url = f"http://localhost:8004/static/seller-payouts.html?onboarded=1"

    try:
        onboarding_url = stripe_client.create_account_link(
            account_id=account_id,
            refresh_url=refresh_url,
            return_url=return_url,
        )
    except Exception as exc:
        logger.error(f"Failed to generate Account Link for {account_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stripe Account Link creation failed: {str(exc)}",
        )

    return ConnectStartResponse(
        user_id=user_id,
        stripe_account_id=account_id,
        onboarding_url=onboarding_url,
    )


@router.get(
    "/status",
    response_model=ConnectStatusResponse,
    summary="Get Stripe Connect onboarding and payout readiness status",
)
def get_connect_status(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns seller's Stripe Connect linkage and checks payout authorization with auth-service.
    SINGLE SOURCE OF TRUTH: Payout readiness status is retrieved directly from auth-service.
    """
    user_id = auth_ctx.user_id
    profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == user_id).first()

    connected = profile is not None
    stripe_account_id = profile.stripe_account_id if profile else None
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
        stripe_account_id=stripe_account_id,
        payout_enabled=payout_enabled,
    )
