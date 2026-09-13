import hmac
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from src.database import get_db
from src.config import settings
from src.auth import require_auth, AuthContext
from src.models.order import Order, OrderStatus, HoldStatus, OrderCreateRequest, OrderResponse, utc_now
from src.models.seller_payment_profile import SellerPaymentProfile
from src.models.entitlement import Entitlement, EntitlementStatus
from src.fraud import evaluate_fraud_rules
from src.stripe_client import stripe_client
from src.storage import generate_signed_download_url, verify_download_token
from src.notifications_client import emit_notification

logger = logging.getLogger("payments-service.routes.orders")

router = APIRouter(prefix="/orders", tags=["Orders & Checkout"])


@router.post(
    "",
    response_model=OrderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create order and initialize Stripe PaymentIntent with Connect destination charge",
)
def create_order(
    data: OrderCreateRequest,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Creates a new order for a live software listing.
    
    IMMUTABILITY & LIVE CHECK:
    - Queries listings-service over HTTP for fresh price and version.
    - Rejects if listing is not currently 'live'.
    - Pins order to the exact immutable listing_version_id purchased.
    - Splits funds at Stripe level using destination charges and application fees.
    """
    buyer_id = auth_ctx.user_id
    listing_id = data.listing_id

    # 1. Fresh check against listings-service over HTTP
    listing_url = f"{settings.LISTINGS_SERVICE_URL}/listings/{listing_id}"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(listing_url)
            if resp.status_code == 404:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listing not found")
            resp.raise_for_status()
            listing_data = resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to fetch listing data from listings-service ({listing_url}): {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to verify listing availability: {str(exc)}",
        )

    # 2. Strict Live Verification Check
    if listing_data.get("status") != "live" or not listing_data.get("vetted", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Listing is not currently available for purchase (must be live and vetted)",
        )

    seller_id = listing_data["seller_id"]
    amount_cents = listing_data["price_cents"]
    current_ver = listing_data.get("current_version")
    if not current_ver or not current_ver.get("id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Listing has no approved version available for download",
        )
    listing_version_id = current_ver["id"]

    # Prevent self-purchase
    if buyer_id == seller_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sellers cannot purchase their own software listings",
        )

    # 3. Lookup Seller's Stripe Connect Account
    seller_profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == seller_id).first()
    if not seller_profile or not seller_profile.stripe_account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Seller has not completed payment onboarding. Purchase cannot proceed.",
        )

    # 4. Compute Fee Split (Flat platform fee, e.g. 8%)
    platform_fee_cents = int(round(amount_cents * (settings.PLATFORM_FEE_PERCENT / 100.0)))
    seller_payout_cents = amount_cents - platform_fee_cents
    assert platform_fee_cents + seller_payout_cents == amount_cents, "Fee split rounding error"

    # 5. Persist Order in PENDING_PAYMENT
    new_order = Order(
        listing_id=listing_id,
        listing_version_id=listing_version_id,
        buyer_id=buyer_id,
        seller_id=seller_id,
        amount_cents=amount_cents,
        platform_fee_cents=platform_fee_cents,
        seller_payout_cents=seller_payout_cents,
        status=OrderStatus.PENDING_PAYMENT.value,
        hold_status=HoldStatus.NONE.value,
    )
    db.add(new_order)
    db.flush()

    # 6. Create Stripe PaymentIntent with Destination Charge
    try:
        pi = stripe_client.create_payment_intent(
            amount_cents=amount_cents,
            application_fee_cents=platform_fee_cents,
            destination_account_id=seller_profile.stripe_account_id,
            metadata={
                "order_id": new_order.id,
                "buyer_id": buyer_id,
                "listing_id": listing_id,
                "listing_version_id": listing_version_id,
            },
        )
        new_order.stripe_payment_intent_id = pi["id"]
        client_secret = pi.get("client_secret")
        db.commit()
        db.refresh(new_order)
    except Exception as exc:
        db.rollback()
        logger.error(f"Stripe PaymentIntent creation failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Payment initialization failed: {str(exc)}",
        )

    return OrderResponse(
        id=new_order.id,
        listing_id=new_order.listing_id,
        listing_version_id=new_order.listing_version_id,
        buyer_id=new_order.buyer_id,
        seller_id=new_order.seller_id,
        amount_cents=new_order.amount_cents,
        amount_usd=round(new_order.amount_cents / 100.0, 2),
        platform_fee_cents=new_order.platform_fee_cents,
        seller_payout_cents=new_order.seller_payout_cents,
        status=new_order.status,
        hold_status=new_order.hold_status,
        hold_reason=new_order.hold_reason,
        held_at=new_order.held_at,
        stripe_payment_intent_id=new_order.stripe_payment_intent_id,
        client_secret=client_secret,
        created_at=new_order.created_at,
        updated_at=new_order.updated_at,
    )


@router.get(
    "/{order_id}",
    response_model=OrderResponse,
    summary="Get order details by order ID",
)
def get_order(
    order_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Returns order details. Restricted to buyer, seller, or admin.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    is_authorized = (
        order.buyer_id == auth_ctx.user_id
        or order.seller_id == auth_ctx.user_id
        or auth_ctx.has_role("admin")
    )
    if not is_authorized:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    return OrderResponse(
        id=order.id,
        listing_id=order.listing_id,
        listing_version_id=order.listing_version_id,
        buyer_id=order.buyer_id,
        seller_id=order.seller_id,
        amount_cents=order.amount_cents,
        amount_usd=round(order.amount_cents / 100.0, 2),
        platform_fee_cents=order.platform_fee_cents,
        seller_payout_cents=order.seller_payout_cents,
        status=order.status,
        hold_status=order.hold_status,
        hold_reason=order.hold_reason,
        held_at=order.held_at,
        stripe_payment_intent_id=order.stripe_payment_intent_id,
        created_at=order.created_at,
        updated_at=order.updated_at,
    )


@router.get(
    "/{order_id}/download",
    summary="Issue short-lived signed download URL for paid order",
)
def get_order_download(
    order_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Issues a short-lived cryptographically signed URL to download the purchased package version.
    
    SECURITY REQUIREMENTS:
    - Caller must be the buyer of the order.
    - Order status must be strictly 'paid'.
    - Link expires in 15 minutes.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    if order.buyer_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the purchasing buyer can access this download",
        )

    if order.status != OrderStatus.PAID.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot download package for order in status '{order.status}' (must be paid)",
        )

    storage_location = f"live/{order.listing_id}/{order.listing_version_id}"
    signed_url = generate_signed_download_url(
        order_id=order.id,
        buyer_id=order.buyer_id,
        listing_version_id=order.listing_version_id,
        storage_location=storage_location,
        ttl_seconds=settings.DOWNLOAD_LINK_TTL_SECONDS,
    )

    return {
        "order_id": order.id,
        "listing_version_id": order.listing_version_id,
        "download_url": signed_url,
        "expires_in_seconds": settings.DOWNLOAD_LINK_TTL_SECONDS,
    }


@router.get(
    "/download/package",
    summary="Download verified package payload using ephemeral signed token",
)
def download_package(token: str = Query(..., description="Signed ephemeral download token")):
    """
    Validates token and delivers the software archive.
    """
    try:
        payload = verify_download_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    return {
        "status": "authorized",
        "order_id": payload["order_id"],
        "listing_version_id": payload["version_id"],
        "storage_location": payload["loc"],
        "message": "Cryptographically verified package ready for digital delivery.",
    }


@router.get(
    "/check-entitlement/{buyer_id}/{listing_id}",
    summary="Inter-service & buyer entitlement verification",
)
def check_entitlement(
    buyer_id: str,
    listing_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Checks if a buyer has purchased and is entitled to a listing.

    HARDENED ANTI-ENUMERATION ACCESS CONTROL:
    Restricted to prevent purchase enumeration:
    1. Internal service holding X-Internal-Secret matching settings.INTERNAL_SERVICE_SECRET.
    2. Authenticated buyer checking their own entitlement (JWT sub == buyer_id).
    3. Authenticated admin.
    4. Development-mode internal caller (X-Internal-Caller == 'listings-service').
    All unauthenticated or probing external requests fail closed (401).
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
            from src.auth import decode_access_token
            claims = decode_access_token(token)
            if claims.get("sub") == buyer_id or "admin" in claims.get("roles", []):
                is_authorized_user = True
        except Exception:
            pass

    is_dev_caller = (
        settings.ENVIRONMENT.lower() == "development"
        and request.headers.get("X-Internal-Caller") == "listings-service"
    )

    if not (is_internal_service or is_authorized_user or is_dev_caller):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access denied: valid internal service secret or authorized buyer session required",
        )

    order = (
        db.query(Order)
        .filter(
            Order.buyer_id == buyer_id,
            Order.listing_id == listing_id,
            Order.status == OrderStatus.PAID.value,
        )
        .order_by(Order.created_at.desc())
        .first()
    )

    if order:
        return {
            "has_entitlement": True,
            "order_id": order.id,
            "listing_version_id": order.listing_version_id,
            "purchased_at": order.created_at.isoformat() if order.created_at else None,
        }

    return {
        "has_entitlement": False,
        "order_id": None,
        "listing_version_id": None,
        "purchased_at": None,
    }


# FAIL-CLOSED PRODUCTION GUARDRAIL:
# The /test-confirm route is strictly registered in non-production environments.
# In production, this route does not exist at all, preventing unauthorized payment bypass.
if settings.ENVIRONMENT.lower() != "production":
    @router.post(
        "/{order_id}/test-confirm",
        response_model=OrderResponse,
        summary="Complete payment in test/development environment (dev/test only)",
    )
    def test_confirm_order(
        order_id: str,
        auth_ctx: AuthContext = Depends(require_auth),
        db: Session = Depends(get_db),
    ):
        """
        Simulates successful Stripe payment completion for testing/development.
        Transitions order to 'paid', issues entitlement, and applies deterministic fraud checks.
        Refused in production.
        """
        order = db.query(Order).filter(Order.id == order_id).first()
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

        if order.buyer_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        if order.status == OrderStatus.PAID.value:
            return OrderResponse.from_orm_order(order)

        order.status = OrderStatus.PAID.value
        order.updated_at = utc_now()

        # Create Entitlement Record
        existing_entitlement = db.query(Entitlement).filter(Entitlement.order_id == order.id).first()
        if not existing_entitlement:
            entitlement = Entitlement(
                order_id=order.id,
                buyer_id=order.buyer_id,
                listing_version_id=order.listing_version_id,
                status=EntitlementStatus.ACTIVE.value,
            )
            db.add(entitlement)

        # Evaluate deterministic fraud rules
        should_hold, hold_reason = evaluate_fraud_rules(order, db)
        if should_hold:
            order.hold_status = HoldStatus.HELD.value
            order.hold_reason = hold_reason
            order.held_at = utc_now()
        else:
            order.hold_status = HoldStatus.NONE.value

        db.commit()
        db.refresh(order)

        # Emit order_paid notification to seller
        emit_notification(
            user_id=order.seller_id,
            notification_type="order_paid",
            payload={
                "order_id": order.id,
                "listing_id": order.listing_id,
                "amount_cents": order.amount_cents,
                "buyer_id": order.buyer_id,
                "role": "seller",
            },
        )
        # Emit order_paid notification to buyer
        emit_notification(
            user_id=order.buyer_id,
            notification_type="order_paid",
            payload={
                "order_id": order.id,
                "listing_id": order.listing_id,
                "amount_cents": order.amount_cents,
                "role": "buyer",
            },
        )

        return OrderResponse.from_orm_order(order)


