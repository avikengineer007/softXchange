import json
import logging
import hashlib
import hmac
import time
import httpx
from fastapi import APIRouter, Request, HTTPException, status, Depends
from sqlalchemy.orm import Session

from src.database import get_db
from src.config import settings
from src.stripe_client import stripe_client
from src.models.seller_payment_profile import SellerPaymentProfile
from src.models.order import Order, OrderStatus, HoldStatus, utc_now
from src.models.entitlement import Entitlement, EntitlementStatus
from src.fraud import evaluate_fraud_rules
from src.notifications_client import emit_notification

logger = logging.getLogger("payments-service.routes.webhooks")

router = APIRouter(prefix="/payments/webhooks", tags=["Webhooks"])


def _send_authenticated_kyc_callback(user_id: str, status_str: str, stripe_account_id: str) -> bool:
    """
    Sends an HMAC-signed inter-service callback to auth-service's KYC webhook.
    Guarantees service-to-service authentication and 5-minute replay protection.
    """
    url = f"{settings.AUTH_SERVICE_URL}/auth/seller/kyc/webhook"
    timestamp = str(int(time.time()))
    payload = {
        "user_id": user_id,
        "event": f"stripe.connect.{status_str}",
        "status": status_str,
        "details": {"stripe_account_id": stripe_account_id},
    }
    raw_json = json.dumps(payload, sort_keys=True).encode("utf-8")
    signed_payload = f"{timestamp}.".encode("utf-8") + raw_json
    signature = hmac.new(
        settings.INTERNAL_SERVICE_SECRET.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                url,
                content=raw_json,
                headers={
                    "Content-Type": "application/json",
                    "X-Service-Timestamp": timestamp,
                    "X-Service-Signature": signature,
                },
            )
            if resp.status_code == 200:
                logger.info(f"Successfully notified auth-service of KYC status '{status_str}' for user {user_id}")
                return True
            else:
                logger.warning(f"Auth-service returned status {resp.status_code} for KYC callback: {resp.text}")
                return False
    except Exception as exc:
        logger.error(f"Failed to deliver KYC webhook to auth-service ({url}): {exc}")
        return False


@router.post(
    "/stripe",
    summary="Stripe webhook endpoint for Connect account updates and PaymentIntent completions",
)
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Verifies Stripe signature from raw body.
    Processes:
    - account.updated: bridges Connect onboarding status into auth-service KYC webhook.
    - payment_intent.succeeded: transitions order to 'paid', creates entitlement, and scores fraud holds.
    """
    payload_bytes = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    if not sig_header:
        logger.warning("Rejecting Stripe webhook missing Stripe-Signature header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe-Signature header",
        )

    try:
        event = stripe_client.construct_webhook_event(payload_bytes, sig_header)
    except Exception as exc:
        logger.warning(f"Stripe webhook signature verification failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook signature verification failed: {str(exc)}",
        )

    event_type = event.get("type") if isinstance(event, dict) else getattr(event, "type", None)
    data_obj = event.get("data", {}).get("object", {}) if isinstance(event, dict) else getattr(getattr(event, "data", None), "object", {})

    logger.info(f"Processing Stripe webhook event: {event_type}")

    # =========================================================================
    # 1. Stripe Connect Account Updated (Prompt 1)
    # =========================================================================
    if event_type == "account.updated":
        account_id = data_obj.get("id") if isinstance(data_obj, dict) else getattr(data_obj, "id", None)
        charges_enabled = data_obj.get("charges_enabled", False) if isinstance(data_obj, dict) else getattr(data_obj, "charges_enabled", False)
        payouts_enabled = data_obj.get("payouts_enabled", False) if isinstance(data_obj, dict) else getattr(data_obj, "payouts_enabled", False)

        profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.stripe_account_id == account_id).first()
        if profile and account_id:
            if charges_enabled and payouts_enabled:
                # Both enabled -> Notify auth-service that KYC is verified
                _send_authenticated_kyc_callback(
                    user_id=profile.user_id,
                    status_str="verified",
                    stripe_account_id=profile.stripe_account_id,
                )
            else:
                logger.info(f"Connect account {account_id} requirements pending (charges: {charges_enabled}, payouts: {payouts_enabled})")

    # =========================================================================
    # 2. Payment Intent Succeeded (Prompt 3 & 4)
    # =========================================================================
    elif event_type == "payment_intent.succeeded":
        pi_id = data_obj.get("id") if isinstance(data_obj, dict) else getattr(data_obj, "id", None)
        order = db.query(Order).filter(Order.stripe_payment_intent_id == pi_id).first()

        if not order:
            logger.warning(f"No order found matching PaymentIntent {pi_id}")
            return {"status": "order_not_found"}

        # Idempotency Check: Skip duplicate processing if already paid
        if order.status == OrderStatus.PAID.value:
            logger.info(f"Order {order.id} is already paid. Skipping duplicate webhook processing.")
            return {"status": "already_processed"}

        # Transition order to PAID
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

        # Evaluate Deterministic Fraud Hold Rules (Prompt 4)
        should_hold, hold_reason = evaluate_fraud_rules(order, db)
        if should_hold:
            order.hold_status = HoldStatus.HELD.value
            order.hold_reason = hold_reason
            order.held_at = utc_now()
            logger.warning(f"Order {order.id} held for fraud review: {hold_reason}")
        else:
            order.hold_status = HoldStatus.NONE.value

        db.commit()

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

    return {"received": True, "event_type": event_type}
