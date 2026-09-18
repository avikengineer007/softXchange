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
from src.razorpay_client import razorpay_client
from src.models.seller_payment_profile import SellerPaymentProfile
from src.models.order import Order, OrderStatus, HoldStatus, utc_now
from src.models.entitlement import Entitlement, EntitlementStatus
from src.fraud import evaluate_fraud_rules
from src.notifications_client import emit_notification

logger = logging.getLogger("payments-service.routes.webhooks")

router = APIRouter(prefix="/payments/webhooks", tags=["Webhooks"])


def _send_authenticated_kyc_callback(user_id: str, status_str: str, razorpay_account_id: str) -> bool:
    """
    Sends an HMAC-signed inter-service callback to auth-service's KYC webhook.
    Guarantees service-to-service authentication and 5-minute replay protection.
    Reuses the existing hardened mechanism.
    """
    url = f"{settings.AUTH_SERVICE_URL}/auth/seller/kyc/webhook"
    timestamp = str(int(time.time()))
    payload = {
        "user_id": user_id,
        "event": f"razorpay.route.{status_str}",
        "status": status_str,
        "details": {"razorpay_account_id": razorpay_account_id},
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
    "/razorpay",
    summary="Razorpay webhook endpoint for Route account activations and Order/Payment captures",
)
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Verifies Razorpay signature from raw body via X-Razorpay-Signature header.
    Processes:
    - account.activated: bridges Route linked account activation into auth-service KYC webhook.
    - account.under_review / needs_clarification / suspended: fails closed (does not advance KYC status).
    - order.paid / payment.captured: transitions order to 'paid', creates entitlement, and scores fraud holds
      with strict idempotency.
    """
    payload_bytes = await request.body()
    sig_header = request.headers.get("X-Razorpay-Signature")

    if not sig_header:
        logger.warning("Rejecting Razorpay webhook missing X-Razorpay-Signature header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Razorpay-Signature header",
        )

    is_valid = razorpay_client.verify_webhook_signature(payload_bytes, sig_header)
    if not is_valid:
        logger.warning("Razorpay webhook signature verification failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook signature verification failed",
        )

    try:
        event = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON payload: {str(exc)}",
        )

    event_type = event.get("event")
    payload_data = event.get("payload", {})

    logger.info(f"Processing Razorpay webhook event: {event_type}")

    # =========================================================================
    # 1. Razorpay Route Linked Account Events
    # =========================================================================
    if event_type == "account.activated":
        account_obj = payload_data.get("account", {}).get("entity", {})
        account_id = account_obj.get("id") or event.get("account_id")

        if account_id:
            profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.razorpay_account_id == account_id).first()
            if profile:
                logger.info(f"Linked account {account_id} activated for seller {profile.user_id}; notifying auth-service")
                _send_authenticated_kyc_callback(
                    user_id=profile.user_id,
                    status_str="verified",
                    razorpay_account_id=profile.razorpay_account_id,
                )
            else:
                logger.warning(f"No SellerPaymentProfile found for activated Razorpay account {account_id}")

    elif event_type in ["account.under_review", "account.needs_clarification", "account.suspended", "account.rejected"]:
        account_obj = payload_data.get("account", {}).get("entity", {})
        account_id = account_obj.get("id") or event.get("account_id")
        logger.info(f"Linked account {account_id} status '{event_type}'; notifying auth-service to fail closed.")
        if account_id:
            profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.razorpay_account_id == account_id).first()
            if profile:
                target_status = "suspended" if event_type == "account.suspended" else ("rejected" if event_type == "account.rejected" else "pending_review")
                _send_authenticated_kyc_callback(
                    user_id=profile.user_id,
                    status_str=target_status,
                    razorpay_account_id=profile.razorpay_account_id,
                )

    # =========================================================================
    # 2. Payment Captured / Order Paid Events
    # =========================================================================
    elif event_type in ["order.paid", "payment.captured"]:
        order_entity = payload_data.get("order", {}).get("entity", {})
        payment_entity = payload_data.get("payment", {}).get("entity", {})

        rzp_order_id = order_entity.get("id") or payment_entity.get("order_id")
        rzp_payment_id = payment_entity.get("id")
        notes = order_entity.get("notes") or payment_entity.get("notes") or {}

        order = None
        if rzp_order_id:
            order = db.query(Order).filter(Order.razorpay_order_id == rzp_order_id).first()
        if not order and notes.get("order_id"):
            order = db.query(Order).filter(Order.id == notes.get("order_id")).first()

        if not order:
            logger.warning(f"No order found matching Razorpay order_id={rzp_order_id}, notes={notes}")
            return {"status": "order_not_found"}

        # Idempotency Check: Skip duplicate processing if already paid
        if order.status == OrderStatus.PAID.value:
            logger.info(f"Order {order.id} is already paid. Skipping duplicate webhook processing.")
            return {"status": "already_processed", "order_id": order.id}

        # Transition order to PAID
        order.status = OrderStatus.PAID.value
        if rzp_payment_id:
            order.razorpay_payment_id = rzp_payment_id
        order.updated_at = utc_now()

        # Create Entitlement Record if not already created
        existing_entitlement = db.query(Entitlement).filter(Entitlement.order_id == order.id).first()
        if not existing_entitlement:
            entitlement = Entitlement(
                order_id=order.id,
                buyer_id=order.buyer_id,
                listing_version_id=order.listing_version_id,
                status=EntitlementStatus.ACTIVE.value,
            )
            db.add(entitlement)

        # Evaluate Deterministic Fraud Hold Rules
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

        return {"received": True, "event": event_type, "order_id": order.id}

    return {"received": True, "event": event_type}
