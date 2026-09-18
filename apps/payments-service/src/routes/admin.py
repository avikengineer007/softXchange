from datetime import datetime, timezone
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.auth import require_admin, AuthContext
from src.models.order import Order, OrderStatus, HoldStatus, HeldOrderResponse, OrderResponse, utc_now
from src.models.entitlement import Entitlement, EntitlementStatus
from src.config import settings
from src.razorpay_client import razorpay_client

logger = logging.getLogger("payments-service.routes.admin")

router = APIRouter(prefix="/payments/orders", tags=["Admin Fraud & Hold Management"])


@router.get(
    "/held",
    response_model=List[HeldOrderResponse],
    summary="List all held orders sorted by hold age for 48-hour SLA human review",
)
def list_held_orders(
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns all orders currently in 'held' status, sorted by hold duration (oldest first).
    Calculates hours held against the 48-hour human review SLA.
    """
    held_orders = (
        db.query(Order)
        .filter(Order.hold_status == HoldStatus.HELD.value)
        .order_by(Order.held_at.asc())
        .all()
    )

    now = datetime.now(timezone.utc)
    results = []
    for order in held_orders:
        held_time = order.held_at or order.created_at
        if held_time.tzinfo is None:
            held_time = held_time.replace(tzinfo=timezone.utc)
        duration_seconds = max(0.0, (now - held_time).total_seconds())
        hours_held = round(duration_seconds / 3600.0, 1)

        results.append(
            HeldOrderResponse(
                id=order.id,
                listing_id=order.listing_id,
                buyer_id=order.buyer_id,
                seller_id=order.seller_id,
                amount_cents=order.amount_cents,
                amount_inr=round(order.amount_cents / 100.0, 2),
                amount_usd=round(order.amount_cents / 100.0, 2),
                hold_status=order.hold_status,
                hold_reason=order.hold_reason,
                held_at=held_time,
                hours_held=hours_held,
                sla_breached=hours_held > 48.0,
            )
        )

    return results


@router.post(
    "/{order_id}/release",
    response_model=OrderResponse,
    summary="Admin release of a held order to normal payout timing",
)
def release_order_hold(
    order_id: str,
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Clears fraud hold on a specific order, allowing payout to proceed normally.
    Does not affect any other orders.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    if order.hold_status != HoldStatus.HELD.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Order is not currently held (status: {order.hold_status})",
        )

    order.hold_status = HoldStatus.RELEASED.value
    order.updated_at = utc_now()
    db.commit()
    db.refresh(order)

    logger.info(f"Admin {auth_ctx.user_id} released hold on order {order_id}")
    return OrderResponse.from_orm_order(order, razorpay_key_id=settings.RAZORPAY_KEY_ID)


@router.post(
    "/{order_id}/refund",
    response_model=OrderResponse,
    summary="Admin refund of an order via Razorpay with entitlement revocation",
)
def refund_order(
    order_id: str,
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Refunds payment via Razorpay, transitions order to 'refunded',
    and revokes buyer entitlement.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    if order.status not in [OrderStatus.PAID.value, OrderStatus.PENDING_PAYMENT.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot refund order in status '{order.status}'",
        )

    # 1. Trigger Razorpay refund if payment was captured
    if order.razorpay_payment_id:
        try:
            razorpay_client.refund_payment(
                payment_id=order.razorpay_payment_id,
                amount_minor_units=order.amount_cents,
                notes={"reason": "fraudulent" if order.hold_status == HoldStatus.HELD.value else "requested_by_customer"},
            )
        except Exception as exc:
            logger.error(f"Razorpay refund failed for order {order_id}: {exc}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Razorpay refund failed: {str(exc)}",
            )

    # 2. Update order state
    order.status = OrderStatus.REFUNDED.value
    order.hold_status = HoldStatus.REFUNDED.value
    order.updated_at = utc_now()

    # 3. Explicitly revoke buyer entitlement
    entitlement = db.query(Entitlement).filter(Entitlement.order_id == order.id).first()
    if entitlement:
        entitlement.status = EntitlementStatus.REVOKED.value
        entitlement.revoked_at = utc_now()

    db.commit()
    db.refresh(order)

    logger.info(f"Admin {auth_ctx.user_id} refunded order {order_id} and revoked entitlement")
    return OrderResponse.from_orm_order(order, razorpay_key_id=settings.RAZORPAY_KEY_ID)
