from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.models.order import Order, OrderStatus, HoldStatus


def evaluate_fraud_rules(
    order: Order,
    db: Session,
    new_seller_threshold_cents: int = 5000,  # $50.00
    new_seller_max_sales: int = 2,
    rapid_buyer_window_minutes: int = 10,
    rapid_buyer_order_limit: int = 3,
) -> Tuple[bool, Optional[str]]:
    """
    Deterministic rule-based fraud scoring executed at order creation.
    
    ISOLATION PRINCIPLE:
    Holds apply strictly to the specific order being evaluated.
    Never freezes a seller's entire balance or other orders.
    """
    # Rule 1: New seller with large transaction
    completed_sales_count = (
        db.query(func.count(Order.id))
        .filter(Order.seller_id == order.seller_id, Order.status == OrderStatus.PAID.value)
        .scalar()
        or 0
    )
    if completed_sales_count <= new_seller_max_sales and order.amount_cents >= new_seller_threshold_cents:
        return True, f"rule: NEW_SELLER_HIGH_AMOUNT (seller sales: {completed_sales_count}, amount: ${order.amount_cents/100:.2f})"

    # Rule 2: Rapid buyer purchase velocity
    time_threshold = datetime.now(timezone.utc) - timedelta(minutes=rapid_buyer_window_minutes)
    recent_buyer_orders = (
        db.query(func.count(Order.id))
        .filter(Order.buyer_id == order.buyer_id, Order.created_at >= time_threshold)
        .scalar()
        or 0
    )
    if recent_buyer_orders >= rapid_buyer_order_limit:
        return True, f"rule: RAPID_BUYER_VELOCITY ({recent_buyer_orders} orders in last {rapid_buyer_window_minutes}m)"

    return False, None
