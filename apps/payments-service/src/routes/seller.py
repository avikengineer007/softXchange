from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.database import get_db
from src.auth import require_seller, AuthContext
from src.models.order import Order, OrderStatus, HoldStatus

router = APIRouter(prefix="/payments/seller", tags=["Seller Payouts"])
alias_router = APIRouter(prefix="/seller", tags=["Seller Payouts Alias"])


class SellerOrderItem(BaseModel):
    id: str
    listing_id: str
    amount_cents: int
    amount_usd: float
    platform_fee_cents: int
    seller_payout_cents: int
    seller_payout_usd: float
    display_status: str
    status_message: str
    created_at: datetime
    seller_net_cents: Optional[int] = None
    hold_status: Optional[str] = None
    hold_reason: Optional[str] = None


class SellerDashboardResponse(BaseModel):
    user_id: str
    available_payout_cents: int
    available_payout_usd: float
    under_review_payout_cents: int
    under_review_payout_usd: float
    total_sales_count: int
    orders: List[SellerOrderItem]
    available_usd: Optional[float] = None
    held_usd: Optional[float] = None


@router.get(
    "/dashboard",
    response_model=SellerDashboardResponse,
    summary="Get seller payout metrics and orders with honest, non-accusatory review messaging",
)
@router.get(
    "/payouts",
    response_model=SellerDashboardResponse,
    summary="Get seller payout metrics (alias for /dashboard)",
)
def get_seller_payout_dashboard(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns seller's payout totals and recent transactions.
    
    HONEST MESSAGING PRINCIPLE:
    Held transactions are displayed honestly as 'under_review' with
    'Order is under routine security review.' Never accusatory or alarming.
    """
    seller_id = auth_ctx.user_id

    orders = (
        db.query(Order)
        .filter(Order.seller_id == seller_id)
        .order_by(Order.created_at.desc())
        .all()
    )

    available_cents = 0
    under_review_cents = 0
    order_items = []

    for o in orders:
        if o.status == OrderStatus.PAID.value:
            if o.hold_status == HoldStatus.HELD.value:
                under_review_cents += o.seller_payout_cents
                display_status = "under_review"
                status_message = "Order is under routine security review."
            else:
                available_cents += o.seller_payout_cents
                display_status = "cleared"
                status_message = "Funds cleared for payout."
        elif o.status == OrderStatus.REFUNDED.value:
            display_status = "refunded"
            status_message = "Order was refunded."
        else:
            display_status = o.status
            status_message = "Payment is pending confirmation."

        order_items.append(
            SellerOrderItem(
                id=o.id,
                listing_id=o.listing_id,
                amount_cents=o.amount_cents,
                amount_usd=round(o.amount_cents / 100.0, 2),
                platform_fee_cents=o.platform_fee_cents,
                seller_payout_cents=o.seller_payout_cents,
                seller_payout_usd=round(o.seller_payout_cents / 100.0, 2),
                display_status=display_status,
                status_message=status_message,
                created_at=o.created_at,
                seller_net_cents=o.seller_payout_cents,
                hold_status=o.hold_status or ("held" if display_status == "under_review" else "cleared"),
                hold_reason=status_message,
            )
        )

    return SellerDashboardResponse(
        user_id=seller_id,
        available_payout_cents=available_cents,
        available_payout_usd=round(available_cents / 100.0, 2),
        under_review_payout_cents=under_review_cents,
        under_review_payout_usd=round(under_review_cents / 100.0, 2),
        total_sales_count=len([o for o in orders if o.status == OrderStatus.PAID.value]),
        orders=order_items,
        available_usd=round(available_cents / 100.0, 2),
        held_usd=round(under_review_cents / 100.0, 2),
    )


alias_router.add_api_route("/dashboard", get_seller_payout_dashboard, methods=["GET"], response_model=SellerDashboardResponse)
alias_router.add_api_route("/payouts", get_seller_payout_dashboard, methods=["GET"], response_model=SellerDashboardResponse)
