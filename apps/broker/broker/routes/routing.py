"""
apps/broker/broker/routes/routing.py

Question routing route handlers for broker service.
Exposes POST /broker/listings/{id}/route-question.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.models.listing import Listing, ListingStatus
from broker.routing import (
    RouteQuestionRequest,
    RouteQuestionResponse,
    question_router,
)

logger = logging.getLogger("broker.routes.routing")

router = APIRouter(prefix="/broker", tags=["Question Routing"])


@router.post(
    "/listings/{listing_id}/route-question",
    response_model=RouteQuestionResponse,
    summary="Route buyer question to instant grounded answer or seller with pre-draft",
    description=(
        "Deterministic routing decision: If the question is covered by public scan/listing "
        "data (grounded=True), returns an immediate direct answer with zero seller involvement. "
        "If out-of-context (grounded=False), creates/routes the BuyerQuestion to the seller and "
        "proactively initiates server-to-server drafting."
    ),
)
def route_listing_question(
    listing_id: str,
    payload: RouteQuestionRequest,
    db: Session = Depends(get_db),
):
    """
    Evaluates buyer inquiry and routes deterministically.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing '{listing_id}' not found",
        )

    # Public questions only routed for active/live listings
    if listing.status != ListingStatus.LIVE.value:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing '{listing_id}' is not live",
        )

    return question_router.route_question(
        listing=listing,
        request=payload,
        db=db,
    )
