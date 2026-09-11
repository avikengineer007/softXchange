"""
apps/broker/broker/routes/demand.py

Route handlers for demand signal aggregation and search event ingestion.
Exposes GET /broker/sellers/{seller_id}/demand-signals.
"""

from typing import Optional
import logging
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from src.database import get_db
from src.models.listing import SearchEvent
from broker.demand import (
    SellerDemandSignalsResponse,
    demand_service,
)

logger = logging.getLogger("broker.routes.demand")

router = APIRouter(prefix="/broker", tags=["Demand Signals"])


class RecordSearchEventRequest(BaseModel):
    query_text: str = Field(..., min_length=1, max_length=500)
    matched_category: Optional[str] = Field(None, max_length=64)


class RecordSearchEventResponse(BaseModel):
    id: str
    status: str = "recorded"


@router.get(
    "/sellers/{seller_id}/demand-signals",
    response_model=SellerDemandSignalsResponse,
    summary="Aggregate 7-day buyer interest signals for seller listings",
    description=(
        "Surfaces observational buyer search and inquiry activity aggregated over a "
        "rolling 7-day window. Strictly preserves buyer privacy by stripping all buyer identities. "
        "Purely read-only and informational; zero transactional side effects."
    ),
)
def get_seller_demand_signals(
    seller_id: str,
    forced_summary_for_test: Optional[str] = Query(
        None,
        description="Internal test injection hook to verify guardrail enforcement on demand signals",
    ),
    db: Session = Depends(get_db),
):
    """
    Returns non-committal, observational aggregate demand signals per seller listing.
    """
    return demand_service.aggregate_for_seller(
        seller_id=seller_id,
        db=db,
        forced_summary_for_test=forced_summary_for_test,
    )


@router.post(
    "/events/search",
    response_model=RecordSearchEventResponse,
    summary="Record an anonymous search event for demand signal aggregation",
)
def record_search_event(
    payload: RecordSearchEventRequest,
    db: Session = Depends(get_db),
):
    """
    Logs an anonymous search query for rolling window demand aggregation.
    Guarantees zero buyer identification.
    """
    event = SearchEvent(
        query_text=payload.query_text.strip(),
        matched_category=payload.matched_category,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return RecordSearchEventResponse(id=event.id, status="recorded")
