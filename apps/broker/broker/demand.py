"""
apps/broker/broker/demand.py

Aggregate demand signals engine (Prompt 3).
Surfaces non-committal, purely observational buyer interest signals over a 7-day rolling window.
Privacy guarantee: aggregates counts and queries only; NEVER stores or surfaces buyer identity.
Guardrail enforcement: routes summary text through ml_shared.enforce_guardrails to strictly
catch and block any sales guarantees or promises.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import logging
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from broker.config import settings
from src.models.listing import Listing, ListingStatus, BuyerQuestion, SearchEvent, utc_now
from ml_shared.context import ListingContextBundle
from ml_shared.guardrails import (
    enforce_guardrails,
    GuardrailViolationError,
    format_guardrail_refusal,
)

logger = logging.getLogger("broker.demand")


class ListingDemandSignal(BaseModel):
    """
    Observational demand signal for an individual seller listing.
    Strictly devoid of individual buyer identities.
    """
    listing_id: str
    title: str
    category: str
    status: str
    total_questions_7d: int
    unanswered_questions_count: int
    answered_questions_count: int
    related_search_terms: List[str]
    signal_summary: str
    guardrail_status: str = "passed"


class SellerDemandSignalsResponse(BaseModel):
    """
    Seller dashboard aggregate demand signals response.
    """
    seller_id: str
    window_days: int = 7
    total_listings_tracked: int
    listings: List[ListingDemandSignal]


class DemandSignalService:
    """
    Aggregates search and inquiry activity over rolling window without individual buyer profiling.
    """

    def aggregate_for_seller(
        self,
        seller_id: str,
        db: Session,
        forced_summary_for_test: Optional[str] = None,
    ) -> SellerDemandSignalsResponse:
        """
        Calculates 7-day aggregate signals for all seller listings. Read-only, zero side effects.
        """
        now = utc_now()
        window_start = now - timedelta(days=settings.DEMAND_WINDOW_DAYS)

        # 1. Fetch seller listings
        seller_listings = (
            db.query(Listing)
            .filter(Listing.seller_id == seller_id)
            .order_by(Listing.created_at.desc())
            .all()
        )

        signals: List[ListingDemandSignal] = []

        for listing in seller_listings:
            # 2. Aggregate question counts in 7-day window
            # Questions on this specific listing
            listing_questions = (
                db.query(BuyerQuestion)
                .filter(
                    BuyerQuestion.listing_id == listing.id,
                    BuyerQuestion.created_at >= window_start,
                )
                .all()
            )

            # Questions across the entire category
            category_questions = (
                db.query(BuyerQuestion)
                .join(Listing, BuyerQuestion.listing_id == Listing.id)
                .filter(
                    Listing.category == listing.category,
                    BuyerQuestion.created_at >= window_start,
                )
                .all()
            )

            unanswered = sum(1 for q in category_questions if not q.seller_response)
            answered = sum(1 for q in category_questions if q.seller_response)
            total_q_7d = len(listing_questions)

            # 3. Aggregate search queries in 7-day window matching category or keywords
            # Guarantees buyer privacy: SearchEvent contains only query_text and timestamp
            cat_lower = listing.category.lower()
            title_keywords = [w.lower() for w in listing.title.split() if len(w) > 3]

            recent_searches = (
                db.query(SearchEvent.query_text)
                .filter(SearchEvent.created_at >= window_start)
                .order_by(SearchEvent.created_at.desc())
                .limit(200)
                .all()
            )

            matched_terms = []
            seen_terms = set()
            for (query_txt,) in recent_searches:
                q_clean = query_txt.strip().lower()
                if q_clean in seen_terms:
                    continue
                # Match if query mentions category or title keyword
                if cat_lower in q_clean or any(k in q_clean for k in title_keywords):
                    seen_terms.add(q_clean)
                    matched_terms.append(query_txt.strip())
                    if len(matched_terms) >= 5:
                        break

            # 4. Generate observational phrasing
            bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing)

            if forced_summary_for_test:
                candidate_summary = forced_summary_for_test
            else:
                if not matched_terms and total_q_7d == 0 and len(category_questions) == 0:
                    candidate_summary = "No notable demand signals recorded for this listing over the past 7 days."
                else:
                    parts = []
                    if matched_terms:
                        parts.append(f"{len(matched_terms)} recent search queries matched this category or topic")
                    if total_q_7d > 0:
                        parts.append(f"{total_q_7d} direct inquiries submitted this week")
                    if len(category_questions) > 0:
                        parts.append(f"{len(category_questions)} questions asked in '{listing.category}' ({unanswered} awaiting reply)")
                    
                    candidate_summary = "Observation: " + "; ".join(parts) + "."

            # 5. Strict Guardrail Verification on generated signal text
            # Catches any implied sales or revenue guarantees (Rule 2)
            try:
                verified_summary = enforce_guardrails(
                    candidate_summary,
                    bundle,
                    skip_price_check=True,
                )
                guardrail_status = "passed"
            except GuardrailViolationError as gv_err:
                logger.warning(f"Guardrail caught unverified claim in demand signal: {gv_err}")
                verified_summary = format_guardrail_refusal(gv_err)
                guardrail_status = "blocked"

            signals.append(
                ListingDemandSignal(
                    listing_id=listing.id,
                    title=listing.title,
                    category=listing.category,
                    status=listing.status,
                    total_questions_7d=total_q_7d,
                    unanswered_questions_count=unanswered,
                    answered_questions_count=answered,
                    related_search_terms=matched_terms,
                    signal_summary=verified_summary,
                    guardrail_status=guardrail_status,
                )
            )

        return SellerDemandSignalsResponse(
            seller_id=seller_id,
            window_days=settings.DEMAND_WINDOW_DAYS,
            total_listings_tracked=len(signals),
            listings=signals,
        )


demand_service = DemandSignalService()
