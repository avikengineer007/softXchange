"""
apps/buyer-assist/buyer_assist/routes/assist.py

Route handlers for buyer-assist capabilities:
- POST /assist/search: Natural-language vector search over live listings.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from buyer_assist.search import (
    SearchQueryRequest,
    SearchQueryResponse,
    search_listings,
)

from typing import List, Optional
from pydantic import BaseModel, Field
from src.models.listing import Listing, ListingStatus, ListingVersion, SearchEvent
from ml_shared.context import ListingContextBundle, SellerDocument
from ml_shared.rag import ListingQAService, AnswerResult

logger = logging.getLogger("buyer-assist.routes.assist")

router = APIRouter(prefix="/assist", tags=["Buyer Assist"])


class AskQuestionRequest(BaseModel):
    """Buyer question request for a specific listing."""
    question: str = Field(..., min_length=1, description="Buyer's question about the listing")


class AskQuestionResponse(BaseModel):
    """Grounded RAG answer response."""
    listing_id: str
    question: str
    answer: str
    grounded: bool
    context_sources: List[str]
    guardrail_status: str


@router.post(
    "/search",
    response_model=SearchQueryResponse,
    summary="Natural language listing search",
    description=(
        "Embeds natural language query using shared BGE-small model and returns "
        "relevance-ranked live software listings. Supplements keyword search."
    ),
)
def search_endpoint(
    payload: SearchQueryRequest,
    db: Session = Depends(get_db),
):
    """
    Executes semantic vector retrieval against live listings.
    Reuses listings-service's own live-only guarantee.
    """
    try:
        results = search_listings(
            query=payload.query,
            db=db,
            limit=payload.limit,
            min_score=payload.min_score,
        )

        # Record search query event for aggregate demand signals (strictly zero buyer identity)
        try:
            matched_cat = results[0].category if results else None
            search_event = SearchEvent(
                query_text=payload.query.strip(),
                matched_category=matched_cat,
            )
            db.add(search_event)
            db.commit()
        except Exception as log_err:
            logger.warning(f"Failed to record search query event: {log_err}")
            db.rollback()

        return SearchQueryResponse(
            query=payload.query,
            total=len(results),
            results=results,
        )
    except Exception as exc:
        logger.error(f"Error executing natural-language search: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Semantic search failed: {str(exc)}",
        )


@router.post(
    "/listings/{listing_id}/ask",
    response_model=AskQuestionResponse,
    summary="Ask a question about a specific listing using RAG",
    description=(
        "Answers buyer questions grounded strictly in the listing's context bundle and docs. "
        "Security questions strictly quote real scan severity counts; questions outside context "
        "honestly refuse to answer. Guardrail enforced."
    ),
)
def ask_listing_question_endpoint(
    listing_id: str,
    payload: AskQuestionRequest,
    db: Session = Depends(get_db),
):
    """
    Retrieves listing context bundle and generates a verified, grounded answer.
    Enforces live-only public visibility: non-live or non-existent listings return 404.
    """
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing or listing.status != ListingStatus.LIVE.value:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Listing not found",
        )

    # 1. Retrieve active version & scan details
    active_version = None
    if listing.current_version_id and listing.versions:
        for v in listing.versions:
            if v.id == listing.current_version_id:
                active_version = v
                break
    if not active_version and listing.versions:
        active_version = listing.versions[0]

    scan_data = {
        "scan_status": active_version.scan_status if active_version else "passed",
        "severity_counts": active_version.findings_summary if active_version else {},
        "scan_job_id": active_version.scan_job_id if active_version else None,
    }

    # 2. Construct canonical ListingContextBundle
    bundle = ListingContextBundle.from_listing_and_scan(
        listing_data=listing,
        scan_data=scan_data,
        seller_docs=getattr(listing, "seller_docs", None) or [],
    )

    # 3. Answer question via RAG and fail-closed guardrails
    qa_service = ListingQAService()
    qa_res: AnswerResult = qa_service.answer_question(bundle, payload.question)

    return AskQuestionResponse(
        listing_id=listing.id,
        question=payload.question,
        answer=qa_res.answer,
        grounded=qa_res.grounded,
        context_sources=qa_res.context_sources,
        guardrail_status=qa_res.guardrail_status,
    )
