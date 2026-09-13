"""
apps/broker/broker/routing.py

Broker question routing engine (Prompt 1 & Prompt 2).
Reuses buyer-assist's ListingQAService and ListingContextBundle directly.
Deterministic routing rule:
- grounded == True: answered_directly (no seller involvement needed)
- grounded == False: routed_to_seller (creates BuyerQuestion, triggers proactive draft-reply)
"""

from typing import Optional, List, Dict, Any
import logging
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ml_shared.context import ListingContextBundle
from ml_shared.rag import ListingQAService, AnswerResult
from src.models.listing import Listing, ListingStatus, ListingVersion, BuyerQuestion
from broker.seller_client import seller_client

logger = logging.getLogger("broker.routing")


class RouteQuestionRequest(BaseModel):
    """
    Request model matching BuyerQuestion input format.
    """
    question_text: str = Field(..., min_length=1, max_length=2000, description="Buyer question text")
    buyer_id: Optional[str] = Field(None, description="Identifier of the asking buyer")
    question_id: Optional[str] = Field(None, description="Pre-existing question ID if already recorded")
    forced_draft_for_test: Optional[str] = Field(None, description="Test hook for forcing a draft in seller-assist")


class RouteQuestionResponse(BaseModel):
    """
    Deterministic routing response shape:
    Makes outcome explicit to caller (web/Android frontend).
    """
    resolution: str = Field(..., description="'answered_directly' or 'routed_to_seller'")
    answer: Optional[str] = Field(None, description="Grounded answer if answered_directly")
    question_id: Optional[str] = Field(None, description="ID of the created/routed question if routed_to_seller")
    context_sources: Optional[List[str]] = Field(None, description="Sources referenced if answered_directly")
    guardrail_status: Optional[str] = Field(None, description="Guardrail evaluation status")


class QuestionRouter:
    """
    Deterministic question routing engine.
    Never answers with authority on its own: reuses ListingQAService directly.
    """

    def __init__(self, qa_service: Optional[ListingQAService] = None):
        self.qa_service = qa_service or ListingQAService()

    def route_question(
        self,
        listing: Listing,
        request: RouteQuestionRequest,
        db: Session,
    ) -> RouteQuestionResponse:
        """
        Evaluates question groundedness against public listing bundle.
        Routes deterministically: grounded -> direct answer; ungrounded -> seller.
        """
        clean_question = request.question_text.strip()
        buyer_id = request.buyer_id or "buyer-anon"

        # 1. Resolve active version and scan data from listing
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

        # 2. Build canonical ListingContextBundle
        bundle = ListingContextBundle.from_listing_and_scan(
            listing_data=listing,
            scan_data=scan_data,
            seller_docs=getattr(listing, "seller_docs", None) or [],
        )

        # 3. Call buyer-assist's ListingQAService (deterministic intent & grounding)
        qa_result: AnswerResult = self.qa_service.answer_question(bundle, clean_question)

        # 4. Deterministic routing decision
        if qa_result.grounded is True:
            # SECURITY or GROUNDED_DETAIL: answer directly from verified public data
            return RouteQuestionResponse(
                resolution="answered_directly",
                answer=qa_result.answer,
                question_id=None,
                context_sources=qa_result.context_sources,
                guardrail_status=qa_result.guardrail_status,
            )

        # 5. OUT_OF_CONTEXT: Route to seller
        question = None
        if request.question_id:
            question = db.query(BuyerQuestion).filter(BuyerQuestion.id == request.question_id).first()

        if not question:
            question = BuyerQuestion(
                listing_id=listing.id,
                buyer_id=buyer_id,
                question_text=clean_question,
            )
            db.add(question)
            db.commit()
            db.refresh(question)

        # 6. Proactive draft hand-off to seller-assist (server-to-server)
        # Fails soft: question routing is never blocked by drafting failures
        try:
            seller_client.trigger_draft_reply(
                question_id=question.id,
                forced_reply_for_test=request.forced_draft_for_test,
            )
        except Exception as draft_err:
            logger.warning(
                f"Proactive drafting hand-off failed for question {question.id} (non-fatal): {draft_err}"
            )

        return RouteQuestionResponse(
            resolution="routed_to_seller",
            answer=None,
            question_id=question.id,
            context_sources=None,
            guardrail_status=None,
        )


question_router = QuestionRouter()
