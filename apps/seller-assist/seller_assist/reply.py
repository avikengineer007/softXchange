"""
apps/seller-assist/seller_assist/reply.py

Drafted buyer-reply suggestions engine for seller-assist.

Strict guarantees:
1. Draft only: POST .../draft-reply returns an editable draft; it NEVER auto-sends.
2. Explicit send: sending requires a separate, explicit action (POST .../send).
3. Grounded: reuses buyer-assist RAG logic over the ListingContextBundle.
4. Fail-closed guardrails: checks enforce_guardrails() before the draft is shown to the seller.
"""

from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

from ml_shared.context import ListingContextBundle
from ml_shared.guardrails import (
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
)
from buyer_assist.rag import ListingQAService, AnswerResult
from src.models.listing import Listing, BuyerQuestion, utc_now


class DraftReplyResponse(BaseModel):
    question_id: str
    listing_id: str
    question_text: str
    suggested_reply: str
    context_sources: List[str]
    sent: bool = False
    notice: str = (
        "Draft only. This response has NOT been sent to the buyer. "
        "Review, edit freely, and click 'Send Reply' to deliver it."
    )


class SendReplyRequest(BaseModel):
    response_text: str = Field(..., min_length=1, max_length=2000, description="The approved reply text to send")


class SentReplyResponse(BaseModel):
    id: str
    listing_id: str
    buyer_id: str
    question_text: str
    seller_response: str
    created_at: datetime
    responded_at: datetime
    sent: bool = True

    model_config = ConfigDict(from_attributes=True)


qa_service = ListingQAService()


def generate_draft_reply(
    question: BuyerQuestion,
    listing: Listing,
    forced_reply_for_test: Optional[str] = None,
) -> DraftReplyResponse:
    """
    Generates a suggested reply grounded in the listing's context bundle.
    Guaranteed strictly read-only: does not modify the question record.
    """
    bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing)

    if forced_reply_for_test:
        suggested_reply = forced_reply_for_test
        sources = ["test_injection"]
    else:
        answer_result: AnswerResult = qa_service.answer_question(
            bundle=bundle,
            question=question.question_text,
        )
        suggested_reply = answer_result.answer
        sources = answer_result.context_sources

    # Guardrail check on draft reply before seller sees it
    enforce_guardrails(suggested_reply, bundle)

    return DraftReplyResponse(
        question_id=question.id,
        listing_id=listing.id,
        question_text=question.question_text,
        suggested_reply=suggested_reply,
        context_sources=sources,
        sent=False,
    )


def deliver_seller_reply(
    question: BuyerQuestion,
    listing: Listing,
    response_text: str,
    db: Session,
) -> SentReplyResponse:
    """
    Delivers the seller's approved response to the buyer.
    Validates with guardrails before committing.
    """
    bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing)
    enforce_guardrails(response_text, bundle)

    question.seller_response = response_text.strip()
    question.responded_at = utc_now()
    db.commit()
    db.refresh(question)

    return SentReplyResponse(
        id=question.id,
        listing_id=question.listing_id,
        buyer_id=question.buyer_id,
        question_text=question.question_text,
        seller_response=question.seller_response,
        created_at=question.created_at,
        responded_at=question.responded_at,
        sent=True,
    )
