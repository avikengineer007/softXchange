"""
apps/seller-assist/seller_assist/routes/reply.py

Route handlers for drafting and sending buyer replies.
"""

from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.models.listing import Listing, BuyerQuestion
from seller_assist.auth import AuthContext, require_seller
from seller_assist.reply import (
    DraftReplyResponse,
    SendReplyRequest,
    SentReplyResponse,
    generate_draft_reply,
    deliver_seller_reply,
)
from ml_shared.guardrails import GuardrailViolationError, format_guardrail_refusal

router = APIRouter(tags=["Buyer Reply Assistance"])


class DraftReplyRequest(BaseModel):
    forced_reply_for_test: Optional[str] = Field(
        None,
        description="Internal test injection hook to verify guardrail enforcement on drafts",
    )


@router.post(
    "/assist/seller/questions/{question_id}/draft-reply",
    response_model=DraftReplyResponse,
    summary="Generate an AI-suggested draft reply to a buyer question (Draft only; never auto-sent)",
)
def draft_buyer_reply(
    question_id: str,
    request: Optional[DraftReplyRequest] = None,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Generates a draft reply grounded in the listing's context bundle.
    Strictly advisory: returned to seller, never delivered to the buyer automatically.
    """
    question = db.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
    if not question:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Buyer question '{question_id}' not found",
        )

    listing = db.query(Listing).filter(Listing.id == question.listing_id).first()
    if not listing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing for question '{question_id}' not found",
        )

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to draft replies for this listing",
        )

    forced_reply = request.forced_reply_for_test if request else None

    try:
        draft = generate_draft_reply(
            question=question,
            listing=listing,
            forced_reply_for_test=forced_reply,
        )
        # Store draft for instant retrieval when seller opens the view
        # Maintains zero send side-effects: seller_response and responded_at remain None
        question.draft_reply = draft.suggested_reply
        db.commit()
        db.refresh(question)
        return draft
    except GuardrailViolationError as exc:
        refusal_msg = format_guardrail_refusal(exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "guardrail_violation",
                "message": refusal_msg,
                "violated_rules": [v.rule_id for v in exc.violations],
            },
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post(
    "/assist/seller/questions/{question_id}/send",
    response_model=SentReplyResponse,
    summary="Explicitly send an approved reply to a buyer question",
)
def send_buyer_reply(
    question_id: str,
    request: SendReplyRequest,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Explicit action that delivers the seller's response to the buyer.
    """
    question = db.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
    if not question:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Buyer question '{question_id}' not found",
        )

    listing = db.query(Listing).filter(Listing.id == question.listing_id).first()
    if not listing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing for question '{question_id}' not found",
        )

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to reply to questions for this listing",
        )

    try:
        sent = deliver_seller_reply(
            question=question,
            listing=listing,
            response_text=request.response_text,
            db=db,
        )
        return sent
    except GuardrailViolationError as exc:
        refusal_msg = format_guardrail_refusal(exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "guardrail_violation",
                "message": refusal_msg,
                "violated_rules": [v.rule_id for v in exc.violations],
            },
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
