"""
apps/seller-assist/seller_assist/routes/suggest.py

Route handlers for listing copy and pricing suggestions.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.models.listing import Listing
from seller_assist.auth import AuthContext, require_seller
from seller_assist.suggest import (
    CopySuggestionRequest,
    CopySuggestionResponse,
    generate_listing_suggestions,
)
from ml_shared.guardrails import GuardrailViolationError, format_guardrail_refusal

router = APIRouter(tags=["Seller Copy & Pricing Suggestions"])


@router.post(
    "/assist/seller/listings/{listing_id}/suggest-copy",
    response_model=CopySuggestionResponse,
    summary="Get AI draft suggestions for title, description, and price range",
)
def suggest_copy(
    listing_id: str,
    request: CopySuggestionRequest,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Suggests improvements to listing copy and pricing guidance grounded in comparable live listings.
    Seller-only, owner-only. Strictly advisory (no database modifications).
    """
    # 1. Fetch listing and verify ownership
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing '{listing_id}' not found",
        )

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access suggestions for this listing",
        )

    # 2. Generate suggestions through grounded engine with guardrail protection
    try:
        response = generate_listing_suggestions(
            listing_id=listing_id,
            request=request,
            db=db,
        )
        return response
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
