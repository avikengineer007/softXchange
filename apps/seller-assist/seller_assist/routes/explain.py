"""
apps/seller-assist/seller_assist/routes/explain.py

Route handler for plain-English scan findings translation.
"""

from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.models.listing import Listing, ListingVersion
from seller_assist.auth import AuthContext, require_seller
from seller_assist.explain import (
    ExplainFindingsResponse,
    generate_findings_explanation,
)
from ml_shared.guardrails import GuardrailViolationError, format_guardrail_refusal

router = APIRouter(tags=["Scan Findings Plain-English Advisory"])


class ExplainFindingsRequest(BaseModel):
    # Optional test injection hook to verify guardrail enforcement on downplayed summaries
    forced_summary_for_test: Optional[str] = Field(
        None,
        description="Internal test injection hook to verify guardrail enforcement",
    )


@router.post(
    "/assist/seller/versions/{version_id}/explain-findings",
    response_model=ExplainFindingsResponse,
    summary="Translate raw scan findings into clear, plain-English seller guidance",
)
def explain_findings(
    version_id: str,
    request: Optional[ExplainFindingsRequest] = None,
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Translates raw scan findings into plain English, grouped by severity,
    re-stating engine remediation hints without adding new claims.
    Seller-only, owner-only.
    """
    version = db.query(ListingVersion).filter(ListingVersion.id == version_id).first()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Listing version '{version_id}' not found",
        )

    listing = db.query(Listing).filter(Listing.id == version.listing_id).first()
    if not listing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parent listing for version '{version_id}' not found",
        )

    if listing.seller_id != auth_ctx.user_id and not auth_ctx.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access scan explanations for this version",
        )

    forced_summary = request.forced_summary_for_test if request else None

    try:
        explanation = generate_findings_explanation(
            version=version,
            listing=listing,
            forced_summary_for_test=forced_summary,
        )
        return explanation
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
