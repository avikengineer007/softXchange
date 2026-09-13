"""
apps/auth-service/src/routes/github.py

Seller GitHub OAuth connection routes providing a complementary public developer trust signal.

CRITICAL ARCHITECTURAL INVARIANTS:
1. Connecting GitHub is explicitly OPTIONAL and ADDITIVE.
2. Connecting GitHub does NOT set payout_enabled or modify kyc_status in any way.
   payout_enabled continues to depend solely on KYCProvider / Stripe Connect verification.
3. Minimal OAuth Scopes: strictly 'read:user public_repo' (read-only, public data).
   Never request 'repo' (private repos), admin scopes, or write permissions.
4. Ephemeral Token Discipline: access token is used strictly in-memory during the callback
   exchange to fetch public profile data, then immediately discarded. No long-lived token
   is stored in the database, cache, or logs.
5. Disconnecting deletes stored connection data with zero side-effects on KYC, listings, or payouts.
"""

import hmac
import hashlib
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
import httpx
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db
from src.models.user import (
    SellerGitHubConnection,
    SellerGitHubConnectionResponse,
    SellerGitHubStatusResponse,
    SellerPublicTrustBadge,
    SellerProfile,
    KYCStatus,
    utc_now,
    ensure_utc,
)
from src.models.notification import Notification, NotificationType
from src.security import require_seller, AuthContext

router = APIRouter(prefix="/auth/seller/github", tags=["Seller GitHub Trust Signal"])
logger = logging.getLogger("auth-service.github")

# Strictly minimal, read-only public scopes
ALLOWED_SCOPES = "read:user public_repo"
STATE_TTL_SECONDS = 900  # 15 minutes


def _generate_oauth_state(user_id: str) -> str:
    """Generates an HMAC-signed CSRF state token containing user_id and expiration timestamp."""
    exp = int(time.time()) + STATE_TTL_SECONDS
    msg = f"{user_id}:{exp}".encode("utf-8")
    sig = hmac.new(settings.INTERNAL_SERVICE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"{user_id}:{exp}:{sig}"


def _verify_oauth_state(state: str) -> str:
    """Verifies HMAC signature and expiration on state token, returning user_id."""
    parts = state.split(":")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state parameter format",
        )
    user_id, exp_str, sig = parts
    try:
        exp = int(exp_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state expiration timestamp",
        )

    if time.time() > exp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state parameter has expired. Please initiate connection again.",
        )

    msg = f"{user_id}:{exp_str}".encode("utf-8")
    expected_sig = hmac.new(settings.INTERNAL_SERVICE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state signature verification failed (CSRF check failed)",
        )
    return user_id


def _compute_account_age_years(created_at: datetime) -> float:
    now = utc_now()
    delta_days = (now - ensure_utc(created_at)).days
    return max(0.0, round(delta_days / 365.25, 1))


class GitHubCallbackRequest(BaseModel):
    code: str = Field(..., description="Authorization code returned by GitHub")
    state: Optional[str] = Field(None, description="CSRF state parameter")
    mock_profile: Optional[dict] = Field(None, description="Optional mock profile for isolated test environments")


@router.get(
    "/authorize",
    summary="Initiate GitHub OAuth connection for seller trust signal",
)
def get_github_authorize_url(
    auth_ctx: AuthContext = Depends(require_seller),
):
    """
    Returns GitHub OAuth authorization URL with minimal read-only scopes (read:user public_repo).
    """
    state = _generate_oauth_state(auth_ctx.user_id)
    params = {
        "client_id": settings.GITHUB_CLIENT_ID or "dev-github-client-id",
        "scope": ALLOWED_SCOPES,
        "state": state,
        "redirect_uri": settings.GITHUB_OAUTH_REDIRECT_URI,
    }
    authorize_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    return {
        "client_id": settings.GITHUB_CLIENT_ID,
        "scope": ALLOWED_SCOPES,
        "state": state,
        "authorize_url": authorize_url,
    }


def _process_github_connection(
    user_id: str,
    code: str,
    mock_profile: Optional[dict],
    db: Session,
) -> SellerGitHubConnection:
    """
    Exchanges code for access token, fetches public user data, stores in database,
    and immediately discards token (zero persistence).
    Guarantees ZERO modification of seller KYC status or payout_enabled.
    """
    profile_data = None

    if mock_profile:
        # Use provided test profile directly
        profile_data = mock_profile
    elif code.startswith("mock_code_"):
        # Built-in synthetic test mock
        username = code.replace("mock_code_", "")
        profile_data = {
            "login": username,
            "id": 12345678,
            "created_at": "2021-01-15T12:00:00Z",
            "public_repos": 14,
        }
    else:
        # Real GitHub OAuth exchange
        token_url = "https://github.com/login/oauth/access_token"
        user_url = "https://api.github.com/user"

        try:
            with httpx.Client(timeout=8.0) as client:
                token_resp = client.post(
                    token_url,
                    data={
                        "client_id": settings.GITHUB_CLIENT_ID,
                        "client_secret": settings.GITHUB_CLIENT_SECRET,
                        "code": code,
                    },
                    headers={"Accept": "application/json"},
                )
                if token_resp.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Failed to exchange authorization code with GitHub",
                    )
                token_data = token_resp.json()
                access_token = token_data.get("access_token")
                if not access_token:
                    err_desc = token_data.get("error_description", token_data.get("error", "Unknown GitHub error"))
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"GitHub OAuth error: {err_desc}",
                    )

                # Fetch user profile using ephemeral token
                user_resp = client.get(
                    user_url,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                        "User-Agent": "softXchange-Platform",
                    },
                )
                # Discard access_token immediately (ephemeral in-memory only)
                access_token = None

                if user_resp.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Failed to fetch GitHub profile with OAuth token",
                    )
                profile_data = user_resp.json()

        except httpx.RequestError as exc:
            logger.error(f"GitHub OAuth request failed: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"GitHub API unreachable: {str(exc)}",
            )

    username_raw = profile_data.get("login")
    gh_user_id_raw = profile_data.get("id")
    created_at_raw = profile_data.get("created_at")
    public_repos = int(profile_data.get("public_repos", 0))

    if not username_raw or gh_user_id_raw is None or not created_at_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incomplete profile data received from GitHub",
        )

    username: str = str(username_raw)
    gh_user_id: str = str(gh_user_id_raw)
    created_at_str: str = str(created_at_raw)

    try:
        gh_created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
    except Exception:
        gh_created_at = utc_now()

    # Upsert connection record
    conn = db.query(SellerGitHubConnection).filter(SellerGitHubConnection.user_id == user_id).first()
    if conn:
        conn.github_username = username
        conn.github_user_id = gh_user_id
        conn.account_created_at = gh_created_at
        conn.public_repo_count = public_repos
        conn.connected_at = utc_now()
    else:
        conn = SellerGitHubConnection(
            user_id=user_id,
            github_username=username,
            github_user_id=gh_user_id,
            account_created_at=gh_created_at,
            public_repo_count=public_repos,
            connected_at=utc_now(),
        )
        db.add(conn)

    # STRICT GUARANTEE: Do NOT touch seller_profile.payout_enabled or kyc_status!
    # KYC status and payout readiness remain governed exclusively by KYCProvider / Stripe.
    notification = Notification(
        user_id=user_id,
        type=NotificationType.GITHUB_CONNECTED.value,
        payload={"github_username": username, "public_repo_count": public_repos},
    )
    db.add(notification)
    db.commit()
    db.refresh(conn)
    return conn


@router.post(
    "/callback",
    response_model=SellerGitHubConnectionResponse,
    summary="Process GitHub OAuth code exchange and store trust connection",
)
def handle_github_callback_post(
    payload: GitHubCallbackRequest,
    auth_ctx: Optional[AuthContext] = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Exchanges code for profile data and saves GitHub connection for the seller.
    Strictly decoupled from KYC / payout readiness.
    """
    user_id = None
    if auth_ctx:
        user_id = auth_ctx.user_id
    elif payload.state:
        user_id = _verify_oauth_state(payload.state)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Seller authentication or verified OAuth state parameter required",
        )

    conn = _process_github_connection(
        user_id=user_id,
        code=payload.code,
        mock_profile=payload.mock_profile,
        db=db,
    )

    age_years = _compute_account_age_years(conn.account_created_at)
    return SellerGitHubConnectionResponse(
        user_id=conn.user_id,
        github_username=conn.github_username,
        github_user_id=conn.github_user_id,
        account_created_at=conn.account_created_at,
        public_repo_count=conn.public_repo_count,
        connected_at=conn.connected_at,
        account_age_years=age_years,
    )


@router.get(
    "/callback",
    summary="Browser redirect callback handler for GitHub OAuth flow",
)
def handle_github_callback_get(
    code: str = Query(..., description="Authorization code from GitHub"),
    state: str = Query(..., description="CSRF state token"),
    db: Session = Depends(get_db),
):
    """
    Browser redirect endpoint returning to seller dashboard.
    """
    user_id = _verify_oauth_state(state)
    _process_github_connection(
        user_id=user_id,
        code=code,
        mock_profile=None,
        db=db,
    )
    redirect_target = f"{settings.GITHUB_OAUTH_REDIRECT_URI}?github=connected"
    return RedirectResponse(url=redirect_target, status_code=status.HTTP_302_FOUND)


@router.get(
    "/status",
    response_model=SellerGitHubStatusResponse,
    summary="Check current GitHub trust connection status for authenticated seller",
)
def get_github_connection_status(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Returns connection status and details if seller has linked GitHub.
    """
    conn = db.query(SellerGitHubConnection).filter(SellerGitHubConnection.user_id == auth_ctx.user_id).first()
    if not conn:
        return SellerGitHubStatusResponse(user_id=auth_ctx.user_id, is_connected=False, connection=None)

    age_years = _compute_account_age_years(conn.account_created_at)
    conn_resp = SellerGitHubConnectionResponse(
        user_id=conn.user_id,
        github_username=conn.github_username,
        github_user_id=conn.github_user_id,
        account_created_at=conn.account_created_at,
        public_repo_count=conn.public_repo_count,
        connected_at=conn.connected_at,
        account_age_years=age_years,
    )
    return SellerGitHubStatusResponse(user_id=auth_ctx.user_id, is_connected=True, connection=conn_resp)


@router.post(
    "/disconnect",
    summary="Disconnect seller GitHub account and remove trust badge data",
)
@router.delete(
    "/disconnect",
    summary="Disconnect seller GitHub account (DELETE alias)",
)
def disconnect_github_account(
    auth_ctx: AuthContext = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """
    Deletes the seller's GitHub connection data.
    ZERO side-effects: leaves listings, KYC status, and payout status completely untouched.
    """
    conn = db.query(SellerGitHubConnection).filter(SellerGitHubConnection.user_id == auth_ctx.user_id).first()
    if conn:
        db.delete(conn)
        notification = Notification(
            user_id=auth_ctx.user_id,
            type=NotificationType.GITHUB_DISCONNECTED.value,
            payload={},
        )
        db.add(notification)
        db.commit()

    return {
        "message": "GitHub account disconnected successfully.",
        "user_id": auth_ctx.user_id,
        "is_connected": False,
    }


@router.get(
    "/seller/{seller_id}/public-trust",
    response_model=SellerPublicTrustBadge,
    summary="Public endpoint exposing distinct seller trust signals (KYC vs GitHub)",
)
def get_seller_public_trust(
    seller_id: str,
    db: Session = Depends(get_db),
):
    """
    Public trust readout for marketplace listings.
    Clearly distinguishes:
    - kyc_verified & payout_enabled: Stripe / KYCProvider identity clearance
    - github_connected & github: complementary developer public repository trust signal
    """
    profile = db.query(SellerProfile).filter(SellerProfile.user_id == seller_id).first()
    kyc_verified = bool(profile and profile.kyc_status == KYCStatus.VERIFIED.value)
    payout_enabled = bool(profile and profile.payout_enabled is True)

    conn = db.query(SellerGitHubConnection).filter(SellerGitHubConnection.user_id == seller_id).first()
    github_resp = None
    if conn:
        age_years = _compute_account_age_years(conn.account_created_at)
        github_resp = SellerGitHubConnectionResponse(
            user_id=conn.user_id,
            github_username=conn.github_username,
            github_user_id=conn.github_user_id,
            account_created_at=conn.account_created_at,
            public_repo_count=conn.public_repo_count,
            connected_at=conn.connected_at,
            account_age_years=age_years,
        )

    return SellerPublicTrustBadge(
        seller_id=seller_id,
        kyc_verified=kyc_verified,
        payout_enabled=payout_enabled,
        github_connected=conn is not None,
        github=github_resp,
    )


seller_trust_router = APIRouter(prefix="/auth/seller", tags=["Seller Public Trust"])


@seller_trust_router.get(
    "/{seller_id}/public-trust",
    response_model=SellerPublicTrustBadge,
    summary="Public endpoint exposing distinct seller trust signals (KYC vs GitHub) at canonical URL",
)
def get_seller_public_trust_canonical(
    seller_id: str,
    db: Session = Depends(get_db),
):
    """Canonical path alias: GET /auth/seller/{seller_id}/public-trust"""
    return get_seller_public_trust(seller_id=seller_id, db=db)

