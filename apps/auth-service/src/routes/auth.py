from datetime import datetime, timedelta, timezone
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db
from src.email_service import send_password_reset_email, send_email_verification_email
from src.models.user import (
    User,
    UserRole,
    KYCStatus,
    RefreshToken,
    SellerProfile,
    VerificationToken,
    UserSignup,
    UserLogin,
    UserResponse,
    TokenResponse,
    RefreshRequest,
    SignupSuccessResponse,
    MessageResponse,
    EmailVerifyRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    utc_now,
    ensure_utc,
)
from src.security import (
    hash_password,
    verify_password,
    verify_dummy_password,
    create_access_token,
    generate_secure_token,
    hash_token,
    get_jwks,
    get_public_key_pem,
    require_auth,
    AuthContext,
)
from src.rate_limiter import login_rate_limiter

logger = logging.getLogger("auth-service.routes.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str:
    """Extract client IP handling reverse proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _set_refresh_cookie(response: Response, raw_refresh_token: str) -> None:
    """
    Set httpOnly cookie for refresh token.
    Flags: httpOnly=True, secure=COOKIE_SECURE (True in prod), SameSite=lax, path=/auth.
    """
    max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    response.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        max_age=max_age,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path=settings.COOKIE_PATH,
    )


# ============================================================================
# Core Signup & Login Endpoints (Prompt 1)
# ============================================================================

@router.post(
    "/signup",
    response_model=SignupSuccessResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account with role(s)",
)
def signup(
    data: UserSignup,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Accepts email, password, and roles.
    Creates user with email_verified=False.
    Does not issue session on signup alone because email verification is required.
    Dispatches verification email asynchronously.
    """
    normalized_email = data.email.strip().lower()

    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists",
        )

    # Determine assigned roles (defaults to ["customer"])
    assigned_roles: List[str]
    if data.roles:
        assigned_roles = list(dict.fromkeys(data.roles))
    elif data.role:
        assigned_roles = [data.role.strip().lower()]
    else:
        assigned_roles = [UserRole.CUSTOMER.value]

    try:
        new_user = User(
            email=normalized_email,
            password_hash=hash_password(data.password),
            roles=assigned_roles,
            email_verified=False,
            display_name=data.display_name,
            is_active=True,
        )
        db.add(new_user)
        db.flush()

        # If user registered as seller, create initial seller profile
        if UserRole.SELLER.value in assigned_roles:
            seller_profile = SellerProfile(
                user_id=new_user.id,
                kyc_status=KYCStatus.NOT_STARTED.value,
                payout_enabled=False,
                kyc_metadata={},
            )
            db.add(seller_profile)

        # Create verification token record
        raw_verify_token = generate_secure_token()
        token_record = VerificationToken(
            token_hash=hash_token(raw_verify_token),
            user_id=new_user.id,
            purpose="email_verify",
            expires_at=utc_now() + timedelta(hours=settings.EMAIL_VERIFY_EXPIRE_HOURS),
        )
        db.add(token_record)

        db.commit()
        db.refresh(new_user)

        # Asynchronously dispatch email verification via Resend
        background_tasks.add_task(send_email_verification_email, normalized_email, raw_verify_token)

    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to create user during signup: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating your account. Please try again.",
        )

    dev_token = raw_verify_token if settings.ENVIRONMENT != "production" else None

    return SignupSuccessResponse(
        message="Registration successful. Please verify your email address to activate full account access.",
        user_id=new_user.id,
        email=new_user.email,
        email_verified=False,
        verification_token=dev_token,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate with email and password",
)
def login(
    data: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticates user, issues RS256 access token and server-side refresh token.
    Protected by per-IP and per-email rate limiting and constant-time timing defense.
    Fail-closed on any database or unexpected errors.
    """
    client_ip = _get_client_ip(request)
    normalized_email = data.email.strip().lower()

    # 1. Rate Limiting Check
    if login_rate_limiter.is_rate_limited(client_ip, normalized_email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )

    # 2. Database Lookup & Timing-defended Verification
    try:
        user = db.query(User).filter(User.email == normalized_email).first()
    except Exception as exc:
        logger.error(f"Database error during login query: {exc}", exc_info=True)
        # Fail closed on unexpected errors: return generic error, never stack trace
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service temporarily unavailable. Please try again.",
        )

    if not user:
        # Timing attack defense: perform dummy bcrypt check
        verify_dummy_password(data.password)
        login_rate_limiter.record_failure(client_ip, normalized_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(data.password, user.password_hash):
        login_rate_limiter.record_failure(client_ip, normalized_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated",
        )

    # Authentication succeeded: reset rate limit tracking
    login_rate_limiter.record_success(client_ip, normalized_email)

    try:
        # 3. Issue Short-Lived Access Token (RS256)
        access_token = create_access_token(user_id=user.id, roles=user.roles)

        # 4. Issue and Persist Server-Side Refresh Token
        raw_refresh_token = generate_secure_token()
        refresh_record = RefreshToken(
            token_hash=hash_token(raw_refresh_token),
            user_id=user.id,
            expires_at=utc_now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        db.add(refresh_record)
        db.commit()

        # 5. Set httpOnly Cookie
        _set_refresh_cookie(response, raw_refresh_token)

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )

    except Exception as exc:
        db.rollback()
        logger.error(f"Error issuing tokens during login: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initialize session. Please try again.",
        )


# ============================================================================
# Session / Token Issuance & Refresh (Prompt 2)
# ============================================================================

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange valid refresh token for a new access token",
)
def refresh_access_token(
    request: Request,
    response: Response,
    data: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Validates server-side non-revoked refresh token and issues fresh access token.
    Supports refresh token from request body or httpOnly cookie.

    CSRF defence-in-depth: with SameSite=None cookies required for cross-origin
    Cloudflare Pages → Railway requests, we explicitly validate the Origin header
    against the CORS allowlist. CORS middleware already blocks attacker sites from
    reading the response, but this check rejects the request entirely at the handler.
    Skipped when no Origin is present (server-to-server, curl, Postman).
    """
    origin = request.headers.get("origin")
    if origin and origin not in settings.CORS_ORIGINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origin not permitted",
        )

    raw_token = None
    if data and data.refresh_token:
        raw_token = data.refresh_token.strip()
    if not raw_token:
        raw_token = request.cookies.get("refresh_token")

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


    token_h = hash_token(raw_token)
    refresh_record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_h).first()

    if not refresh_record or refresh_record.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if ensure_utc(refresh_record.expires_at) < utc_now():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == refresh_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Issue new access token
    new_access_token = create_access_token(user_id=user.id, roles=user.roles)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=raw_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke refresh token and terminate session",
)
def logout(
    request: Request,
    response: Response,
    data: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Revokes the refresh token (sets revoked_at) and clears the cookie.
    """
    raw_token = None
    if data and data.refresh_token:
        raw_token = data.refresh_token.strip()
    if not raw_token:
        raw_token = request.cookies.get("refresh_token")

    if raw_token:
        token_h = hash_token(raw_token)
        refresh_record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_h).first()
        if refresh_record and refresh_record.revoked_at is None:
            refresh_record.revoked_at = utc_now()
            db.commit()

    # Clear cookie
    response.delete_cookie(
        key="refresh_token",
        path=settings.COOKIE_PATH,
    )

    return MessageResponse(message="Successfully logged out")


# ============================================================================
# Public Key Distribution Endpoints (RS256 Downstream Discovery)
# ============================================================================

@router.get(
    "/.well-known/jwks.json",
    summary="JWKS endpoint for downstream token verification",
)
def get_jwks_keys():
    """Exposes JSON Web Key Set for listings-service and payments-service."""
    return get_jwks()


@router.get(
    "/public-key.pem",
    response_class=PlainTextResponse,
    summary="Public key in PEM format for downstream services",
)
def get_public_key():
    """Returns PEM-encoded public key for services requiring raw key files."""
    return get_public_key_pem()


# ============================================================================
# Email Verification & Password Reset (Prompt 4)
# ============================================================================

@router.post(
    "/verify-email/request",
    response_model=MessageResponse,
    summary="Request email verification link",
)
def request_email_verification(
    data: EmailVerifyRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Returns identical generic success response whether email exists or not
    to prevent user enumeration.
    Dispatches verification email asynchronously via Resend.
    Raw token is never logged or returned in responses.
    """
    normalized_email = data.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if user and not user.email_verified:
        raw_token = generate_secure_token()
        token_record = VerificationToken(
            token_hash=hash_token(raw_token),
            user_id=user.id,
            purpose="email_verify",
            expires_at=utc_now() + timedelta(hours=settings.EMAIL_VERIFY_EXPIRE_HOURS),
        )
        db.add(token_record)
        db.commit()
        # Asynchronously dispatch email without blocking client response
        background_tasks.add_task(send_email_verification_email, normalized_email, raw_token)
    else:
        # Constant-time dummy operation to prevent timing attacks
        verify_dummy_password("dummy-prevent-timing-leak")

    return MessageResponse(
        message="If this email is registered, a verification link has been sent to it."
    )


@router.get(
    "/verify-email/confirm",
    response_model=MessageResponse,
    summary="Confirm email address using verification token",
)
def confirm_email_verification(
    token: str,
    db: Session = Depends(get_db),
):
    """
    Single-use verification token confirmation.
    Fails closed with generic error if token is already used or expired.
    """
    token_h = hash_token(token.strip())
    record = (
        db.query(VerificationToken)
        .filter(VerificationToken.token_hash == token_h, VerificationToken.purpose == "email_verify")
        .first()
    )

    if not record or record.used_at is not None or ensure_utc(record.expires_at) < utc_now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    record.used_at = utc_now()
    user = db.query(User).filter(User.id == record.user_id).first()
    if user:
        user.email_verified = True
        user.updated_at = utc_now()
        db.commit()

    return MessageResponse(message="Email address successfully verified.")


@router.post(
    "/password-reset/request",
    response_model=MessageResponse,
    summary="Request password reset token",
)
def request_password_reset(
    data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Returns identical generic success response whether email exists or not
    to prevent user enumeration.
    Dispatches password reset email asynchronously via Resend.
    Raw token is never logged or returned in responses.
    """
    normalized_email = data.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if user and user.is_active:
        raw_token = generate_secure_token()
        token_record = VerificationToken(
            token_hash=hash_token(raw_token),
            user_id=user.id,
            purpose="password_reset",
            expires_at=utc_now() + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        )
        db.add(token_record)
        db.commit()
        # Asynchronously dispatch email without blocking client response
        background_tasks.add_task(send_password_reset_email, normalized_email, raw_token)
    else:
        # Constant-time dummy operation to balance execution latency
        verify_dummy_password("dummy-prevent-timing-leak")

    return MessageResponse(
        message="If this email is registered, password reset instructions have been sent."
    )


@router.post(
    "/password-reset/confirm",
    response_model=MessageResponse,
    summary="Confirm password reset and revoke all existing sessions",
)
def confirm_password_reset(
    data: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    """
    Validates token, updates password hash, marks token used, and
    REVOKES ALL EXISTING REFRESH TOKENS for that user.
    """
    token_h = hash_token(data.token.strip())
    record = (
        db.query(VerificationToken)
        .filter(VerificationToken.token_hash == token_h, VerificationToken.purpose == "password_reset")
        .first()
    )

    if not record or record.used_at is not None or ensure_utc(record.expires_at) < utc_now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    # 1. Update user password
    user.password_hash = hash_password(data.new_password)
    user.updated_at = utc_now()

    # 2. Mark verification token consumed
    record.used_at = utc_now()

    # 3. REVOKE ALL EXISTING REFRESH TOKENS FOR THIS USER
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at.is_(None)
    ).update({"revoked_at": utc_now()})

    db.commit()

    return MessageResponse(
        message="Password has been successfully updated. All active sessions have been revoked."
    )


# ============================================================================
# Authenticated User Profile
# ============================================================================

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get profile of current authenticated user",
)
def get_me(
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Retrieve profile of authenticated caller."""
    user = db.query(User).filter(User.id == auth_ctx.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive",
        )
    return UserResponse.model_validate(user)


# ============================================================================
# Backward-Compatible Endpoints for Existing Callers
# ============================================================================

@router.post("/customer/signup", response_model=SignupSuccessResponse, status_code=status.HTTP_201_CREATED)
def legacy_customer_signup(
    data: UserSignup,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    data.roles = [UserRole.CUSTOMER.value]
    return signup(data, background_tasks=background_tasks, db=db)


@router.post("/seller/signup", response_model=SignupSuccessResponse, status_code=status.HTTP_201_CREATED)
def legacy_seller_signup(
    data: UserSignup,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    data.roles = [UserRole.SELLER.value]
    return signup(data, background_tasks=background_tasks, db=db)


@router.post("/customer/login", response_model=TokenResponse)
def legacy_customer_login(data: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    return login(data, request=request, response=response, db=db)


@router.post("/seller/login", response_model=TokenResponse)
def legacy_seller_login(data: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    return login(data, request=request, response=response, db=db)
