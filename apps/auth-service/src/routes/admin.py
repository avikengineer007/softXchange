from datetime import timedelta
import hashlib
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db
from src.models.user import (
    User,
    SellerProfile,
    KYCStatus,
    AdminProvisionAuditLog,
    AdminProvisioningState,
    AdminProvisionRequest,
    AdminProvisionResponse,
    AdminAuditLogItem,
    SellerPendingKYCItem,
    KYCStatusResponse,
    utc_now,
)
from src.security import (
    require_auth,
    require_admin,
    AuthContext,
    verify_password,
    hash_password,
    create_access_token,
)
from src.kyc.service import update_seller_kyc_status

logger = logging.getLogger("auth-service.routes.admin")

router = APIRouter(prefix="/auth/admin", tags=["Admin Operations"])

# Cached bcrypt hash of configured ADMIN_PROVISIONING_CODE
_CACHED_CODE_HASH: Optional[str] = None


def _get_admin_code_hash() -> str:
    global _CACHED_CODE_HASH
    if settings.ADMIN_PROVISIONING_CODE_HASH:
        return settings.ADMIN_PROVISIONING_CODE_HASH
    if _CACHED_CODE_HASH is None:
        raw_code = settings.ADMIN_PROVISIONING_CODE or ""
        _CACHED_CODE_HASH = hash_password(raw_code)
    return _CACHED_CODE_HASH


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class KYCRejectRequest(BaseModel):
    reason: Optional[str] = "Manual administrative rejection"


# ============================================================================
# Prompt 3: Code-Gated Admin Role Provisioning
# ============================================================================

@router.post(
    "/provision",
    response_model=AdminProvisionResponse,
    summary="Code-gated elevation to administrative role",
)
def provision_admin_role(
    data: AdminProvisionRequest,
    request: Request,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Elevates an authenticated user to the 'admin' role.
    
    Security controls:
    - Fail-closed: unauthenticated or invalid code fails immediately
    - Strict rate limiting: max 3 failed attempts per hour per user/IP (locks with 429)
    - Constant-time bcrypt comparison via verify_password()
    - Persistent security audit logging of every attempt
    - Single-use invalidation: once used, the code cannot be reused until rotated
    """
    client_ip = _get_client_ip(request)
    now = utc_now()
    window_start = now - timedelta(hours=settings.ADMIN_PROVISION_WINDOW_HOURS)

    # 1. Rate Limiting Check (max 3 failed attempts in window)
    failed_attempts = (
        db.query(AdminProvisionAuditLog)
        .filter(
            (AdminProvisionAuditLog.user_id == auth_ctx.user_id) | (AdminProvisionAuditLog.source_ip == client_ip),
            AdminProvisionAuditLog.timestamp >= window_start,
            AdminProvisionAuditLog.success == False,
        )
        .count()
    )

    if failed_attempts >= settings.ADMIN_PROVISION_MAX_ATTEMPTS:
        # Log rate limit lock-out
        audit = AdminProvisionAuditLog(
            user_id=auth_ctx.user_id,
            timestamp=now,
            success=False,
            source_ip=client_ip,
            failure_reason="rate_limit_exceeded",
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {settings.ADMIN_PROVISION_MAX_ATTEMPTS} failed attempts per hour allowed.",
        )

    # 2. Check Single-Use Consumption State
    code_fingerprint = hashlib.sha256((settings.ADMIN_PROVISIONING_CODE or "").encode("utf-8")).hexdigest()
    state = db.query(AdminProvisioningState).filter(AdminProvisioningState.code_hash == code_fingerprint).first()
    if state and state.is_used:
        audit = AdminProvisionAuditLog(
            user_id=auth_ctx.user_id,
            timestamp=now,
            success=False,
            source_ip=client_ip,
            failure_reason="code_already_consumed",
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin provisioning code has already been used and invalidated.",
        )

    # 3. Bcrypt Verification
    expected_hash = _get_admin_code_hash()
    is_valid = verify_password(data.code.strip(), expected_hash)

    if not is_valid:
        audit = AdminProvisionAuditLog(
            user_id=auth_ctx.user_id,
            timestamp=now,
            success=False,
            source_ip=client_ip,
            failure_reason="invalid_code",
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrative provisioning code.",
        )

    # 4. Invalidate Code (Single-Use)
    if not state:
        state = AdminProvisioningState(
            code_hash=code_fingerprint,
            is_used=True,
            used_by=auth_ctx.user_id,
            used_at=now,
        )
        db.add(state)
    else:
        state.is_used = True
        state.used_by = auth_ctx.user_id
        state.used_at = now

    # 5. Elevate User Role
    user = db.query(User).filter(User.id == auth_ctx.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    from sqlalchemy.orm.attributes import flag_modified
    current_roles = list(user.roles or [])
    if "admin" not in current_roles:
        current_roles.append("admin")
        user.roles = current_roles
        flag_modified(user, "roles")

    # 6. Audit Successful Elevation
    audit = AdminProvisionAuditLog(
        user_id=auth_ctx.user_id,
        timestamp=now,
        success=True,
        source_ip=client_ip,
        failure_reason=None,
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    # 7. Issue Fresh Access Token with Updated Admin Role
    new_token = create_access_token(
        user_id=user.id,
        roles=user.roles,
    )

    logger.info(f"User {user.id} successfully provisioned as admin by IP {client_ip}")


    return AdminProvisionResponse(
        message="Admin role provisioned successfully",
        user_id=user.id,
        roles=user.roles,
        access_token=new_token,
        token_type="bearer",
    )


@router.get(
    "/audit-log",
    response_model=List[AdminAuditLogItem],
    summary="Retrieve administrative audit log",
)
def get_admin_audit_log(
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns recent administrative provisioning audit logs.
    Restricted to callers with the admin role.
    """
    logs = (
        db.query(AdminProvisionAuditLog)
        .order_by(AdminProvisionAuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return [AdminAuditLogItem.model_validate(log) for log in logs]


# ============================================================================
# Prompt 4: KYC Review Queue (Single Source of Truth)
# ============================================================================

@router.get(
    "/kyc/pending",
    response_model=List[SellerPendingKYCItem],
    summary="List seller accounts awaiting KYC verification",
)
def list_pending_kyc_sellers(
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns all seller profiles currently in 'pending' status for operator review.
    """
    results = (
        db.query(SellerProfile, User)
        .join(User, User.id == SellerProfile.user_id)
        .filter(SellerProfile.kyc_status == KYCStatus.PENDING.value)
        .order_by(SellerProfile.updated_at.desc())
        .all()
    )

    items = []
    for profile, user in results:
        items.append(
            SellerPendingKYCItem(
                user_id=profile.user_id,
                email=user.email,
                display_name=user.display_name,
                kyc_status=profile.kyc_status,
                created_at=profile.created_at,
                details=profile.kyc_metadata,
            )
        )
    return items


@router.post(
    "/kyc/{user_id}/verify",
    response_model=KYCStatusResponse,
    summary="Manually verify seller KYC (Routes through canonical state machine)",
)
def verify_seller_kyc_admin(
    user_id: str,
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Manually verifies a seller account.
    
    IMPORTANT: Routes strictly through update_seller_kyc_status(), preserving
    the exact same is_seller_payout_enabled / kyc_status state machine as the
    automated Razorpay Route webhook flow. Zero dual-source-of-truth drift.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Seller user not found")

    profile = update_seller_kyc_status(
        user_id=user_id,
        target_status=KYCStatus.VERIFIED.value,
        db=db,
        details={
            "source": "admin_manual_review",
            "admin_id": auth_ctx.user_id,
            "action": "verified",
        },
    )

    logger.info(f"Admin {auth_ctx.user_id} verified KYC for seller {user_id}")
    return KYCStatusResponse(
        user_id=profile.user_id,
        kyc_status=profile.kyc_status,
        payout_enabled=profile.payout_enabled,
        details=profile.kyc_metadata,
    )


@router.post(
    "/kyc/{user_id}/reject",
    response_model=KYCStatusResponse,
    summary="Manually reject seller KYC (Routes through canonical state machine)",
)
def reject_seller_kyc_admin(
    user_id: str,
    body: Optional[KYCRejectRequest] = None,
    auth_ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Manually rejects a seller account.
    
    IMPORTANT: Routes strictly through update_seller_kyc_status(), preserving
    the exact same is_seller_payout_enabled / kyc_status state machine as the
    automated Razorpay Route webhook flow. Zero dual-source-of-truth drift.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Seller user not found")

    reason = body.reason if body and body.reason else "Administrative manual rejection"

    profile = update_seller_kyc_status(
        user_id=user_id,
        target_status=KYCStatus.REJECTED.value,
        db=db,
        details={
            "source": "admin_manual_review",
            "admin_id": auth_ctx.user_id,
            "action": "rejected",
            "reason": reason,
        },
    )

    logger.info(f"Admin {auth_ctx.user_id} rejected KYC for seller {user_id}: {reason}")
    return KYCStatusResponse(
        user_id=profile.user_id,
        kyc_status=profile.kyc_status,
        payout_enabled=profile.payout_enabled,
        details=profile.kyc_metadata,
    )
