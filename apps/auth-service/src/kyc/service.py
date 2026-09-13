import logging
import uuid
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from src.database import SessionLocal
from src.models.user import User, UserRole, KYCStatus, SellerProfile, utc_now
from src.models.notification import Notification, NotificationType
from src.kyc.provider import get_kyc_provider, KYCProvider

logger = logging.getLogger("auth-service.kyc.service")


def is_seller_payout_enabled(user_id: str, db: Optional[Session] = None) -> bool:
    """
    Clean, exportable gate check for downstream services (listings-service, payments-service).
    
    FAIL-CLOSED ENFORCEMENT:
    A seller cannot publish paid listings or receive payout disbursements unless
    identity verification has fully cleared. Returns True ONLY IF kyc_status == "verified"
    and payout_enabled is True.
    """
    should_close_db = False
    if db is None:
        db = SessionLocal()
        should_close_db = True

    try:
        profile = db.query(SellerProfile).filter(SellerProfile.user_id == user_id).first()
        if not profile:
            return False

        # Fail closed: strictly verified and payout_enabled True
        return profile.kyc_status == KYCStatus.VERIFIED.value and profile.payout_enabled is True
    except Exception as exc:
        logger.error(f"Error checking seller payout gate for {user_id}: {exc}", exc_info=True)
        return False
    finally:
        if should_close_db:
            db.close()


def get_or_create_seller_profile(user_id: str, db: Session) -> SellerProfile:
    """Retrieve seller profile or initialize one with 'not_started' status."""
    profile = db.query(SellerProfile).filter(SellerProfile.user_id == user_id).first()
    if not profile:
        profile = SellerProfile(
            user_id=user_id,
            kyc_status=KYCStatus.NOT_STARTED.value,
            payout_enabled=False,
            kyc_metadata={},
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
    return profile


def start_seller_kyc(
    user_id: str,
    db: Session,
    provider: Optional[KYCProvider] = None,
) -> Dict[str, Any]:
    """
    Transitions kyc_status to 'pending' and calls KYCProvider.start_onboarding.
    Fail-closed: if provider fails, status remains pending and payout_enabled remains False.
    """
    if provider is None:
        provider = get_kyc_provider()

    profile = get_or_create_seller_profile(user_id, db)

    # Transition to pending
    profile.kyc_status = KYCStatus.PENDING.value
    profile.payout_enabled = False
    profile.updated_at = utc_now()
    db.commit()

    try:
        onboarding_res = provider.start_onboarding(user_id)
        meta = dict(profile.kyc_metadata or {})
        meta["onboarding"] = onboarding_res
        profile.kyc_metadata = meta
        db.commit()
        db.refresh(profile)
        return onboarding_res
    except Exception as exc:
        logger.error(f"KYC provider failed during start_onboarding for {user_id}: {exc}", exc_info=True)
        # Fail closed: remain pending and payout_enabled=False
        return {
            "status": "pending",
            "error": "Failed to connect to identity provider. Status remains pending.",
        }


def update_seller_kyc_status(
    user_id: str,
    target_status: str,
    db: Session,
    details: Optional[Dict[str, Any]] = None,
) -> SellerProfile:
    """
    Updates KYC status based on provider response or webhook.
    
    FAIL-CLOSED GUARANTEE:
    Only target_status == "verified" sets payout_enabled=True.
    Any unexpected status or error leaves payout_enabled=False.
    """
    profile = get_or_create_seller_profile(user_id, db)
    meta = dict(profile.kyc_metadata or {})
    meta["last_update"] = {
        "status": target_status,
        "details": details or {},
        "timestamp": utc_now().isoformat(),
    }
    profile.kyc_metadata = meta
    profile.updated_at = utc_now()

    if target_status == KYCStatus.VERIFIED.value:
        profile.kyc_status = KYCStatus.VERIFIED.value
        profile.payout_enabled = True
        notif = Notification(
            id=str(uuid.uuid4()),
            user_id=user_id,
            type=NotificationType.KYC_VERIFIED.value,
            payload={"message": "Identity verification approved. Payouts enabled.", "status": "verified"},
            created_at=utc_now(),
        )
        db.add(notif)
    elif target_status == KYCStatus.REJECTED.value:
        profile.kyc_status = KYCStatus.REJECTED.value
        profile.payout_enabled = False
        notif = Notification(
            id=str(uuid.uuid4()),
            user_id=user_id,
            type=NotificationType.KYC_REJECTED.value,
            payload={"message": "Identity verification was rejected. Please review submission guidelines.", "status": "rejected"},
            created_at=utc_now(),
        )
        db.add(notif)
    else:
        # Any unexpected value or error fails closed
        profile.kyc_status = KYCStatus.PENDING.value
        profile.payout_enabled = False

    db.commit()
    db.refresh(profile)
    return profile


def check_and_sync_kyc_status(
    user_id: str,
    db: Session,
    provider: Optional[KYCProvider] = None,
) -> SellerProfile:
    """
    Query provider for status and synchronize local seller_profile.
    Fail-closed: if provider fails, leaves kyc_status as pending and payout_enabled as False.
    """
    if provider is None:
        provider = get_kyc_provider()

    try:
        status_res = provider.check_status(user_id)
        return update_seller_kyc_status(user_id, status_res, db)
    except Exception as exc:
        logger.error(f"Error querying provider status for {user_id}: {exc}", exc_info=True)
        # Fail closed: ensure payout_enabled is not True
        profile = get_or_create_seller_profile(user_id, db)
        profile.kyc_status = KYCStatus.PENDING.value
        profile.payout_enabled = False
        db.commit()
        db.refresh(profile)
        return profile
