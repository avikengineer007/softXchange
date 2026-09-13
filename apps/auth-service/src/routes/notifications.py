import hmac
import logging
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db
from src.models.user import User, utc_now
from src.models.notification import (
    Notification,
    ALL_NOTIFICATION_TYPES,
    NotificationEmitRequest,
    NotificationResponse,
    NotificationListResponse,
    UnreadCountResponse,
)
from src.security import require_auth, AuthContext

logger = logging.getLogger("auth-service.routes.notifications")

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.post(
    "/emit",
    response_model=NotificationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inter-service notification emission endpoint (Internal secret protected)",
)
def emit_notification_interservice(
    data: NotificationEmitRequest,
    x_internal_secret: Optional[str] = Header(None, alias="X-Internal-Secret"),
    db: Session = Depends(get_db),
):
    """
    Inter-service endpoint to deliver notifications to users from downstream services.
    Requires and strictly validates X-Internal-Secret against settings.INTERNAL_SERVICE_SECRET.
    Rejects unauthenticated callers with 401.
    """
    if not x_internal_secret or not hmac.compare_digest(
        x_internal_secret, settings.INTERNAL_SERVICE_SECRET
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal service secret",
        )

    if data.type not in ALL_NOTIFICATION_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid notification type '{data.type}'. Must be one of {sorted(ALL_NOTIFICATION_TYPES)}",
        )

    # Verify recipient user exists (fail closed if invalid user)
    user = db.query(User).filter(User.id == data.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recipient user '{data.user_id}' not found",
        )

    notif = Notification(
        id=str(uuid.uuid4()),
        user_id=data.user_id,
        type=data.type,
        payload=data.payload,
        read_at=None,
        created_at=utc_now(),
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)

    logger.info(f"Emitted notification {notif.id} (type: {notif.type}) to user {notif.user_id}")
    return NotificationResponse.model_validate(notif)


@router.get(
    "",
    response_model=NotificationListResponse,
    summary="Get notifications for authenticated user (Newest first)",
)
def get_user_notifications(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    unread_only: bool = Query(False),
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Lists notifications for the authenticated user, newest first.
    Optionally filters for unread-only.
    """
    base_query = db.query(Notification).filter(Notification.user_id == auth_ctx.user_id)

    unread_count = (
        db.query(Notification)
        .filter(Notification.user_id == auth_ctx.user_id, Notification.read_at.is_(None))
        .count()
    )

    if unread_only:
        query = base_query.filter(Notification.read_at.is_(None))
    else:
        query = base_query

    total = query.count()
    items = query.order_by(Notification.created_at.desc()).offset(offset).limit(limit).all()

    return NotificationListResponse(
        notifications=[NotificationResponse.model_validate(n) for n in items],
        total=total,
        unread_count=unread_count,
    )


@router.get(
    "/unread-count",
    response_model=UnreadCountResponse,
    summary="Get unread notification count for authenticated user",
)
def get_unread_count(
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Returns number of unread notifications for the user."""
    count = (
        db.query(Notification)
        .filter(Notification.user_id == auth_ctx.user_id, Notification.read_at.is_(None))
        .count()
    )
    return UnreadCountResponse(unread_count=count)


@router.post(
    "/{notification_id}/read",
    response_model=NotificationResponse,
    summary="Mark single notification as read",
)
def mark_notification_read(
    notification_id: str,
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Marks a single notification belonging to the authenticated user as read."""
    notif = (
        db.query(Notification)
        .filter(Notification.id == notification_id, Notification.user_id == auth_ctx.user_id)
        .first()
    )
    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )

    if notif.read_at is None:
        notif.read_at = utc_now()
        db.commit()
        db.refresh(notif)

    return NotificationResponse.model_validate(notif)


@router.post(
    "/read-all",
    summary="Mark all notifications as read for authenticated user",
)
def mark_all_notifications_read(
    auth_ctx: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Marks all unread notifications for the authenticated user as read."""
    now = utc_now()
    unread_notifs = (
        db.query(Notification)
        .filter(Notification.user_id == auth_ctx.user_id, Notification.read_at.is_(None))
        .all()
    )
    for n in unread_notifs:
        n.read_at = now
    db.commit()

    return {"updated": len(unread_notifs)}
