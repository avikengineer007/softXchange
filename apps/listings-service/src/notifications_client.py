import logging
from typing import Dict, Any
import httpx
from src.config import settings

logger = logging.getLogger("listings-service.notifications_client")


def emit_notification(
    user_id: str,
    notification_type: str,
    payload: Dict[str, Any],
) -> bool:
    """
    Emits an event notification to auth-service using X-Internal-Secret.
    Fails open to protect primary transactional flows.
    """
    url = f"{settings.AUTH_SERVICE_URL}/notifications/emit"
    headers = {
        "X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET,
        "Content-Type": "application/json",
    }
    body = {
        "user_id": user_id,
        "type": notification_type,
        "payload": payload,
    }
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(url, json=body, headers=headers)
            if resp.status_code == 201:
                return True
            logger.warning(f"Failed to emit notification: {resp.status_code} {resp.text}")
    except Exception as exc:
        logger.warning(f"Error emitting notification to {url}: {exc}")
    return False
