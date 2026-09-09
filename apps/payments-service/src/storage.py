from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import base64
from typing import Optional, Dict, Any

from src.config import settings


def generate_signed_download_url(
    order_id: str,
    buyer_id: str,
    listing_version_id: str,
    storage_location: str,
    ttl_seconds: Optional[int] = None,
) -> str:
    """
    Generates a cryptographically signed, short-lived download URL.
    Enforces ephemeral access (default 15 minutes) for the exact immutable version purchased.
    """
    ttl = ttl_seconds or settings.DOWNLOAD_LINK_TTL_SECONDS
    now = datetime.now(timezone.utc)
    expires_at = int((now + timedelta(seconds=ttl)).timestamp())

    payload = {
        "order_id": order_id,
        "buyer_id": buyer_id,
        "version_id": listing_version_id,
        "loc": storage_location,
        "exp": expires_at,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    sig = hmac.new(
        settings.DOWNLOAD_SIGNING_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    token = f"{payload_b64}.{sig}"
    return f"/orders/download/package?token={token}"


def verify_download_token(token: str) -> Dict[str, Any]:
    """
    Validates a download token's HMAC signature and expiration timestamp.
    Returns decoded token payload if valid, or raises ValueError.
    """
    try:
        parts = token.split(".")
        if len(parts) != 2:
            raise ValueError("Malformed download token format")

        payload_b64, signature = parts
        expected_sig = hmac.new(
            settings.DOWNLOAD_SIGNING_SECRET.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid download token signature")

        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)

        now = int(datetime.now(timezone.utc).timestamp())
        if now > payload.get("exp", 0):
            raise ValueError("Download token has expired")

        return payload
    except Exception as exc:
        raise ValueError(f"Download authorization failed: {str(exc)}")
