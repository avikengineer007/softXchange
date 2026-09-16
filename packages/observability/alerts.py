"""
packages/observability/alerts.py

Lightweight alerting handlers for production incidents:
1. Stripe Webhook Failures (signature fraud or processing crashes)
2. Scan Job Failures / Dead Jobs / Timeouts
3. Admin Provisioning Abuse (multiple consecutive failed elevation attempts)
"""

import json
import logging
import os
import time
from typing import Optional, Dict, Any

logger = logging.getLogger("softxchange.alerts")

ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL")  # Slack / Discord / PagerDuty webhook


def trigger_alert(alert_type: str, severity: str, title: str, details: Dict[str, Any]):
    """
    Emits an operational alert to structured logs and webhook if configured.
    Severity: 'CRITICAL', 'WARNING', 'INFO'
    """
    alert_payload = {
        "timestamp": time.time(),
        "alert_type": alert_type,
        "severity": severity,
        "title": title,
        "details": details,
    }

    # Always log alert prominently
    log_msg = f"OPERATIONAL ALERT [{severity}] {alert_type}: {title} | {json.dumps(details)}"
    if severity == "CRITICAL":
        logger.critical(log_msg)
    elif severity == "WARNING":
        logger.warning(log_msg)
    else:
        logger.info(log_msg)

    # If external webhook configured, dispatch notification asynchronously
    if ALERT_WEBHOOK_URL:
        try:
            import httpx
            with httpx.Client(timeout=3.0) as client:
                client.post(ALERT_WEBHOOK_URL, json=alert_payload)
        except Exception as exc:
            logger.error(f"Failed to deliver alert to webhook: {exc}")


def alert_payment_webhook_failure(reason: str, event_id: Optional[str] = None, correlation_id: Optional[str] = None):
    """Triggers an alert when a Stripe payment webhook fails signature or crashes."""
    trigger_alert(
        alert_type="PAYMENT_WEBHOOK_FAILURE",
        severity="CRITICAL",
        title="Stripe Payment Webhook Rejected or Failed",
        details={
            "reason": reason,
            "event_id": event_id,
            "correlation_id": correlation_id,
        },
    )


def alert_scan_job_failure(job_id: str, listing_id: str, error: str, attempts: int):
    """Triggers an alert when a background security scan job crashes or times out repeatedly."""
    trigger_alert(
        alert_type="SCAN_JOB_FAILURE",
        severity="WARNING" if attempts < 2 else "CRITICAL",
        title=f"Security Scan Job {'Failed' if attempts < 2 else 'DEAD'}: {job_id}",
        details={
            "job_id": job_id,
            "listing_id": listing_id,
            "error": error,
            "attempts": attempts,
        },
    )


def alert_admin_provisioning_abuse(user_id: str, source_ip: Optional[str], failed_attempts: int):
    """Triggers an alert when repeated failed admin provisioning attempts occur."""
    trigger_alert(
        alert_type="ADMIN_PROVISION_SUSPICIOUS_ACTIVITY",
        severity="CRITICAL",
        title=f"Repeated Admin Elevation Failures Detected ({failed_attempts} attempts)",
        details={
            "target_user_id": user_id,
            "source_ip": source_ip,
            "consecutive_failures": failed_attempts,
        },
    )


def alert_email_delivery_failure(recipient_email: str, email_type: str, error: str, provider: str = "resend"):
    """Triggers an alert when outbound transactional email delivery fails (network/provider outage)."""
    trigger_alert(
        alert_type="EMAIL_DELIVERY_FAILURE",
        severity="WARNING",
        title=f"Transactional Email Delivery Failed: {email_type}",
        details={
            "recipient": recipient_email,
            "email_type": email_type,
            "error": str(error),
            "provider": provider,
        },
    )
