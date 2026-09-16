"""
Transactional Email Service for softXchange Auth Service.
Integrates with Resend for delivering password reset and email verification emails.
Enforces zero token leakage: raw tokens are never logged or returned in responses.
Supports test/sandbox isolation for fast, deterministic unit and CI tests.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import resend

from src.config import settings

logger = logging.getLogger("auth-service.email_service")

# Alerting hook integration with fallback
try:
    from packages.observability.alerts import alert_email_delivery_failure
except ImportError:
    try:
        workspace_root = Path(__file__).resolve().parent.parent.parent.parent
        if str(workspace_root) not in sys.path:
            sys.path.insert(0, str(workspace_root))
        from packages.observability.alerts import alert_email_delivery_failure
    except Exception:
        def alert_email_delivery_failure(recipient_email: str, email_type: str, error: str, provider: str = "resend"):
            logger.critical(
                f"OPERATIONAL ALERT [WARNING] Transactional Email Delivery Failed ({email_type}) "
                f"for recipient {recipient_email}: {error}"
            )

# In-memory sandbox inbox for test-mode verification (CI / test environments)
_test_inbox: List[Dict[str, Any]] = []


def get_test_inbox() -> List[Dict[str, Any]]:
    """Return in-memory sent email records during test runs."""
    return list(_test_inbox)


def clear_test_inbox() -> None:
    """Clear in-memory test inbox."""
    _test_inbox.clear()


# ============================================================================
# Email Templates (Luxury Obsidian Palette & SoftXchange Branding)
# ============================================================================

def _build_password_reset_email(recipient_email: str, reset_url: str, expire_minutes: int) -> Dict[str, str]:
    """Generates branded HTML and plain-text email for password reset."""
    subject = "Reset your softXchange password"
    
    text_content = (
        f"softXchange Account Security\n\n"
        f"We received a request to reset your softXchange account password.\n\n"
        f"To choose a new password, click the link below or paste it into your browser:\n"
        f"{reset_url}\n\n"
        f"This password reset link will expire in {expire_minutes} minutes.\n\n"
        f"If you did not request this password reset, you can safely ignore this email. "
        f"Your account and password will remain unchanged.\n\n"
        f"— The softXchange Team\n"
        f"https://softxchange.com"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset your softXchange password</title>
</head>
<body style="margin: 0; padding: 0; background-color: #030408; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #030408; width: 100%; margin: 0; padding: 40px 16px;">
    <tr>
      <td align="center">
        <!-- Main Card Container -->
        <table role="presentation" width="100%" max-width="580px" cellspacing="0" cellpadding="0" border="0" style="max-width: 580px; width: 100%; background: #0c0f1e; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.6);">
          <!-- Header Bar -->
          <tr>
            <td style="padding: 32px 40px 20px 40px; border-bottom: 1px solid rgba(255, 255, 255, 0.06);">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td>
                    <span style="font-size: 20px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff;">
                      soft<span style="color: #38bdf8;">X</span>change
                    </span>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; font-size: 11px; font-family: monospace; color: #38bdf8; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); padding: 4px 10px; border-radius: 9999px;">
                      Institutional Gateway
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Content Body -->
          <tr>
            <td style="padding: 36px 40px 28px 40px;">
              <h1 style="margin: 0 0 16px 0; font-size: 24px; font-weight: 700; color: #ffffff; letter-spacing: -0.3px;">
                Password Reset Request
              </h1>
              <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.6; color: #94a3b8;">
                We received a request to reset the password for your softXchange account (<strong style="color: #e2e8f0;">{recipient_email}</strong>). Click the button below to choose a new password.
              </p>

              <!-- Action Button -->
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 32px 0;">
                <tr>
                  <td align="center" style="border-radius: 10px; background: linear-gradient(135deg, #2563eb 0%, #7c3aed 50%, #c084fc 100%);">
                    <a href="{reset_url}" target="_blank" style="display: inline-block; padding: 14px 28px; font-size: 14px; font-weight: 600; color: #ffffff; text-decoration: none; border-radius: 10px; letter-spacing: 0.2px;">
                      Reset Password &rarr;
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Security Notice & Expiry -->
              <div style="background: rgba(0, 0, 0, 0.35); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 10px; padding: 16px 20px; margin: 28px 0 20px 0;">
                <p style="margin: 0 0 8px 0; font-size: 12px; color: #38bdf8; font-family: monospace;">
                  &bull; This link expires in <strong>{expire_minutes} minutes</strong>.
                </p>
                <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
                  If you didn't request a password reset, you can safely ignore this email. Your password will not change until you access the link above and create a new one.
                </p>
              </div>

              <!-- Fallback Direct URL -->
              <p style="margin: 20px 0 0 0; font-size: 11px; color: #64748b; line-height: 1.5; word-break: break-all;">
                If the button above does not work, copy and paste this link into your browser:<br>
                <a href="{reset_url}" style="color: #38bdf8; text-decoration: none;">{reset_url}</a>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background: rgba(0, 0, 0, 0.45); border-top: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
              <p style="margin: 0; font-size: 11px; color: #64748b; font-family: monospace;">
                &copy; softXchange Verified Software Asset Marketplace. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return {
        "subject": subject,
        "text": text_content,
        "html": html_content,
    }


def _build_email_verification_email(recipient_email: str, verify_url: str, expire_hours: int) -> Dict[str, str]:
    """Generates branded HTML and plain-text email for account email verification."""
    subject = "Verify your softXchange email address"
    
    text_content = (
        f"softXchange Email Verification\n\n"
        f"Thank you for registering with softXchange.\n\n"
        f"To complete your registration and activate your account, please verify your email address:\n"
        f"{verify_url}\n\n"
        f"This verification link will expire in {expire_hours} hours.\n\n"
        f"If you did not register for a softXchange account, you can safely ignore this email.\n\n"
        f"— The softXchange Team\n"
        f"https://softxchange.com"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your softXchange email address</title>
</head>
<body style="margin: 0; padding: 0; background-color: #030408; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #030408; width: 100%; margin: 0; padding: 40px 16px;">
    <tr>
      <td align="center">
        <!-- Main Card Container -->
        <table role="presentation" width="100%" max-width="580px" cellspacing="0" cellpadding="0" border="0" style="max-width: 580px; width: 100%; background: #0c0f1e; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.6);">
          <!-- Header Bar -->
          <tr>
            <td style="padding: 32px 40px 20px 40px; border-bottom: 1px solid rgba(255, 255, 255, 0.06);">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td>
                    <span style="font-size: 20px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff;">
                      soft<span style="color: #38bdf8;">X</span>change
                    </span>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; font-size: 11px; font-family: monospace; color: #10b981; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 10px; border-radius: 9999px;">
                      Verification Gateway
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Content Body -->
          <tr>
            <td style="padding: 36px 40px 28px 40px;">
              <h1 style="margin: 0 0 16px 0; font-size: 24px; font-weight: 700; color: #ffffff; letter-spacing: -0.3px;">
                Verify Your Email Address
              </h1>
              <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.6; color: #94a3b8;">
                Welcome to softXchange. Please verify that <strong style="color: #e2e8f0;">{recipient_email}</strong> is your email address to enable access to marketplace features.
              </p>

              <!-- Action Button -->
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 32px 0;">
                <tr>
                  <td align="center" style="border-radius: 10px; background: linear-gradient(135deg, #10b981 0%, #2563eb 100%);">
                    <a href="{verify_url}" target="_blank" style="display: inline-block; padding: 14px 28px; font-size: 14px; font-weight: 600; color: #ffffff; text-decoration: none; border-radius: 10px; letter-spacing: 0.2px;">
                      Verify Email Address &rarr;
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Notice & Expiry -->
              <div style="background: rgba(0, 0, 0, 0.35); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 10px; padding: 16px 20px; margin: 28px 0 20px 0;">
                <p style="margin: 0 0 8px 0; font-size: 12px; color: #10b981; font-family: monospace;">
                  &bull; This link expires in <strong>{expire_hours} hours</strong>.
                </p>
                <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
                  If you did not sign up for softXchange, no action is needed and you can ignore this email.
                </p>
              </div>

              <!-- Fallback Direct URL -->
              <p style="margin: 20px 0 0 0; font-size: 11px; color: #64748b; line-height: 1.5; word-break: break-all;">
                If the button above does not work, copy and paste this link into your browser:<br>
                <a href="{verify_url}" style="color: #38bdf8; text-decoration: none;">{verify_url}</a>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background: rgba(0, 0, 0, 0.45); border-top: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
              <p style="margin: 0; font-size: 11px; color: #64748b; font-family: monospace;">
                &copy; softXchange Verified Software Asset Marketplace. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return {
        "subject": subject,
        "text": text_content,
        "html": html_content,
    }


# ============================================================================
# Outbound Dispatch Engine
# ============================================================================

def _dispatch_email(
    recipient_email: str,
    subject: str,
    text_content: str,
    html_content: str,
    email_type: str,
) -> bool:
    """
    Internal dispatcher for sending transactional emails.
    - If in test mode (CI or settings.EMAIL_TEST_MODE), records to _test_inbox.
    - Otherwise, dispatches via Resend API.
    - Enforces zero raw token logging.
    - Catches provider/network failures and triggers operational alerts without crashing.
    """
    # Guardrail: Fail-closed if someone erroneously attempts test mode in production
    if settings.ENVIRONMENT.lower() == "production" and settings.EMAIL_TEST_MODE:
        alert_email_delivery_failure(
            recipient_email=recipient_email,
            email_type=email_type,
            error="EMAIL_TEST_MODE attempted in production environment.",
            provider="resend",
        )
        raise RuntimeError("FATAL: EMAIL_TEST_MODE is strictly forbidden in production.")

    # 1. Test Mode / Sandbox Execution (for CI & Unit Tests)
    if settings.EMAIL_TEST_MODE:
        _test_inbox.append({
            "recipient": recipient_email,
            "subject": subject,
            "text": text_content,
            "html": html_content,
            "email_type": email_type,
        })
        logger.info(f"Transactional email ({email_type}) recorded in test inbox for {recipient_email}")
        return True

    # 2. Production / Real Provider Execution (Resend)
    api_key = settings.EMAIL_PROVIDER_API_KEY
    if not api_key:
        err_msg = "EMAIL_PROVIDER_API_KEY is not configured."
        logger.error(f"Cannot dispatch email ({email_type}) to {recipient_email}: {err_msg}")
        alert_email_delivery_failure(
            recipient_email=recipient_email,
            email_type=email_type,
            error=err_msg,
            provider="resend",
        )
        return False

    try:
        resend.api_key = api_key
        sender_header = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM_ADDRESS}>"
        
        params = {
            "from": sender_header,
            "to": [recipient_email],
            "subject": subject,
            "text": text_content,
            "html": html_content,
        }
        
        # Dispatch via Resend API
        resend.Emails.send(params)
        logger.info(f"Successfully dispatched {email_type} email to {recipient_email} via Resend")
        return True

    except Exception as exc:
        err_str = f"Resend API dispatch failed: {exc}"
        # NEVER log the raw token or email body contents here
        logger.error(f"Failed to deliver {email_type} email to {recipient_email}: {err_str}")
        alert_email_delivery_failure(
            recipient_email=recipient_email,
            email_type=email_type,
            error=str(exc),
            provider="resend",
        )
        return False


# ============================================================================
# Public Service API
# ============================================================================

def send_password_reset_email(recipient_email: str, raw_token: str) -> bool:
    """
    Sends password reset email containing link to reset-password.html.
    Raw token is ONLY contained within the email link itself, never logged.
    """
    base_url = settings.FRONTEND_URL.rstrip("/")
    reset_url = f"{base_url}/reset-password.html?token={raw_token}"
    expire_minutes = settings.PASSWORD_RESET_EXPIRE_MINUTES

    built = _build_password_reset_email(
        recipient_email=recipient_email,
        reset_url=reset_url,
        expire_minutes=expire_minutes,
    )

    return _dispatch_email(
        recipient_email=recipient_email,
        subject=built["subject"],
        text_content=built["text"],
        html_content=built["html"],
        email_type="password_reset",
    )


def send_email_verification_email(recipient_email: str, raw_token: str) -> bool:
    """
    Sends email verification email containing verification link.
    Raw token is ONLY contained within the email link itself, never logged.
    """
    base_url = settings.FRONTEND_URL.rstrip("/")
    verify_url = f"{base_url}/auth/verify-email/confirm?token={raw_token}"
    expire_hours = settings.EMAIL_VERIFY_EXPIRE_HOURS

    built = _build_email_verification_email(
        recipient_email=recipient_email,
        verify_url=verify_url,
        expire_hours=expire_hours,
    )

    return _dispatch_email(
        recipient_email=recipient_email,
        subject=built["subject"],
        text_content=built["text"],
        html_content=built["html"],
        email_type="email_verification",
    )
