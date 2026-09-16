import sys
import uuid
import re
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch, MagicMock

# Ensure apps/auth-service is on sys.path
SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))
if "src" in sys.modules and not getattr(sys.modules["src"], "__file__", "").startswith(str(SERVICE_ROOT)):
    sys.modules.pop("src", None)
    for k in list(sys.modules.keys()):
        if k.startswith("src."):
            sys.modules.pop(k, None)

from src.main import app
from src.config import settings
from src.database import Base, get_db
from src.models.user import User, RefreshToken, VerificationToken, utc_now
from src.security import hash_password, create_access_token
from src.email_service import (
    get_test_inbox,
    clear_test_inbox,
    send_password_reset_email,
    send_email_verification_email,
)
from src.rate_limiter import login_rate_limiter

# In-memory SQLite database
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup clean database and test inbox for every test."""
    app.dependency_overrides[get_db] = override_get_db
    settings.EMAIL_TEST_MODE = True
    settings.FRONTEND_URL = "http://localhost:8000"
    login_rate_limiter.reset_all()
    clear_test_inbox()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    clear_test_inbox()
    settings.EMAIL_TEST_MODE = False
    app.dependency_overrides.pop(get_db, None)


def _create_user(email: str = "realuser@softxchange.com", password: str = "SecurePass123!", verified: bool = True) -> User:
    db = TestingSessionLocal()
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        password_hash=hash_password(password),
        roles=["customer"],
        email_verified=verified,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


# ============================================================================
# 1. Delivery & Content Verification (Password Reset & Email Verification)
# ============================================================================

def test_password_reset_email_delivery_and_content():
    """
    POST /auth/password-reset/request dispatches a branded email with token link.
    Token TTL is dynamically rendered, SoftXchange branding is present.
    """
    user = _create_user(email="reset.tester@softxchange.com")
    
    resp = client.post("/auth/password-reset/request", json={"email": "reset.tester@softxchange.com"})
    assert resp.status_code == 200
    assert resp.json()["message"] == "If this email is registered, password reset instructions have been sent."

    # Check test inbox
    inbox = get_test_inbox()
    assert len(inbox) == 1
    sent = inbox[0]
    assert sent["recipient"] == "reset.tester@softxchange.com"
    assert sent["email_type"] == "password_reset"
    assert "Reset your softXchange password" in sent["subject"]

    # Verify link formatting in both HTML and plain text
    assert "reset-password.html?token=" in sent["text"]
    assert "reset-password.html?token=" in sent["html"]
    assert f"{settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes" in sent["text"]
    assert f"{settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes" in sent["html"]
    assert "safely ignore this email" in sent["text"]
    assert "Institutional Gateway" in sent["html"]


def test_email_verification_delivery_and_content():
    """
    POST /auth/verify-email/request dispatches a branded verification email.
    """
    user = _create_user(email="unverified@softxchange.com", verified=False)
    
    resp = client.post("/auth/verify-email/request", json={"email": "unverified@softxchange.com"})
    assert resp.status_code == 200
    assert resp.json()["message"] == "If this email is registered, a verification link has been sent to it."

    inbox = get_test_inbox()
    assert len(inbox) == 1
    sent = inbox[0]
    assert sent["recipient"] == "unverified@softxchange.com"
    assert sent["email_type"] == "email_verification"
    assert "Verify your softXchange email address" in sent["subject"]
    assert "verify-email/confirm?token=" in sent["text"]
    assert f"{settings.EMAIL_VERIFY_EXPIRE_HOURS} hours" in sent["text"]


# ============================================================================
# 2. Zero Token Leakage Hardening
# ============================================================================

def test_zero_token_leakage_in_api_response_and_logs(caplog):
    """
    The raw token must NEVER appear in the API response or application logs.
    """
    import logging
    caplog.set_level(logging.INFO)
    user = _create_user(email="leaktest@softxchange.com")

    resp = client.post("/auth/password-reset/request", json={"email": "leaktest@softxchange.com"})
    assert resp.status_code == 200
    response_body = resp.text

    inbox = get_test_inbox()
    assert len(inbox) == 1
    # Extract raw token from the delivered email
    match = re.search(r"reset-password\.html\?token=([a-zA-Z0-9_-]+)", inbox[0]["text"])
    assert match is not None
    raw_token = match.group(1)
    assert len(raw_token) >= 20

    # 1. Raw token must NOT appear anywhere in the API response
    assert raw_token not in response_body

    # 2. Raw token must NOT appear anywhere in the logs
    for record in caplog.records:
        assert raw_token not in record.message


# ============================================================================
# 3. Enumeration Safety (Timing & Response Shape Equivalence)
# ============================================================================

def test_enumeration_safety_password_reset():
    """
    Whether account exists or not:
    - Same status code (200)
    - Identical response JSON
    - Non-existent account does NOT send an email
    """
    _create_user(email="exists@softxchange.com")

    resp_exists = client.post("/auth/password-reset/request", json={"email": "exists@softxchange.com"})
    resp_fake = client.post("/auth/password-reset/request", json={"email": "doesnotexist@softxchange.com"})

    assert resp_exists.status_code == 200
    assert resp_fake.status_code == 200
    assert resp_exists.json() == resp_fake.json()

    # Only existent account receives email
    inbox = get_test_inbox()
    assert len(inbox) == 1
    assert inbox[0]["recipient"] == "exists@softxchange.com"


def test_enumeration_safety_email_verification():
    """
    Verify-email request provides identical response whether email exists or not.
    """
    _create_user(email="exists.verify@softxchange.com", verified=False)

    resp_exists = client.post("/auth/verify-email/request", json={"email": "exists.verify@softxchange.com"})
    resp_fake = client.post("/auth/verify-email/request", json={"email": "ghost@softxchange.com"})

    assert resp_exists.status_code == 200
    assert resp_fake.status_code == 200
    assert resp_exists.json() == resp_fake.json()


# ============================================================================
# 4. Provider Failure Resilience & Operational Alerting
# ============================================================================

def test_provider_outage_fails_safe_with_alert():
    """
    If Resend API throws an error (network failure / outage),
    the endpoint still returns generic 200 success to the user (anti-enumeration),
    while an operational alert is dispatched.
    """
    _create_user(email="outage.user@softxchange.com")
    settings.EMAIL_TEST_MODE = False
    settings.EMAIL_PROVIDER_API_KEY = "re_mock_test_key_12345"

    with patch("resend.Emails.send", side_effect=Exception("Connection timeout to api.resend.com")):
        with patch("src.email_service.alert_email_delivery_failure") as mock_alert:
            resp = client.post("/auth/password-reset/request", json={"email": "outage.user@softxchange.com"})
            
            # User receives generic success response without provider leak
            assert resp.status_code == 200
            assert resp.json()["message"] == "If this email is registered, password reset instructions have been sent."

            # Operational alert was triggered
            mock_alert.assert_called_once()
            call_kwargs = mock_alert.call_args.kwargs
            assert call_kwargs["recipient_email"] == "outage.user@softxchange.com"
            assert call_kwargs["email_type"] == "password_reset"
            assert "Connection timeout" in call_kwargs["error"]


# ============================================================================
# 5. Production Guardrail: Test Mode Lockout
# ============================================================================

def test_production_environment_locks_out_email_test_mode(monkeypatch):
    """
    In production, EMAIL_TEST_MODE must fail closed and never activate.
    """
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "EMAIL_TEST_MODE", True)

    with pytest.raises(RuntimeError) as exc_info:
        send_password_reset_email("user@softxchange.com", "dummy-raw-token")
    assert "strictly forbidden in production" in str(exc_info.value)


# ============================================================================
# 6. End-to-End Password Reset Loop with Delivered Email Token
# ============================================================================

def test_end_to_end_password_reset_flow():
    """
    Complete flow:
    1. User signs up and logs in (receives access and refresh tokens).
    2. User requests password reset.
    3. Token is retrieved from delivered email.
    4. POST /auth/password-reset/confirm updates password.
    5. Old password and old refresh tokens are rejected.
    6. New password successfully logs in.
    """
    # 1. Signup and login
    signup_resp = client.post(
        "/auth/signup",
        json={"email": "e2e.reset@softxchange.com", "password": "OriginalPassword123!"},
    )
    assert signup_resp.status_code == 201

    # Manually verify user so login succeeds
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "e2e.reset@softxchange.com").first()
    user.email_verified = True
    db.commit()
    db.close()

    # Log in to acquire active refresh tokens
    login1 = client.post(
        "/auth/login",
        json={"email": "e2e.reset@softxchange.com", "password": "OriginalPassword123!"},
    )
    assert login1.status_code == 200
    old_refresh_token = login1.json()["refresh_token"]

    # 2. Request password reset
    clear_test_inbox()
    req_resp = client.post(
        "/auth/password-reset/request",
        json={"email": "e2e.reset@softxchange.com"},
    )
    assert req_resp.status_code == 200

    # 3. Extract token from delivered email
    inbox = get_test_inbox()
    assert len(inbox) == 1
    match = re.search(r"reset-password\.html\?token=([a-zA-Z0-9_-]+)", inbox[0]["text"])
    assert match is not None
    received_token = match.group(1)

    # 4. Confirm password reset
    confirm_resp = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": received_token,
            "new_password": "NewBrandSecurePassword2026!",
        },
    )
    assert confirm_resp.status_code == 200
    assert "successfully updated" in confirm_resp.json()["message"]

    # 5. Old password must fail
    old_login = client.post(
        "/auth/login",
        json={"email": "e2e.reset@softxchange.com", "password": "OriginalPassword123!"},
    )
    assert old_login.status_code == 401

    # Old refresh token must be revoked
    old_refresh = client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh_token},
    )
    assert old_refresh.status_code == 401

    # 6. New password must succeed
    new_login = client.post(
        "/auth/login",
        json={"email": "e2e.reset@softxchange.com", "password": "NewBrandSecurePassword2026!"},
    )
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()
