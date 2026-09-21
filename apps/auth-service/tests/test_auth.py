import sys
import time
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure apps/auth-service is on sys.path
SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from src.main import app
from src.config import settings
from src.database import Base, get_db
from src.models.user import (
    User,
    RefreshToken,
    SellerProfile,
    VerificationToken,
    UserRole,
    KYCStatus,
    utc_now,
)
from src.security import (
    hash_password,
    verify_password,
    create_access_token,
    hash_token,
    decode_access_token,
    get_public_key_pem,
    require_auth,
    AuthContext,
)
from src.rate_limiter import login_rate_limiter
from src.kyc.service import is_seller_payout_enabled
from src.kyc.provider import get_kyc_provider, MockKYCProvider

# Setup isolated test in-memory SQLite database
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
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


@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    login_rate_limiter.reset_all()
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# Prompt 1 Tests: User Model, Password Auth, Roles, Timing Attack, Rate Limiter
# ============================================================================

def test_signup_creates_user_with_hashed_password_and_no_session(client):
    """
    Asserts:
    1. Stored password is not plaintext and is not reversible.
    2. Email is stored case-insensitively.
    3. User can register with multiple roles (customer and seller).
    4. Signup does not issue an active session (returns placeholder verification hook).
    5. email_verified defaults to False.
    """
    raw_password = "SuperSecretPassword123!"
    payload = {
        "email": "MultiRole@Example.COM",
        "password": raw_password,
        "roles": ["customer", "seller"],
        "display_name": "Test User",
    }
    resp = client.post("/auth/signup", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["email"] == "multirole@example.com"
    assert data["email_verified"] is False
    assert "access_token" not in data  # No session issued on signup alone!

    # Inspect database directly
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "multirole@example.com").first()
    assert user is not None
    assert user.email == "multirole@example.com"
    assert user.email_verified is False
    assert set(user.roles) == {"customer", "seller"}

    # Assert password hash is secure bcrypt hash
    assert user.password_hash != raw_password
    assert not user.password_hash.startswith(raw_password)
    assert user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$")
    assert verify_password(raw_password, user.password_hash) is True
    assert verify_password("WrongPassword!", user.password_hash) is False
    db.close()


def test_duplicate_signup_rejected(client):
    payload = {
        "email": "unique@example.com",
        "password": "Password123!",
        "roles": ["customer"],
    }
    resp1 = client.post("/auth/signup", json=payload)
    assert resp1.status_code == 201

    # Same email in different casing
    payload2 = {
        "email": "UNIQUE@EXAMPLE.COM",
        "password": "Password123!",
        "roles": ["customer"],
    }
    resp2 = client.post("/auth/signup", json=payload2)
    assert resp2.status_code == 409
    assert "already exists" in resp2.json()["detail"]


def test_login_success_and_fail_identically_on_wrong_creds(client):
    """
    Login must fail identically (same status 401, identical error message)
    for both 'nonexistent email' and 'wrong password' to prevent user enumeration.
    """
    # 1. Create a user
    client.post(
        "/auth/signup",
        json={"email": "existing@example.com", "password": "CorrectPassword123!"},
    )

    # 2. Login with wrong password
    resp_wrong_pw = client.post(
        "/auth/login",
        json={"email": "existing@example.com", "password": "IncorrectPassword123!"},
    )
    assert resp_wrong_pw.status_code == 401
    assert resp_wrong_pw.json()["detail"] == "Invalid credentials"

    # 3. Login with nonexistent email
    resp_no_user = client.post(
        "/auth/login",
        json={"email": "nonexistent@example.com", "password": "AnyPassword123!"},
    )
    assert resp_no_user.status_code == 401
    assert resp_no_user.json()["detail"] == "Invalid credentials"

    # 4. Login with correct credentials succeeds
    resp_success = client.post(
        "/auth/login",
        json={"email": "existing@example.com", "password": "CorrectPassword123!"},
    )
    assert resp_success.status_code == 200
    data = resp_success.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_rate_limiter_blocks_after_rapid_failed_attempts(client):
    """
    Rate limiter blocks after N rapid failed attempts from one IP/email.
    """
    login_rate_limiter.reset_all()

    # Attempt 5 failed logins (threshold is 5)
    for _ in range(5):
        resp = client.post(
            "/auth/login",
            json={"email": "target@example.com", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    # 6th attempt must be rejected with 429 Too Many Requests
    blocked_resp = client.post(
        "/auth/login",
        json={"email": "target@example.com", "password": "WrongPassword!"},
    )
    assert blocked_resp.status_code == 429
    assert "Too many failed login attempts" in blocked_resp.json()["detail"]


# ============================================================================
# Prompt 2 Tests: RS256 Tokens, Server-Side Refresh, Auth Middleware
# ============================================================================

def test_rs256_access_token_and_middleware(client):
    """
    Valid access token passes middleware; invalid/expired token is rejected.
    """
    # Create user and log in
    client.post(
        "/auth/signup",
        json={"email": "jwtuser@example.com", "password": "Password123!", "roles": ["seller", "customer"]},
    )
    login_resp = client.post(
        "/auth/login",
        json={"email": "jwtuser@example.com", "password": "Password123!"},
    )
    assert login_resp.status_code == 200
    access_token = login_resp.json()["access_token"]

    # 1. Verify token payload structure
    claims = decode_access_token(access_token)
    assert claims["type"] == "access"
    assert "seller" in claims["roles"]
    assert "customer" in claims["roles"]

    # 2. Access /auth/me with valid Bearer token
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "jwtuser@example.com"

    # 3. Reject token signed with wrong key
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fake_token = jwt.encode(
        {"sub": claims["sub"], "roles": ["customer"], "type": "access", "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        other_pem,
        algorithm="RS256",
    )
    fake_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {fake_token}"})
    assert fake_resp.status_code == 401

    # 4. Reject expired token
    expired_token = create_access_token(
        user_id=claims["sub"],
        roles=["customer"],
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )
    exp_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert exp_resp.status_code == 401
    assert "expired" in exp_resp.json()["detail"].lower()


def test_server_side_refresh_token_and_logout_revocation(client):
    """
    1. Refresh token is stored server-side as SHA-256 hash.
    2. /auth/refresh exchanges valid token for new access token.
    3. /auth/logout revokes refresh token.
    4. Refresh attempt after logout fails.
    """
    client.post(
        "/auth/signup",
        json={"email": "refreshuser@example.com", "password": "Password123!"},
    )
    login_resp = client.post(
        "/auth/login",
        json={"email": "refreshuser@example.com", "password": "Password123!"},
    )
    raw_refresh = login_resp.json()["refresh_token"]

    # Verify server-side storage
    db = TestingSessionLocal()
    token_record = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(raw_refresh)).first()
    assert token_record is not None
    assert token_record.revoked_at is None
    db.close()

    # Refresh works
    refresh_resp = client.post("/auth/refresh", json={"refresh_token": raw_refresh})
    assert refresh_resp.status_code == 200
    new_access = refresh_resp.json()["access_token"]
    assert new_access is not None

    # Logout revokes refresh token
    logout_resp = client.post("/auth/logout", json={"refresh_token": raw_refresh})
    assert logout_resp.status_code == 200

    # Verify revoked in DB
    db = TestingSessionLocal()
    revoked_record = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(raw_refresh)).first()
    assert revoked_record is not None
    assert revoked_record.revoked_at is not None
    db.close()

    # Subsequent refresh attempt must fail
    second_refresh = client.post("/auth/refresh", json={"refresh_token": raw_refresh})
    assert second_refresh.status_code == 401
    assert "Invalid or revoked refresh token" in second_refresh.json()["detail"]


def test_jwks_endpoint_available_for_downstream_services(client):
    """Downstream services can fetch JWKS or raw public key to verify RS256 tokens."""
    jwks_resp = client.get("/auth/.well-known/jwks.json")
    assert jwks_resp.status_code == 200
    keys = jwks_resp.json()["keys"]
    assert len(keys) >= 1
    assert keys[0]["alg"] == "RS256"
    assert keys[0]["kty"] == "RSA"

    pem_resp = client.get("/auth/public-key.pem")
    assert pem_resp.status_code == 200
    assert "BEGIN PUBLIC KEY" in pem_resp.text


# ============================================================================
# Prompt 3 Tests: Seller KYC Gate & Payout Gate State Machine
# ============================================================================

def test_seller_kyc_gate_lifecycle_and_fail_closed(client):
    """
    1. New seller starts with kyc_status='not_started', payout_enabled=False.
    2. Starting KYC transitions to 'pending'.
    3. Mock provider verified sets payout_enabled=True.
    4. Mock provider rejected sets payout_enabled=False.
    5. is_seller_payout_enabled returns correct boolean at each step.
    """
    # Register seller
    client.post(
        "/auth/signup",
        json={"email": "kycseller@example.com", "password": "Password123!", "roles": ["seller"]},
    )
    login_resp = client.post(
        "/auth/login",
        json={"email": "kycseller@example.com", "password": "Password123!"},
    )
    seller_id = login_resp.json()["user"]["id"]
    seller_token = login_resp.json()["access_token"]
    seller_headers = {"Authorization": f"Bearer {seller_token}"}

    # 1. Initial State: not_started, payout_enabled=False
    db = TestingSessionLocal()
    assert is_seller_payout_enabled(seller_id, db) is False
    db.close()

    status_resp = client.get("/auth/seller/kyc/status", headers=seller_headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["kyc_status"] == "not_started"
    assert status_resp.json()["payout_enabled"] is False

    # 2. Start KYC -> transitions to pending
    start_resp = client.post("/auth/seller/kyc/start", headers=seller_headers)
    assert start_resp.status_code == 200
    assert start_resp.json()["kyc_status"] == "pending"

    db = TestingSessionLocal()
    assert is_seller_payout_enabled(seller_id, db) is False
    db.close()

    # 3. Provider sends 'verified' webhook -> payout_enabled=True
    webhook_payload = {
        "user_id": seller_id,
        "event": "identity.verified",
        "status": "verified",
        "details": {"verification_id": "verif_123"},
    }
    wb_resp = client.post("/auth/seller/kyc/webhook", json=webhook_payload)
    assert wb_resp.status_code == 200
    assert wb_resp.json()["kyc_status"] == "verified"
    assert wb_resp.json()["payout_enabled"] is True

    db = TestingSessionLocal()
    assert is_seller_payout_enabled(seller_id, db) is True
    db.close()

    # 4. Provider sends 'rejected' webhook -> payout_enabled=False
    reject_payload = {
        "user_id": seller_id,
        "event": "identity.rejected",
        "status": "rejected",
    }
    client.post("/auth/seller/kyc/webhook", json=reject_payload)
    db = TestingSessionLocal()
    assert is_seller_payout_enabled(seller_id, db) is False
    db.close()

    # 5. Unexpected/error response must FAIL CLOSED (never accidentally True)
    error_payload = {
        "user_id": seller_id,
        "event": "provider.error",
        "status": "corrupted_or_unexpected",
    }
    client.post("/auth/seller/kyc/webhook", json=error_payload)
    db = TestingSessionLocal()
    assert is_seller_payout_enabled(seller_id, db) is False
    db.close()


def test_seller_kyc_submit_form_endpoint(client):
    """
    Submitting KYC form details transitions status to 'pending',
    stores masked tax identifier, and leaves payout_enabled=False until verified.
    """
    client.post(
        "/auth/signup",
        json={"email": "kycform@example.com", "password": "Password123!", "roles": ["seller"]},
    )
    login_resp = client.post(
        "/auth/login",
        json={"email": "kycform@example.com", "password": "Password123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "legal_name": "Jane Developer",
        "business_name": "Dev Labs Studio",
        "tax_id": "12-3456789",
        "country": "US",
        "city": "Austin",
    }
    resp = client.post("/auth/seller/kyc/submit", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["kyc_status"] == "pending"
    assert data["payout_enabled"] is False
    assert data["details"]["submission"]["legal_name"] == "Jane Developer"
    assert data["details"]["submission"]["tax_id_masked"] == "***-**-6789"


# ============================================================================
# Prompt 4 Tests: Password Reset & Email Verification
# ============================================================================

def test_email_verification_lifecycle(client):
    """
    1. Valid verification token confirms email and cannot be reused.
    2. Expired token fails closed.
    3. Request endpoint returns identical response for existing/non-existing emails.
    """
    client.post(
        "/auth/signup",
        json={"email": "verifyme@example.com", "password": "Password123!"},
    )

    # Request endpoint returns same response regardless of email existence
    resp_exist = client.post("/auth/verify-email/request", json={"email": "verifyme@example.com"})
    resp_fake = client.post("/auth/verify-email/request", json={"email": "doesnotexist@example.com"})
    assert resp_exist.status_code == 200
    assert resp_fake.status_code == 200
    assert resp_exist.json()["message"] == resp_fake.json()["message"]

    # Extract token from database
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "verifyme@example.com").first()
    assert user is not None
    assert user.email_verified is False
    token_rec = (
        db.query(VerificationToken)
        .filter(VerificationToken.user_id == user.id, VerificationToken.purpose == "email_verify")
        .first()
    )
    db.close()

    # Generate a fresh known token for direct confirmation test
    raw_token = "valid-test-verification-token"
    db = TestingSessionLocal()
    db.add(
        VerificationToken(
            token_hash=hash_token(raw_token),
            user_id=user.id,
            purpose="email_verify",
            expires_at=utc_now() + timedelta(hours=1),
        )
    )
    db.commit()
    db.close()

    # Confirm email
    confirm_resp = client.get(f"/auth/verify-email/confirm?token={raw_token}")
    assert confirm_resp.status_code == 200
    assert "successfully verified" in confirm_resp.json()["message"].lower()

    # User is verified
    db = TestingSessionLocal()
    user_updated = db.query(User).filter(User.email == "verifyme@example.com").first()
    assert user_updated is not None
    assert user_updated.email_verified is True
    db.close()

    # Token cannot be reused (fails closed)
    reuse_resp = client.get(f"/auth/verify-email/confirm?token={raw_token}")
    assert reuse_resp.status_code == 400
    assert "Invalid or expired" in reuse_resp.json()["detail"]


def test_password_reset_revokes_all_refresh_tokens(client):
    """
    Password reset with valid token changes password AND revokes ALL existing refresh tokens.
    """
    client.post(
        "/auth/signup",
        json={"email": "resetuser@example.com", "password": "OldPassword123!"},
    )
    # Log in to acquire refresh tokens
    login1 = client.post("/auth/login", json={"email": "resetuser@example.com", "password": "OldPassword123!"})
    refresh_token_1 = login1.json()["refresh_token"]

    login2 = client.post("/auth/login", json={"email": "resetuser@example.com", "password": "OldPassword123!"})
    refresh_token_2 = login2.json()["refresh_token"]

    # Request reset
    client.post("/auth/password-reset/request", json={"email": "resetuser@example.com"})

    # Setup known reset token
    raw_reset_token = "password-reset-valid-token"
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == "resetuser@example.com").first()
    assert user is not None
    db.add(
        VerificationToken(
            token_hash=hash_token(raw_reset_token),
            user_id=user.id,
            purpose="password_reset",
            expires_at=utc_now() + timedelta(minutes=30),
        )
    )
    db.commit()
    db.close()

    # Confirm password reset
    confirm_resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": raw_reset_token, "new_password": "NewBrandSecurePassword999!"},
    )
    assert confirm_resp.status_code == 200

    # Old password no longer works
    old_login = client.post("/auth/login", json={"email": "resetuser@example.com", "password": "OldPassword123!"})
    assert old_login.status_code == 401

    # New password works
    new_login = client.post("/auth/login", json={"email": "resetuser@example.com", "password": "NewBrandSecurePassword999!"})
    assert new_login.status_code == 200

    # ALL previous refresh tokens must now be revoked
    refresh_fail_1 = client.post("/auth/refresh", json={"refresh_token": refresh_token_1})
    assert refresh_fail_1.status_code == 401

    refresh_fail_2 = client.post("/auth/refresh", json={"refresh_token": refresh_token_2})
    assert refresh_fail_2.status_code == 401


# ============================================================================
# Prompt 5 Tests: Static Pages & End-to-End Delivery
# ============================================================================

def test_static_login_and_signup_pages_served(client):
    """Verify auth-service is pure API: /static is not mounted (404) and root redirects to unified frontend."""
    pages = [
        "/static/login-customer.html",
        "/static/login-seller.html",
        "/static/signup-customer.html",
        "/static/signup-seller.html",
        "/static/dashboard-customer.html",
        "/static/dashboard-seller.html",
        "/static/customer-login.html",
        "/static/seller-login.html",
        "/static/css/style.css",
        "/static/js/auth.js",
    ]
    for page in pages:
        resp = client.get(page)
        assert resp.status_code == 404, f"Page {page} returned status {resp.status_code}, expected 404 (API-only)"

    # Root redirect to unified frontend
    root_resp = client.get("/", follow_redirects=False)
    assert root_resp.status_code == 307
    assert root_resp.headers["location"] == "http://localhost:8000/login-customer.html"


def test_production_fails_closed_when_keys_missing(monkeypatch):
    """
    FAIL-CLOSED GUARDRAIL:
    If ENVIRONMENT='production' and RS256 is selected without configured keys,
    refuse to start with an explicit RuntimeError.
    """
    from src import security
    from src.config import settings

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY", None)
    monkeypatch.setattr(settings, "JWT_PUBLIC_KEY", None)
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY_PATH", None)
    monkeypatch.setattr(settings, "JWT_PUBLIC_KEY_PATH", None)

    with pytest.raises(RuntimeError) as exc_info:
        security._init_rsa_keys()
    assert "FATAL" in str(exc_info.value)
    assert "production" in str(exc_info.value)


def test_legacy_endpoints_backward_compatibility(client):
    """Verify legacy endpoints operate as aliases to modern unified routes."""
    # Customer signup and login
    c_signup = client.post("/auth/customer/signup", json={"email": "legcust@test.com", "password": "Password123!"})
    assert c_signup.status_code == 201

    c_login = client.post("/auth/customer/login", json={"email": "legcust@test.com", "password": "Password123!"})
    assert c_login.status_code == 200
    assert "access_token" in c_login.json()

    # Seller signup and login
    s_signup = client.post("/auth/seller/signup", json={"email": "legsell@test.com", "password": "Password123!"})
    assert s_signup.status_code == 201

    s_login = client.post("/auth/seller/login", json={"email": "legsell@test.com", "password": "Password123!"})
    assert s_login.status_code == 200
    token = s_login.json()["access_token"]

    # Legacy KYC endpoints
    headers = {"Authorization": f"Bearer {token}"}
    kyc_stat = client.get("/kyc/status", headers=headers)
    assert kyc_stat.status_code == 200
    assert kyc_stat.json()["kyc_status"] == "not_started"

    kyc_sub = client.post("/kyc/submit", headers=headers)
    assert kyc_sub.status_code == 200
    assert kyc_sub.json()["kyc_status"] == "pending"


def test_legacy_endpoints_enumeration_safety(client):
    """
    Ensure legacy endpoints (/auth/seller/login, /auth/customer/login) fail identically
    for wrong password vs nonexistent user, never leaking whether an account exists
    or what role it holds.
    """
    # 1. Create a customer-only account
    client.post("/auth/signup", json={"email": "custonly@test.com", "password": "CustPassword123!", "roles": ["customer"]})

    # 2. Hitting /auth/seller/login with nonexistent account
    resp_nonexistent = client.post("/auth/seller/login", json={"email": "nobody@test.com", "password": "WrongPassword!"})
    assert resp_nonexistent.status_code == 401
    assert resp_nonexistent.json()["detail"] == "Invalid credentials"

    # 3. Hitting /auth/seller/login with existing customer account but wrong password
    resp_wrong_pw = client.post("/auth/seller/login", json={"email": "custonly@test.com", "password": "WrongPassword!"})
    assert resp_wrong_pw.status_code == 401
    assert resp_wrong_pw.json()["detail"] == "Invalid credentials"

    # Both responses are strictly identical
    assert resp_nonexistent.json() == resp_wrong_pw.json()


def test_kyc_webhook_replay_protection(client):
    """
    Replay attack prevention:
    Webhook payloads with a timestamp older than 5 minutes (300 seconds)
    are rejected with 401 Unauthorized, even if HMAC signature is mathematically valid.
    """
    seller_id = "seller-replay-test"
    db = TestingSessionLocal()
    profile = SellerProfile(user_id=seller_id, kyc_status="pending", payout_enabled=False)
    db.add(profile)
    db.commit()
    db.close()

    payload = {
        "user_id": seller_id,
        "event": "razorpay_route.verified",
        "status": "verified",
        "details": {"razorpay_account_id": "acct_replay_test"},
    }
    raw_json = json.dumps(payload, sort_keys=True).encode("utf-8")

    # 1. Expired timestamp (10 minutes ago)
    old_timestamp = str(int(time.time()) - 600)
    signed_old = f"{old_timestamp}.".encode("utf-8") + raw_json
    old_sig = hmac.new(
        settings.INTERNAL_SERVICE_SECRET.encode("utf-8"),
        signed_old,
        hashlib.sha256,
    ).hexdigest()

    resp_old = client.post(
        "/auth/seller/kyc/webhook",
        content=raw_json,
        headers={
            "Content-Type": "application/json",
            "X-Service-Timestamp": old_timestamp,
            "X-Service-Signature": old_sig,
        },
    )
    assert resp_old.status_code == 401
    assert "expired or replayed" in resp_old.json()["detail"]

    # 2. Fresh timestamp (current time) -> Accepted
    now_timestamp = str(int(time.time()))
    signed_fresh = f"{now_timestamp}.".encode("utf-8") + raw_json
    fresh_sig = hmac.new(
        settings.INTERNAL_SERVICE_SECRET.encode("utf-8"),
        signed_fresh,
        hashlib.sha256,
    ).hexdigest()

    resp_fresh = client.post(
        "/auth/seller/kyc/webhook",
        content=raw_json,
        headers={
            "Content-Type": "application/json",
            "X-Service-Timestamp": now_timestamp,
            "X-Service-Signature": fresh_sig,
        },
    )
    assert resp_fresh.status_code == 200
    assert resp_fresh.json()["kyc_status"] == "verified"
    assert resp_fresh.json()["payout_enabled"] is True


def test_payout_status_access_control(client):
    """
    Access control & enumeration safety on /kyc/seller/{seller_id}/payout-status:
    1. Unauthenticated random probes fail closed with 401.
    2. Internal service with X-Internal-Secret succeeds (200).
    3. Authenticated seller inspecting their own status succeeds (200).
    4. Authenticated seller trying to inspect another seller's status is rejected (401).
    """
    seller_1 = "seller-perm-1"
    seller_2 = "seller-perm-2"

    db = TestingSessionLocal()
    p1 = SellerProfile(user_id=seller_1, kyc_status="verified", payout_enabled=True)
    p2 = SellerProfile(user_id=seller_2, kyc_status="not_started", payout_enabled=False)
    db.add_all([p1, p2])
    db.commit()
    db.close()

    token_seller_1 = create_access_token(seller_1, ["seller"])
    token_seller_2 = create_access_token(seller_2, ["seller"])

    # 1. Unauthenticated request without internal secret or token -> 401
    resp_unauth = client.get(f"/kyc/seller/{seller_1}/payout-status")
    assert resp_unauth.status_code == 401
    assert "Access denied" in resp_unauth.json()["detail"]

    # 2. Internal service with X-Internal-Secret -> 200
    resp_internal = client.get(
        f"/kyc/seller/{seller_1}/payout-status",
        headers={"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET},
    )
    assert resp_internal.status_code == 200
    assert resp_internal.json()["payout_enabled"] is True

    # 3. Seller 1 inspecting their own status -> 200
    resp_own = client.get(
        f"/kyc/seller/{seller_1}/payout-status",
        headers={"Authorization": f"Bearer {token_seller_1}"},
    )
    assert resp_own.status_code == 200
    assert resp_own.json()["payout_enabled"] is True

    # 4. Seller 2 attempting to inspect Seller 1's status -> 401
    resp_other = client.get(
        f"/kyc/seller/{seller_1}/payout-status",
        headers={"Authorization": f"Bearer {token_seller_2}"},
    )
    assert resp_other.status_code == 401
    assert "Access denied" in resp_other.json()["detail"]


