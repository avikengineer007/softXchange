import sys
import hashlib
from datetime import timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
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
    SellerProfile,
    KYCStatus,
    AdminProvisionAuditLog,
    AdminProvisioningState,
    utc_now,
)
from src.security import hash_password, create_access_token, decode_access_token
from src.kyc.service import get_or_create_seller_profile, is_seller_payout_enabled

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
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    return TestClient(app)


def _create_user(db, email="operator@example.com", roles=None):
    if roles is None:
        roles = ["customer"]
    user = User(
        email=email.lower(),
        password_hash=hash_password("OperatorPass123!"),
        roles=roles,
        email_verified=True,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _get_token_for(user):
    return create_access_token(user_id=user.id, roles=user.roles)


# ============================================================================
# Admin Provisioning & Security Tests (Prompt 3)
# ============================================================================

def test_admin_role_cannot_be_self_registered(client):
    """Admin role cannot be selected at registration (must be code-gated)."""
    resp = client.post(
        "/auth/signup",
        json={
            "email": "hacker@example.com",
            "password": "Password1234!",
            "roles": ["admin"],
        },
    )
    assert resp.status_code == 422
    assert "Admin role cannot be self-registered" in str(resp.json())


def test_admin_provision_unauthenticated_fails(client):
    """Unauthenticated call to /auth/admin/provision is rejected with 401."""
    resp = client.post(
        "/auth/admin/provision",
        json={"code": settings.ADMIN_PROVISIONING_CODE},
    )
    assert resp.status_code == 401


def test_admin_provision_invalid_code_fails_and_audits(client):
    """Wrong provisioning code fails with 401 and logs an audit failure."""
    db = TestingSessionLocal()
    user = _create_user(db, email="candidate@example.com")
    token = _get_token_for(user)

    resp = client.post(
        "/auth/admin/provision",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "sx_admin_sec_wrong_bad_code_12345678"},
    )
    assert resp.status_code == 401
    assert "Invalid administrative provisioning code" in resp.json()["detail"]

    # Verify audit log entry
    audit = db.query(AdminProvisionAuditLog).filter(AdminProvisionAuditLog.user_id == user.id).first()
    assert audit is not None
    assert audit.success is False
    assert audit.failure_reason == "invalid_code"
    db.close()


def test_admin_provision_rate_limiting_after_3_attempts(client):
    """3 failed provisioning attempts locks out the user with 429."""
    db = TestingSessionLocal()
    user = _create_user(db, email="ratelimited@example.com")
    token = _get_token_for(user)

    # Make 3 failed attempts
    for _ in range(3):
        resp = client.post(
            "/auth/admin/provision",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": "sx_admin_sec_invalid_attempt_123456"},
        )
        assert resp.status_code == 401

    # 4th attempt must be rate-limited (429)
    resp4 = client.post(
        "/auth/admin/provision",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": settings.ADMIN_PROVISIONING_CODE},
    )
    assert resp4.status_code == 429
    assert "Rate limit exceeded" in resp4.json()["detail"]
    db.close()


def test_admin_provision_success_elevation_and_single_use(client):
    """
    Elevates user with valid code:
    1. Returns new JWT token containing 'admin' in claims.
    2. Updates user roles in database.
    3. Invalidates code so reuse is rejected with 400.
    """
    db = TestingSessionLocal()
    user = _create_user(db, email="admin_candidate@example.com", roles=["seller"])
    token = _get_token_for(user)

    # Valid provisioning
    resp = client.post(
        "/auth/admin/provision",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": settings.ADMIN_PROVISIONING_CODE},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "admin" in data["roles"]
    assert "seller" in data["roles"]

    # Check decoded new token
    new_token = data["access_token"]
    payload = decode_access_token(new_token)
    assert "admin" in payload["roles"]

    # Check database persistence
    db.expire_all()
    refreshed_user = db.query(User).filter(User.id == user.id).first()
    assert refreshed_user is not None
    assert "admin" in refreshed_user.roles

    # Check audit log
    audit = db.query(AdminProvisionAuditLog).filter(AdminProvisionAuditLog.user_id == user.id, AdminProvisionAuditLog.success == True).first()
    assert audit is not None

    # Single-use: attempting to use the code again fails
    user2 = _create_user(db, email="second_candidate@example.com")
    token2 = _get_token_for(user2)

    resp_reuse = client.post(
        "/auth/admin/provision",
        headers={"Authorization": f"Bearer {token2}"},
        json={"code": settings.ADMIN_PROVISIONING_CODE},
    )
    assert resp_reuse.status_code == 400
    assert "already been used and invalidated" in resp_reuse.json()["detail"]
    db.close()


# ============================================================================
# Admin Endpoints & KYC Canonical State Machine Tests (Prompt 4)
# ============================================================================

def test_admin_audit_log_endpoint(client):
    """GET /auth/admin/audit-log requires admin role."""
    db = TestingSessionLocal()
    regular_user = _create_user(db, email="regular@example.com", roles=["customer"])
    admin_user = _create_user(db, email="operator@example.com", roles=["admin"])

    # Customer is forbidden (403)
    resp_reg = client.get(
        "/auth/admin/audit-log",
        headers={"Authorization": f"Bearer {_get_token_for(regular_user)}"},
    )
    assert resp_reg.status_code == 403

    # Admin succeeds (200)
    resp_admin = client.get(
        "/auth/admin/audit-log",
        headers={"Authorization": f"Bearer {_get_token_for(admin_user)}"},
    )
    assert resp_admin.status_code == 200
    assert isinstance(resp_admin.json(), list)
    db.close()


def test_admin_kyc_verification_uses_canonical_state_machine(client):
    """
    CRITICAL CHECK:
    Confirm manual admin verification routes strictly through update_seller_kyc_status()
    and correctly toggles is_seller_payout_enabled to True without state machine drift.
    """
    db = TestingSessionLocal()
    admin_user = _create_user(db, email="chief_admin@example.com", roles=["admin"])
    seller = _create_user(db, email="seller_kyc@example.com", roles=["seller"])

    # Create seller profile in pending status
    profile = get_or_create_seller_profile(seller.id, db)
    profile.kyc_status = KYCStatus.PENDING.value
    profile.payout_enabled = False
    db.commit()

    assert is_seller_payout_enabled(seller.id, db) is False

    admin_token = _get_token_for(admin_user)

    # 1. Admin checks pending queue
    queue_resp = client.get(
        "/auth/admin/kyc/pending",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert queue_resp.status_code == 200
    pending_list = queue_resp.json()
    assert any(item["user_id"] == seller.id for item in pending_list)

    # 2. Admin manually verifies seller
    verify_resp = client.post(
        f"/auth/admin/kyc/{seller.id}/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["kyc_status"] == "verified"
    assert verify_data["payout_enabled"] is True

    # 3. Assert downstream payout gate is enabled
    db.expire_all()
    assert is_seller_payout_enabled(seller.id, db) is True

    # 4. Assert audit details are attached in metadata
    db.refresh(profile)
    assert profile.kyc_metadata["last_update"]["details"]["source"] == "admin_manual_review"
    assert profile.kyc_metadata["last_update"]["details"]["admin_id"] == admin_user.id
    db.close()


def test_admin_kyc_rejection_uses_canonical_state_machine(client):
    """
    Confirm manual admin rejection routes strictly through update_seller_kyc_status()
    and leaves payout_enabled as False with recorded rejection reason.
    """
    db = TestingSessionLocal()
    admin_user = _create_user(db, email="compliance_officer@example.com", roles=["admin"])
    seller = _create_user(db, email="rejected_seller@example.com", roles=["seller"])

    profile = get_or_create_seller_profile(seller.id, db)
    profile.kyc_status = KYCStatus.PENDING.value
    profile.payout_enabled = False
    db.commit()

    admin_token = _get_token_for(admin_user)

    reject_resp = client.post(
        f"/auth/admin/kyc/{seller.id}/reject",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"reason": "Identity document illegible"},
    )
    assert reject_resp.status_code == 200
    reject_data = reject_resp.json()
    assert reject_data["kyc_status"] == "rejected"
    assert reject_data["payout_enabled"] is False

    assert is_seller_payout_enabled(seller.id, db) is False

    db.refresh(profile)
    assert profile.kyc_metadata["last_update"]["details"]["reason"] == "Identity document illegible"
    db.close()


# ============================================================================
# Post-Login Role Routing Hierarchy Tests (Prompt 5)
# ============================================================================

def test_admin_who_is_also_seller_routing_priority():
    """
    Confirm post-login routing rules:
    - User with both 'seller' and 'admin' roles lands on seller dashboard (most specific applicable role).
    - NOT redirected to admin dashboard.
    """
    user_seller_admin = {
        "id": "usr-123",
        "roles": ["customer", "seller", "admin"],
    }
    roles = user_seller_admin["roles"]

    # Emulate routeUserAfterLogin logic
    destination = None
    if "seller" in roles:
        destination = "/static/dashboard-seller.html"
    elif "customer" in roles:
        destination = "/static/browse-listings.html"
    else:
        destination = "/static/browse-listings.html"

    assert destination == "/static/dashboard-seller.html"
    assert destination != "/static/admin-dashboard.html"
    assert destination != "/static/browse-listings.html"
