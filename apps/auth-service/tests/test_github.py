import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.config import settings
from src.database import Base, get_db
from src.main import app
from src.models.user import User, SellerProfile, SellerGitHubConnection, KYCStatus
from src.models.notification import Notification, NotificationType
from src.security import create_access_token, hash_password

# Test database setup (in-memory SQLite)
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
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
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


def _create_seller(email: str = "seller@example.com", kyc_status: str = KYCStatus.NOT_STARTED.value) -> User:
    db = TestingSessionLocal()
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=email,
        password_hash=hash_password("Password123!"),
        roles=["seller"],
        email_verified=True,
    )
    profile = SellerProfile(
        user_id=user_id,
        kyc_status=kyc_status,
        payout_enabled=(kyc_status == KYCStatus.VERIFIED.value),
    )
    db.add(user)
    db.add(profile)
    db.commit()
    db.refresh(user)
    db.close()
    return user


def _create_customer(email: str = "customer@example.com") -> User:
    db = TestingSessionLocal()
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        password_hash=hash_password("Password123!"),
        roles=["customer"],
        email_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


def _auth_headers(user: User) -> dict:
    token = create_access_token(user_id=user.id, roles=user.roles)
    return {"Authorization": f"Bearer {token}"}


def test_authorize_url_minimal_scopes():
    """
    Scope & Protocol Test:
    Ensures /auth/seller/github/authorize requests only read:user public_repo
    and strictly never requests 'repo', 'admin', or write scopes.
    """
    seller = _create_seller("scope_seller@test.com")
    headers = _auth_headers(seller)

    res = client.get("/auth/seller/github/authorize", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["scope"] == "read:user public_repo"
    assert "authorize_url" in data
    auth_url = data["authorize_url"]
    assert "scope=read%3Auser+public_repo" in auth_url or "scope=read:user+public_repo" in auth_url or "scope=read%3Auser%20public_repo" in auth_url

    # Negative scope enforcement
    assert "admin:" not in auth_url
    assert "write:" not in auth_url
    assert "repo," not in auth_url and "scope=repo" not in auth_url

    # State HMAC parameter present
    assert "state" in data
    state_parts = data["state"].split(":")
    assert len(state_parts) == 3
    assert state_parts[0] == seller.id


def test_authorize_requires_seller_role():
    """Customer-only tokens are rejected with 403; unauthenticated with 401."""
    cust = _create_customer("cust_only@test.com")
    cust_headers = _auth_headers(cust)

    res_unauth = client.get("/auth/seller/github/authorize")
    assert res_unauth.status_code == 401

    res_cust = client.get("/auth/seller/github/authorize", headers=cust_headers)
    assert res_cust.status_code == 403


def test_github_connect_does_not_enable_payout():
    """
    Decoupling Invariant 1:
    Connecting GitHub for seller with kyc_status='not_started' strictly leaves
    payout_enabled == False and kyc_status == 'not_started'.
    """
    seller = _create_seller("unverified_seller@test.com", kyc_status=KYCStatus.NOT_STARTED.value)
    headers = _auth_headers(seller)

    # 1. Initiate auth to obtain valid signed state
    auth_res = client.get("/auth/seller/github/authorize", headers=headers)
    state = auth_res.json()["state"]

    # 2. Complete callback with mock profile
    mock_profile = {
        "login": "octocat-dev",
        "id": 583231,
        "created_at": "2020-03-01T00:00:00Z",
        "public_repos": 24,
    }
    cb_res = client.post(
        "/auth/seller/github/callback",
        headers=headers,
        json={
            "code": "test_auth_code_123",
            "state": state,
            "mock_profile": mock_profile,
        },
    )
    assert cb_res.status_code == 200
    cb_data = cb_res.json()
    assert cb_data["github_username"] == "octocat-dev"
    assert cb_data["public_repo_count"] == 24
    assert cb_data["account_age_years"] > 0.0

    # 3. Assert KYC and Payout in DB remain strictly unverified & disabled
    db = TestingSessionLocal()
    profile = db.query(SellerProfile).filter(SellerProfile.user_id == seller.id).first()
    assert profile is not None
    assert profile.kyc_status == KYCStatus.NOT_STARTED.value
    assert profile.payout_enabled is False
    db.close()


def test_github_connected_seller_without_kyc_fails_payout():
    """
    Decoupling Invariant 2:
    A GitHub-connected seller without KYC is denied payout access.
    """
    seller = _create_seller("gh_seller_no_kyc@test.com", kyc_status=KYCStatus.NOT_STARTED.value)
    headers = _auth_headers(seller)

    # Connect GitHub
    client.post(
        "/auth/seller/github/callback",
        headers=headers,
        json={"code": "mock_code_octocat_pro"},
    )

    # Check status endpoint reflects connection
    status_res = client.get("/auth/seller/github/status", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["is_connected"] is True
    assert status_res.json()["connection"]["github_username"] == "octocat_pro"

    # Query KYC status -> MUST remain NOT_STARTED and payout disabled
    kyc_res = client.get("/auth/seller/kyc/status", headers=headers)
    assert kyc_res.status_code == 200
    assert kyc_res.json()["kyc_status"] == KYCStatus.NOT_STARTED.value
    assert kyc_res.json()["payout_enabled"] is False


def test_disconnect_github_leaves_kyc_and_listings_intact():
    """
    Decoupling Invariant 3:
    Disconnecting GitHub removes connection row and does not modify KYC status.
    """
    seller = _create_seller("disconnect_seller@test.com", kyc_status=KYCStatus.VERIFIED.value)
    headers = _auth_headers(seller)

    # 1. Connect GitHub
    client.post(
        "/auth/seller/github/callback",
        headers=headers,
        json={"code": "mock_code_connected_dev"},
    )

    # 2. Verify connected
    st1 = client.get("/auth/seller/github/status", headers=headers)
    assert st1.json()["is_connected"] is True

    # 3. Disconnect
    disc_res = client.post("/auth/seller/github/disconnect", headers=headers)
    assert disc_res.status_code == 200
    assert disc_res.json()["is_connected"] is False

    # 4. Status endpoint reflects disconnected
    st2 = client.get("/auth/seller/github/status", headers=headers)
    assert st2.json()["is_connected"] is False
    assert st2.json()["connection"] is None

    # 5. KYC remains verified
    db = TestingSessionLocal()
    profile = db.query(SellerProfile).filter(SellerProfile.user_id == seller.id).first()
    assert profile.kyc_status == KYCStatus.VERIFIED.value
    assert profile.payout_enabled is True
    # Connection row deleted
    conn = db.query(SellerGitHubConnection).filter(SellerGitHubConnection.user_id == seller.id).first()
    assert conn is None
    db.close()


def test_notifications_emitted_on_connect_and_disconnect():
    """Ensures github_connected and github_disconnected notifications are emitted."""
    seller = _create_seller("notif_seller@test.com")
    headers = _auth_headers(seller)

    # Connect
    client.post(
        "/auth/seller/github/callback",
        headers=headers,
        json={"code": "mock_code_notif_dev"},
    )

    db = TestingSessionLocal()
    conn_notif = (
        db.query(Notification)
        .filter(Notification.user_id == seller.id, Notification.type == NotificationType.GITHUB_CONNECTED.value)
        .first()
    )
    assert conn_notif is not None
    assert conn_notif.payload.get("github_username") == "notif_dev"
    db.close()

    # Disconnect
    client.post("/auth/seller/github/disconnect", headers=headers)

    db = TestingSessionLocal()
    disc_notif = (
        db.query(Notification)
        .filter(Notification.user_id == seller.id, Notification.type == NotificationType.GITHUB_DISCONNECTED.value)
        .first()
    )
    assert disc_notif is not None
    db.close()


def test_public_trust_endpoint():
    """
    Public trust readout endpoint test:
    Validates GET /auth/seller/{seller_id}/public-trust returns distinct trust signals.
    """
    # 1. Seller without GitHub and without KYC
    seller1 = _create_seller("s1@test.com", kyc_status=KYCStatus.NOT_STARTED.value)
    res1 = client.get(f"/auth/seller/{seller1.id}/public-trust")
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["kyc_verified"] is False
    assert d1["payout_enabled"] is False
    assert d1["github_connected"] is False
    assert d1["github"] is None

    # 2. Seller with GitHub and KYC verified
    seller2 = _create_seller("s2@test.com", kyc_status=KYCStatus.VERIFIED.value)
    client.post(
        "/auth/seller/github/callback",
        headers=_auth_headers(seller2),
        json={"code": "mock_code_octoverified"},
    )

    res2 = client.get(f"/auth/seller/{seller2.id}/public-trust")
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["kyc_verified"] is True
    assert d2["payout_enabled"] is True
    assert d2["github_connected"] is True
    assert d2["github"]["github_username"] == "octoverified"
    assert d2["github"]["public_repo_count"] == 14
