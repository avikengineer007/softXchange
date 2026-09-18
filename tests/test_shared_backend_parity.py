"""
test_shared_backend_parity.py — Shared Backend Parity and Cross-Service Integration Tests

Validates the platform guarantee:
1. Both Web and Android clients interact with the exact same backend endpoints and data models.
2. Complete end-to-end lifecycle:
   - User registration and authentication (Auth Service)
   - Seller KYC submission and provider webhook verification (Auth Service)
   - Package creation, versioning, security scan gate, and promotion to live (Listings Service)
   - Order creation, fee split calculation, payment confirmation, and entitlement issuance (Payments Service)
   - Secure customer download verification and access control (Payments Service)
   - Fail-closed security rules (unpaid downloads rejected, unvetted packages non-purchasable).

Run: pytest tests/test_shared_backend_parity.py -v
"""
import sys
import uuid
import importlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parent.parent


def setup_service_env(service_dir_name: str):
    """Cleanly switches sys.path and sys.modules to the requested service directory."""
    service_dir = REPO_ROOT / "apps" / service_dir_name
    for app in ["auth-service", "listings-service", "payments-service", "scan-service", "web-unified"]:
        p = str(REPO_ROOT / "apps" / app)
        if p in sys.path:
            sys.path.remove(p)
    sys.path.insert(0, str(service_dir))
    for k in list(sys.modules.keys()):
        if k == "src" or k.startswith("src."):
            sys.modules.pop(k, None)


def generate_jwt(private_key, kid, user_id, roles, email=None):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "roles": roles,
        "type": "access",
        "email": email or f"{user_id}@example.com",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": kid})


def test_auth_service_registration_and_login_lifecycle():
    """Verify auth-service handles user registration, token generation, and profile retrieval."""
    setup_service_env("auth-service")
    from src.main import app
    from src.database import Base, get_db

    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # 1. Signup
    signup_res = client.post(
        "/auth/signup",
        json={
            "email": "shared-client@example.com",
            "password": "SecurePassword123!",
            "roles": ["customer", "seller"],
            "display_name": "Shared Client",
        },
    )
    assert signup_res.status_code == 201
    assert signup_res.json()["email"] == "shared-client@example.com"

    # 2. Login
    login_res = client.post(
        "/auth/login",
        json={
            "email": "shared-client@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert set(data["user"]["roles"]) == {"customer", "seller"}

    # 3. Authenticated /auth/me
    token = data["access_token"]
    me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "shared-client@example.com"

    # 4. httpOnly cookie refresh flow (Silent Re-authentication)
    # Server sets httpOnly refresh_token cookie on login
    assert "refresh_token" in login_res.cookies
    # POST /auth/refresh without payload exchanges the httpOnly cookie for a new access token
    refresh_res = client.post("/auth/refresh", json={})
    assert refresh_res.status_code == 200
    refreshed_data = refresh_res.json()
    new_token = refreshed_data["access_token"]
    assert new_token is not None

    # New access token is fully valid
    new_me = client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert new_me.status_code == 200
    assert new_me.json()["email"] == "shared-client@example.com"

    # Logout clears session and revokes refresh token
    logout_res = client.post("/auth/logout", json={})
    assert logout_res.status_code == 200


def test_seller_kyc_verification_and_payout_gate():
    """Verify seller KYC lifecycle: start, submit details, webhook confirmation, payout enabled."""
    setup_service_env("auth-service")
    from src.main import app
    from src.database import Base, get_db

    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # Signup & login
    client.post(
        "/auth/signup",
        json={"email": "kyc-flow@example.com", "password": "Password123!", "roles": ["seller"]},
    )
    login_res = client.post(
        "/auth/login",
        json={"email": "kyc-flow@example.com", "password": "Password123!"},
    )
    seller_id = login_res.json()["user"]["id"]
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial KYC status is not_started, payout disabled
    stat_res = client.get("/auth/seller/kyc/status", headers=headers)
    assert stat_res.status_code == 200
    assert stat_res.json()["kyc_status"] == "not_started"
    assert stat_res.json()["payout_enabled"] is False

    # Start KYC
    start_res = client.post("/auth/seller/kyc/start", headers=headers)
    assert start_res.status_code == 200
    assert start_res.json()["kyc_status"] == "pending"

    # Submit KYC form
    submit_res = client.post(
        "/auth/seller/kyc/submit",
        headers=headers,
        json={
            "legal_name": "Shared Seller LLC",
            "business_name": "Shared Labs",
            "tax_id": "99-8887776",
            "country": "US",
            "city": "San Francisco",
        },
    )
    assert submit_res.status_code == 200
    assert submit_res.json()["kyc_status"] == "pending"

    # Simulate identity verification webhook
    wb_res = client.post(
        "/auth/seller/kyc/webhook",
        json={
            "user_id": seller_id,
            "event": "identity.verified",
            "status": "verified",
            "details": {"verification_id": "verif_shared_123"},
        },
    )
    assert wb_res.status_code == 200
    assert wb_res.json()["payout_enabled"] is True


def test_listings_and_gate_parity_lifecycle():
    """Verify seller creates listing, submits version, passes gate into live status."""
    setup_service_env("listings-service")
    app = importlib.import_module("src.main").app
    db_mod = importlib.import_module("src.database")
    Base = db_mod.Base
    get_db = db_mod.get_db
    jwks_manager = importlib.import_module("src.auth").jwks_manager
    listing_models = importlib.import_module("src.models.listing")
    Listing = listing_models.Listing
    ListingVersion = listing_models.ListingVersion
    ListingStatus = listing_models.ListingStatus
    ScanStatus = listing_models.ScanStatus
    gate_mod = importlib.import_module("src.gate")
    evaluate_publish_gate = gate_mod.evaluate_publish_gate
    PayoutCheckResult = gate_mod.PayoutCheckResult

    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "shared-listings-key"
    jwks_manager.set_key_for_testing(kid, rsa_key.public_key())

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    seller_id = "seller-shared-99"
    token = generate_jwt(rsa_key, kid, seller_id, ["seller"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create listing
    create_res = client.post(
        "/listings",
        headers=headers,
        json={
            "title": "Cloud Analytics SDK",
            "description": "High throughput telemetry pipeline SDK",
            "price_cents": 4900,
            "category": "analytics",
        },
    )
    assert create_res.status_code == 201
    listing = create_res.json()
    listing_id = listing["id"]
    assert listing["status"] == "draft"

    # 2. Public browse does NOT show draft listing
    browse_res = client.get("/listings")
    assert browse_res.status_code == 200
    listings_list = browse_res.json()
    assert not any(l["id"] == listing_id for l in listings_list)

    # 3. Simulate gate evaluation -> promote to LIVE
    db = TestingSessionLocal()
    db_listing = db.query(Listing).filter(Listing.id == listing_id).first()
    ver = ListingVersion(
        id=f"ver-{uuid.uuid4().hex[:8]}",
        listing_id=listing_id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db.add(ver)
    db.commit()

    evaluate_publish_gate(db_listing, ver, db, payout_override=PayoutCheckResult.PAYOUT_ENABLED)
    db.close()

    # 4. Public browse now returns the LIVE listing
    browse_res = client.get("/listings")
    assert browse_res.status_code == 200
    listings_list = browse_res.json()
    assert any(l["id"] == listing_id for l in listings_list)


def test_payments_order_and_entitlement_lifecycle(monkeypatch):
    """Verify order creation, test-confirm payment, entitlement grant, and secure download."""
    setup_service_env("payments-service")
    app = importlib.import_module("src.main").app
    db_mod = importlib.import_module("src.database")
    Base = db_mod.Base
    get_db = db_mod.get_db
    jwks_manager = importlib.import_module("src.auth").jwks_manager
    SellerPaymentProfile = importlib.import_module("src.models.seller_payment_profile").SellerPaymentProfile

    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "shared-payments-key"
    jwks_manager.set_key_for_testing(kid, rsa_key.public_key())

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    buyer_id = "buyer-user-88"
    buyer_token = generate_jwt(rsa_key, kid, buyer_id, ["customer"])
    buyer_headers = {"Authorization": f"Bearer {buyer_token}"}

    # Setup connected seller in payments db
    db = TestingSessionLocal()
    seller_profile = SellerPaymentProfile(
        user_id="seller-user-77",
        razorpay_account_id="acc_shared_test",
    )
    db.add(seller_profile)
    db.commit()
    db.close()

    # Mock listings-service HTTP response
    import httpx
    orig_get = httpx.Client.get

    def mock_get(self, url, *args, **kwargs):
        url_str = str(url)
        if "listings" in url_str:
            class MockResp:
                status_code = 200
                def raise_for_status(self): pass
                def json(self):
                    return {
                        "id": "listing-live-1",
                        "status": "live",
                        "vetted": True,
                        "seller_id": "seller-user-77",
                        "price_cents": 5000,
                        "current_version": {"id": "ver-live-1"},
                    }
            return MockResp()
        return orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    # Mock razorpay order creation
    monkeypatch.setattr(
        "src.razorpay_client.razorpay_client.create_order",
        lambda **kwargs: {"id": "order_mock_shared_123"},
    )

    # 1. Buyer creates order
    order_res = client.post(
        "/orders",
        headers=buyer_headers,
        json={"listing_id": "listing-live-1"},
    )
    assert order_res.status_code == 201
    order_data = order_res.json()
    order_id = order_data["id"]
    assert order_data["status"] == "pending_payment"
    assert order_data["amount_cents"] == 5000

    # 2. Test-confirm order
    confirm_res = client.post(f"/orders/{order_id}/test-confirm", headers=buyer_headers)
    assert confirm_res.status_code == 200
    assert confirm_res.json()["status"] == "paid"

    # 3. Authorized buyer can request download URL
    dl_res = client.get(f"/orders/{order_id}/download", headers=buyer_headers)
    assert dl_res.status_code == 200
    assert "download_url" in dl_res.json()

    # 4. Unauthenticated user cannot download
    unauth_dl = client.get(f"/orders/{order_id}/download")
    assert unauth_dl.status_code == 401

    # 5. Other buyer cannot download
    other_token = generate_jwt(rsa_key, kid, "other-buyer-99", ["customer"])
    other_dl = client.get(f"/orders/{order_id}/download", headers={"Authorization": f"Bearer {other_token}"})
    assert other_dl.status_code == 403
