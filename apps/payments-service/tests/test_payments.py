import os
import sys
import uuid
import hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
import jwt
import httpx
import asyncio
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure apps/payments-service is on sys.path and prior src is cleared
SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))
sys.modules.pop("src", None)
for k in list(sys.modules.keys()):
    if k.startswith("src."):
        sys.modules.pop(k, None)

from src.main import app
from src.database import Base, get_db
from src.config import settings
from src.auth import jwks_manager
from src.models import (
    SellerPaymentProfile,
    Order,
    OrderStatus,
    HoldStatus,
    Entitlement,
    EntitlementStatus,
)
from src.razorpay_client import razorpay_client
from src.storage import generate_signed_download_url, verify_download_token

# In-memory SQLite for testing with StaticPool
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Setup RSA Test Keypair
test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_public_key = test_private_key.public_key()
TEST_KID = "test-payments-key-1"

# Inject into JWKS manager test hook
jwks_manager.set_key_for_testing(TEST_KID, test_public_key)


def generate_test_token(user_id: str, roles: list, kid: str = TEST_KID, expired: bool = False) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": user_id,
        "roles": roles,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    pem_priv = test_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_priv, algorithm="RS256", headers={"kid": kid})


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seller_token():
    return generate_test_token("seller-user-123", ["seller"])


@pytest.fixture
def buyer_token():
    return generate_test_token("buyer-user-456", ["customer"])


@pytest.fixture
def admin_token():
    return generate_test_token("admin-user-999", ["admin"])


# ============================================================================
# Section 1: Razorpay Route Linked Account Onboarding & Webhook Bridge Tests
# ============================================================================

def test_connect_start_requires_seller_role(client, buyer_token):
    """Only sellers can initiate Razorpay Route onboarding."""
    res_unauth = client.post("/payments/seller/connect/start")
    assert res_unauth.status_code == 401

    res_buyer = client.post(
        "/payments/seller/connect/start",
        headers={"Authorization": f"Bearer {buyer_token}"}
    )
    assert res_buyer.status_code == 403


def test_connect_start_creates_linked_account(client, seller_token, monkeypatch):
    """Seller onboarding creates Razorpay Route linked account and returns details."""
    monkeypatch.setattr(
        razorpay_client,
        "create_linked_account",
        lambda user_id, email, business_name=None: "acc_rzp_test_123"
    )

    res = client.post(
        "/payments/seller/connect/start",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["user_id"] == "seller-user-123"
    assert data["razorpay_account_id"] == "acc_rzp_test_123"
    assert "onboarding_url" in data

    # Verify profile stored in DB without duplicate KYC flags
    db = TestingSessionLocal()
    profile = db.query(SellerPaymentProfile).filter(SellerPaymentProfile.user_id == "seller-user-123").first()
    assert profile is not None
    assert profile.razorpay_account_id == "acc_rzp_test_123"
    assert not hasattr(profile, "kyc_status")  # Single source of truth guarantee
    db.close()


def test_razorpay_webhook_rejects_missing_or_invalid_signature(client):
    """Razorpay webhook rejects unauthenticated or tampered payloads (400)."""
    # Missing header
    res_no_sig = client.post("/payments/webhooks/razorpay", content=b"{}")
    assert res_no_sig.status_code == 400

    # Invalid signature
    res_bad_sig = client.post(
        "/payments/webhooks/razorpay",
        content=b"{}",
        headers={"X-Razorpay-Signature": "invalid_signature"}
    )
    assert res_bad_sig.status_code == 400


def test_razorpay_webhook_account_activated_triggers_auth_kyc_callback(client, monkeypatch):
    """When Razorpay Route account is activated, webhook triggers HMAC-signed callback to auth-service."""
    db = TestingSessionLocal()
    profile = SellerPaymentProfile(user_id="seller-kyc-test", razorpay_account_id="acc_verified_456")
    db.add(profile)
    db.commit()
    db.close()

    # Mock signature verification
    monkeypatch.setattr(razorpay_client, "verify_webhook_signature", lambda body, sig, secret=None: True)

    mock_event = {
        "event": "account.activated",
        "account_id": "acc_verified_456",
        "payload": {
            "account": {
                "entity": {
                    "id": "acc_verified_456",
                    "status": "activated",
                }
            }
        }
    }

    # Capture HMAC callback to auth-service
    captured_callback = {}
    def mock_send_kyc(user_id, status_str, razorpay_account_id):
        captured_callback["user_id"] = user_id
        captured_callback["status"] = status_str
        captured_callback["razorpay_account_id"] = razorpay_account_id
        return True

    import src.routes.webhooks as webhooks_mod
    monkeypatch.setattr(webhooks_mod, "_send_authenticated_kyc_callback", mock_send_kyc)

    res = client.post(
        "/payments/webhooks/razorpay",
        content=json.dumps(mock_event).encode("utf-8"),
        headers={"X-Razorpay-Signature": "valid_sig"}
    )
    assert res.status_code == 200
    assert captured_callback["user_id"] == "seller-kyc-test"
    assert captured_callback["status"] == "verified"
    assert captured_callback["razorpay_account_id"] == "acc_verified_456"


@pytest.mark.parametrize("ambiguous_event,expected_status", [
    ("account.under_review", "pending_review"),
    ("account.needs_clarification", "pending_review"),
    ("account.suspended", "suspended"),
    ("account.rejected", "rejected"),
])
def test_razorpay_webhook_fails_closed_on_ambiguous_or_rejected_kyc_states(
    client, monkeypatch, ambiguous_event, expected_status
):
    """Fails closed on non-activated Route account states, never assuming verified."""
    db = TestingSessionLocal()
    profile = SellerPaymentProfile(user_id="seller-ambig", razorpay_account_id="acc_ambig_789")
    db.add(profile)
    db.commit()
    db.close()

    monkeypatch.setattr(razorpay_client, "verify_webhook_signature", lambda b, s, secret=None: True)

    mock_event = {
        "event": ambiguous_event,
        "account_id": "acc_ambig_789",
    }

    captured_callback = {}
    def mock_send_kyc(user_id, status_str, razorpay_account_id):
        captured_callback["user_id"] = user_id
        captured_callback["status"] = status_str
        captured_callback["razorpay_account_id"] = razorpay_account_id
        return True

    import src.routes.webhooks as webhooks_mod
    monkeypatch.setattr(webhooks_mod, "_send_authenticated_kyc_callback", mock_send_kyc)

    res = client.post(
        "/payments/webhooks/razorpay",
        content=json.dumps(mock_event).encode("utf-8"),
        headers={"X-Razorpay-Signature": "valid_sig"}
    )
    assert res.status_code == 200
    assert captured_callback["user_id"] == "seller-ambig"
    assert captured_callback["status"] == expected_status
    assert captured_callback["razorpay_account_id"] == "acc_ambig_789"


def test_send_authenticated_kyc_callback_generates_valid_hmac(monkeypatch):
    """Verifies that _send_authenticated_kyc_callback computes correct SHA256 HMAC."""
    from src.routes.webhooks import _send_authenticated_kyc_callback
    captured = {}
    def mock_post(url, content, headers):
        captured["url"] = url
        captured["content"] = content
        captured["headers"] = headers
        class MockResp:
            status_code = 200
            text = "ok"
        return MockResp()

    monkeypatch.setattr(httpx.Client, "post", lambda self, url, content=None, headers=None: mock_post(url, content, headers))

    ok = _send_authenticated_kyc_callback("user-1", "verified", "acc_1")
    assert ok is True
    assert "X-Service-Signature" in captured["headers"]
    assert "X-Service-Timestamp" in captured["headers"]
    ts = captured["headers"]["X-Service-Timestamp"]
    sig = captured["headers"]["X-Service-Signature"]
    signed_data = f"{ts}.".encode("utf-8") + captured["content"]
    expected_sig = hmac.new(
        settings.INTERNAL_SERVICE_SECRET.encode("utf-8"),
        signed_data,
        hashlib.sha256
    ).hexdigest()
    assert sig == expected_sig


# ============================================================================
# Section 2: Order Model + Razorpay Order Creation Tests
# ============================================================================

def test_create_order_requires_authentication(client):
    """Unauthenticated buyer cannot create orders."""
    res = client.post("/orders", json={"listing_id": "l-123"})
    assert res.status_code == 401


def test_create_order_rejects_non_live_listing(client, buyer_token, monkeypatch):
    """Rejects checkout if listing is not currently 'live' in listings-service."""
    def mock_get(url):
        class MockResp:
            status_code = 200
            def raise_for_status(self): pass
            def json(self):
                return {
                    "id": "l-draft-1",
                    "status": "draft",  # NOT live
                    "vetted": False,
                    "seller_id": "seller-user-123",
                    "price_cents": 2500,
                    "current_version": {"id": "v-1"},
                }
        return MockResp()

    monkeypatch.setattr("httpx.Client.get", lambda self, url: mock_get(url))

    res = client.post(
        "/orders",
        headers={"Authorization": f"Bearer {buyer_token}"},
        json={"listing_id": "l-draft-1"}
    )
    assert res.status_code == 400
    assert "must be live and vetted" in res.json()["detail"]


def test_create_order_fee_split_math_and_razorpay_order(client, buyer_token, monkeypatch):
    """Validates 8% flat platform fee calculation and Razorpay order creation."""
    db = TestingSessionLocal()
    seller_profile = SellerPaymentProfile(user_id="seller-corp-1", razorpay_account_id="acc_seller_1")
    db.add(seller_profile)
    db.commit()
    db.close()

    def mock_get(url):
        class MockResp:
            status_code = 200
            def raise_for_status(self): pass
            def json(self):
                return {
                    "id": "l-live-1",
                    "status": "live",
                    "vetted": True,
                    "seller_id": "seller-corp-1",
                    "price_cents": 5000,  # $50.00
                    "current_version": {"id": "v-pinned-100"},
                }
        return MockResp()

    monkeypatch.setattr("httpx.Client.get", lambda self, url: mock_get(url))

    captured_rzp_order = {}
    def mock_create_rzp_order(amount_minor_units, currency="INR", receipt=None, notes=None):
        captured_rzp_order["amount"] = amount_minor_units
        captured_rzp_order["currency"] = currency
        captured_rzp_order["receipt"] = receipt
        captured_rzp_order["notes"] = notes
        return {
            "id": "order_rzp_mock_999",
            "amount": amount_minor_units,
            "currency": currency,
            "status": "created",
        }

    monkeypatch.setattr(razorpay_client, "create_order", mock_create_rzp_order)

    res = client.post(
        "/orders",
        headers={"Authorization": f"Bearer {buyer_token}"},
        json={"listing_id": "l-live-1"}
    )
    assert res.status_code == 201
    order = res.json()

    # Verify amounts and fee split math in canonical INR (paise)
    assert order["amount_cents"] == 5000
    assert order["platform_fee_cents"] == 400   # 8% of 5000
    assert order["seller_payout_cents"] == 4600 # 5000 - 400
    assert order["platform_fee_cents"] + order["seller_payout_cents"] == order["amount_cents"]

    # Verify Razorpay fields
    assert order["razorpay_order_id"] == "order_rzp_mock_999"
    assert order["charged_currency"] == "INR"
    assert order["charged_amount_minor_units"] == 5000

    # Verify DEAD client_secret field is dropped completely
    assert "client_secret" not in order

    # Verify immutable version pinning
    assert order["listing_version_id"] == "v-pinned-100"
    assert order["status"] == "pending_payment"

    # Verify Razorpay order params
    assert captured_rzp_order["amount"] == 5000
    assert captured_rzp_order["currency"] == "INR"
    assert captured_rzp_order["notes"]["seller_id"] == "seller-corp-1"
    assert captured_rzp_order["notes"]["platform_fee_cents"] == 400


# ============================================================================
# Section 3: Payment Verification Endpoint (/orders/{id}/verify) Tests
# ============================================================================

def test_order_verify_with_valid_signature_transitions_order_and_creates_entitlement(client, buyer_token, monkeypatch):
    """POST /orders/{id}/verify with valid signature transitions order to paid and creates Entitlement."""
    db = TestingSessionLocal()
    order = Order(
        id="order-vfy-1",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=2500,
        platform_fee_cents=200,
        seller_payout_cents=2300,
        status=OrderStatus.PENDING_PAYMENT.value,
        razorpay_order_id="order_rzp_vfy_1",
    )
    db.add(order)
    db.commit()
    db.close()

    # Mock signature verification succeeding
    monkeypatch.setattr(razorpay_client, "verify_payment_signature", lambda **kwargs: True)

    verify_payload = {
        "razorpay_order_id": "order_rzp_vfy_1",
        "razorpay_payment_id": "pay_rzp_12345",
        "razorpay_signature": "sig_valid_abc",
    }

    res = client.post(
        "/orders/order-vfy-1/verify",
        headers={"Authorization": f"Bearer {buyer_token}"},
        json=verify_payload,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "paid"
    assert res.json()["razorpay_payment_id"] == "pay_rzp_12345"

    # Verify DB state
    db = TestingSessionLocal()
    updated = db.query(Order).filter(Order.id == "order-vfy-1").first()
    assert updated is not None
    assert updated.status == OrderStatus.PAID.value
    assert updated.razorpay_payment_id == "pay_rzp_12345"
    assert updated.razorpay_signature == "sig_valid_abc"

    entitlement = db.query(Entitlement).filter(Entitlement.order_id == "order-vfy-1").first()
    assert entitlement is not None
    assert entitlement.buyer_id == "buyer-user-456"
    assert entitlement.status == EntitlementStatus.ACTIVE.value
    db.close()


def test_order_verify_rejects_invalid_signature(client, buyer_token, monkeypatch):
    """POST /orders/{id}/verify fails closed (400) if signature is forged/invalid."""
    db = TestingSessionLocal()
    order = Order(
        id="order-vfy-bad",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=2500,
        platform_fee_cents=200,
        seller_payout_cents=2300,
        status=OrderStatus.PENDING_PAYMENT.value,
        razorpay_order_id="order_rzp_vfy_bad",
    )
    db.add(order)
    db.commit()
    db.close()

    # Mock signature verification failing
    monkeypatch.setattr(razorpay_client, "verify_payment_signature", lambda **kwargs: False)

    res = client.post(
        "/orders/order-vfy-bad/verify",
        headers={"Authorization": f"Bearer {buyer_token}"},
        json={
            "razorpay_order_id": "order_rzp_vfy_bad",
            "razorpay_payment_id": "pay_tampered",
            "razorpay_signature": "sig_forged",
        },
    )
    assert res.status_code == 400
    assert "Invalid payment signature" in res.json()["detail"]


def test_order_verify_idempotent_duplicate_call(client, buyer_token, monkeypatch):
    """POST /orders/{id}/verify called repeatedly on already-paid order returns 200 without creating duplicate entitlements."""
    db = TestingSessionLocal()
    order = Order(
        id="order-vfy-idemp",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=3000,
        platform_fee_cents=240,
        seller_payout_cents=2760,
        status=OrderStatus.PAID.value,
        razorpay_order_id="order_rzp_idemp",
        razorpay_payment_id="pay_existing_123",
    )
    ent = Entitlement(order_id="order-vfy-idemp", buyer_id="buyer-user-456", listing_version_id="v-1")
    db.add_all([order, ent])
    db.commit()
    db.close()

    monkeypatch.setattr(razorpay_client, "verify_payment_signature", lambda o, p, s: True)

    res = client.post(
        "/orders/order-vfy-idemp/verify",
        headers={"Authorization": f"Bearer {buyer_token}"},
        json={
            "razorpay_order_id": "order_rzp_idemp",
            "razorpay_payment_id": "pay_existing_123",
            "razorpay_signature": "sig_whatever",
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "paid"

    # Only 1 entitlement exists
    db = TestingSessionLocal()
    ents = db.query(Entitlement).filter(Entitlement.order_id == "order-vfy-idemp").all()
    assert len(ents) == 1
    db.close()


# ============================================================================
# Section 4: Razorpay Webhook (order.paid & payment.captured) & Idempotency Tests
# ============================================================================

def test_razorpay_webhook_order_paid_transitions_order_and_creates_entitlement(client, monkeypatch):
    """Webhook event order.paid transitions order to 'paid' and creates Entitlement."""
    db = TestingSessionLocal()
    order = Order(
        id="order-rzp-paid-1",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=2000,
        platform_fee_cents=160,
        seller_payout_cents=1840,
        status=OrderStatus.PENDING_PAYMENT.value,
        razorpay_order_id="order_rzp_wh_1",
    )
    db.add(order)
    db.commit()
    db.close()

    monkeypatch.setattr(razorpay_client, "verify_webhook_signature", lambda b, s, secret=None: True)

    mock_event = {
        "event": "order.paid",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_rzp_wh_1",
                    "amount": 2000,
                    "status": "paid",
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_rzp_wh_payment_1",
                    "order_id": "order_rzp_wh_1",
                }
            }
        }
    }

    res = client.post(
        "/payments/webhooks/razorpay",
        content=json.dumps(mock_event).encode("utf-8"),
        headers={"X-Razorpay-Signature": "valid_sig"}
    )
    assert res.status_code == 200

    db = TestingSessionLocal()
    updated_order = db.query(Order).filter(Order.id == "order-rzp-paid-1").first()
    assert updated_order is not None
    assert updated_order.status == OrderStatus.PAID.value
    assert updated_order.razorpay_payment_id == "pay_rzp_wh_payment_1"

    entitlement = db.query(Entitlement).filter(Entitlement.order_id == "order-rzp-paid-1").first()
    assert entitlement is not None
    assert entitlement.buyer_id == "buyer-user-456"
    assert entitlement.listing_version_id == "v-1"
    assert entitlement.status == EntitlementStatus.ACTIVE.value
    db.close()


def test_razorpay_webhook_cross_event_idempotency_order_paid_and_payment_captured(client, monkeypatch):
    """
    CRITICAL IDEMPOTENCY GUARANTEE:
    When Razorpay sends both order.paid AND payment.captured for the same order,
    the second event does not duplicate entitlements or fail.
    """
    db = TestingSessionLocal()
    order = Order(
        id="order-cross-idemp",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=3500,
        platform_fee_cents=280,
        seller_payout_cents=3220,
        status=OrderStatus.PENDING_PAYMENT.value,
        razorpay_order_id="order_rzp_cross_1",
    )
    db.add(order)
    db.commit()
    db.close()

    monkeypatch.setattr(razorpay_client, "verify_webhook_signature", lambda b, s, secret=None: True)

    # 1. order.paid arrives first
    event_order_paid = {
        "event": "order.paid",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_rzp_cross_1",
                    "amount": 3500,
                    "status": "paid",
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_rzp_cross_payment_1",
                    "order_id": "order_rzp_cross_1",
                }
            }
        }
    }
    res1 = client.post(
        "/payments/webhooks/razorpay",
        content=json.dumps(event_order_paid).encode("utf-8"),
        headers={"X-Razorpay-Signature": "valid"}
    )
    assert res1.status_code == 200

    # 2. payment.captured arrives next for the same transaction
    event_payment_captured = {
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_rzp_cross_payment_1",
                    "order_id": "order_rzp_cross_1",
                    "amount": 3500,
                    "status": "captured",
                }
            }
        }
    }
    res2 = client.post(
        "/payments/webhooks/razorpay",
        content=json.dumps(event_payment_captured).encode("utf-8"),
        headers={"X-Razorpay-Signature": "valid"}
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_processed"

    # Verify only 1 entitlement exists in DB
    db = TestingSessionLocal()
    ents = db.query(Entitlement).filter(Entitlement.order_id == "order-cross-idemp").all()
    assert len(ents) == 1
    db.close()


# ============================================================================
# Section 5: Secure Download Token Tests
# ============================================================================

def test_download_authorized_buyer_paid_order(client, buyer_token):
    """Paid order generates short-lived signed download URL for authorized buyer."""
    db = TestingSessionLocal()
    order = Order(
        id="order-dl-paid",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=1000,
        platform_fee_cents=80,
        seller_payout_cents=920,
        status=OrderStatus.PAID.value,
    )
    db.add(order)
    db.commit()
    db.close()

    res = client.get(
        "/orders/order-dl-paid/download",
        headers={"Authorization": f"Bearer {buyer_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "download_url" in data
    assert data["expires_in_seconds"] == 900

    # Test downloading package with signed token
    dl_url = data["download_url"]
    dl_res = client.get(dl_url)
    assert dl_res.status_code == 200
    assert dl_res.json()["status"] == "authorized"


def test_download_rejected_for_unpaid_or_other_buyer(client, buyer_token):
    """Download rejected if order is unpaid or requested by someone other than the buyer."""
    db = TestingSessionLocal()
    unpaid_order = Order(
        id="order-dl-unpaid", listing_id="l-1", listing_version_id="v-1",
        buyer_id="buyer-user-456", seller_id="seller-1", amount_cents=1000,
        platform_fee_cents=80, seller_payout_cents=920, status=OrderStatus.PENDING_PAYMENT.value
    )
    db.add(unpaid_order)
    db.commit()
    db.close()

    # 1. Unpaid order rejected
    res_unpaid = client.get(
        "/orders/order-dl-unpaid/download",
        headers={"Authorization": f"Bearer {buyer_token}"}
    )
    assert res_unpaid.status_code == 400
    assert "must be paid" in res_unpaid.json()["detail"]

    # 2. Other buyer rejected (403)
    other_buyer_token = generate_test_token("stranger-buyer-999", ["customer"])
    res_forbidden = client.get(
        "/orders/order-dl-unpaid/download",
        headers={"Authorization": f"Bearer {other_buyer_token}"}
    )
    assert res_forbidden.status_code == 403


# ============================================================================
# Section 6: Fraud Holds & Admin SLA Release/Refund Tests
# ============================================================================

def test_fraud_rule_triggers_new_seller_high_amount_hold(client, monkeypatch):
    """
    Deterministic rule triggers hold on large transaction for new seller.
    Isolated hold: Does NOT affect seller's other transactions.
    """
    db = TestingSessionLocal()
    order = Order(
        id="order-fraud-1",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-brand-new",
        amount_cents=6000,
        platform_fee_cents=480,
        seller_payout_cents=5520,
        status=OrderStatus.PENDING_PAYMENT.value,
        razorpay_order_id="order_rzp_fraud_1",
    )
    db.add(order)
    db.commit()
    db.close()

    monkeypatch.setattr(razorpay_client, "verify_webhook_signature", lambda b, s, secret=None: True)

    mock_event = {
        "event": "order.paid",
        "payload": {
            "order": {"entity": {"id": "order_rzp_fraud_1", "amount": 6000}},
            "payment": {"entity": {"id": "pay_fraud_1", "order_id": "order_rzp_fraud_1"}},
        }
    }

    client.post("/payments/webhooks/razorpay", content=json.dumps(mock_event).encode("utf-8"), headers={"X-Razorpay-Signature": "valid"})

    db = TestingSessionLocal()
    flagged = db.query(Order).filter(Order.id == "order-fraud-1").first()
    assert flagged is not None
    assert flagged.status == OrderStatus.PAID.value
    assert flagged.hold_status == HoldStatus.HELD.value
    assert flagged.hold_reason is not None
    assert "NEW_SELLER_HIGH_AMOUNT" in flagged.hold_reason
    assert flagged.held_at is not None
    db.close()


def test_admin_list_held_orders_and_release(client, admin_token):
    """Admin surfaces held orders sorted by hold age and releases a hold."""
    db = TestingSessionLocal()
    order = Order(
        id="order-held-admin",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=7500,
        platform_fee_cents=600,
        seller_payout_cents=6900,
        status=OrderStatus.PAID.value,
        hold_status=HoldStatus.HELD.value,
        hold_reason="rule: NEW_SELLER_HIGH_AMOUNT",
        held_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(order)
    db.commit()
    db.close()

    # 1. Admin lists held orders
    res_list = client.get("/payments/orders/held", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_list.status_code == 200
    held_list = res_list.json()
    assert len(held_list) >= 1
    target = next(h for h in held_list if h["id"] == "order-held-admin")
    assert target["hours_held"] >= 2.0
    assert target["sla_breached"] is False

    # 2. Admin releases hold
    res_rel = client.post(
        "/payments/orders/order-held-admin/release",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_rel.status_code == 200
    assert res_rel.json()["hold_status"] == "released"


def test_admin_refund_order_calls_razorpay_and_revokes_entitlement(client, admin_token, monkeypatch):
    """
    Admin refunding an order triggers Razorpay refund AND revokes buyer entitlement.
    Guarantees entitlement-revocation behavior is preserved.
    """
    db = TestingSessionLocal()
    order = Order(
        id="order-refund-test",
        listing_id="l-1",
        listing_version_id="v-1",
        buyer_id="buyer-user-456",
        seller_id="seller-1",
        amount_cents=4000,
        platform_fee_cents=320,
        seller_payout_cents=3680,
        status=OrderStatus.PAID.value,
        hold_status=HoldStatus.HELD.value,
        razorpay_payment_id="pay_rzp_to_refund",
    )
    entitlement = Entitlement(
        order_id="order-refund-test",
        buyer_id="buyer-user-456",
        listing_version_id="v-1",
        status=EntitlementStatus.ACTIVE.value,
    )
    db.add_all([order, entitlement])
    db.commit()
    db.close()

    # Mock Razorpay refund
    refund_called = {}
    def mock_refund(payment_id=None, amount_minor_units=None, notes=None, **kwargs):
        refund_called["payment_id"] = payment_id or kwargs.get("razorpay_payment_id")
        refund_called["amount"] = amount_minor_units
        return {"id": "rfnd_rzp_123", "status": "processed"}

    monkeypatch.setattr(razorpay_client, "refund_payment", mock_refund)

    res = client.post(
        "/payments/orders/order-refund-test/refund",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "refunded"
    assert res.json()["hold_status"] == "refunded"
    assert refund_called["payment_id"] == "pay_rzp_to_refund"

    # Verify entitlement is revoked
    db = TestingSessionLocal()
    revoked_ent = db.query(Entitlement).filter(Entitlement.order_id == "order-refund-test").first()
    assert revoked_ent is not None
    assert revoked_ent.status == EntitlementStatus.REVOKED.value
    assert revoked_ent.revoked_at is not None
    db.close()


# ============================================================================
# Section 7: Seller Dashboard & Connected Route Status Tests
# ============================================================================

def test_seller_payout_dashboard_metrics_and_honest_messaging(client, seller_token):
    """Seller dashboard calculates available vs under review totals with honest messaging."""
    db = TestingSessionLocal()
    order_cleared = Order(
        id="o-cleared", listing_id="l-1", listing_version_id="v-1",
        buyer_id="b1", seller_id="seller-user-123", amount_cents=5000,
        platform_fee_cents=400, seller_payout_cents=4600,
        status=OrderStatus.PAID.value, hold_status=HoldStatus.NONE.value,
    )
    order_held = Order(
        id="o-held", listing_id="l-2", listing_version_id="v-1",
        buyer_id="b2", seller_id="seller-user-123", amount_cents=6000,
        platform_fee_cents=480, seller_payout_cents=5520,
        status=OrderStatus.PAID.value, hold_status=HoldStatus.HELD.value,
    )
    db.add_all([order_cleared, order_held])
    db.commit()
    db.close()

    res = client.get("/payments/seller/dashboard", headers={"Authorization": f"Bearer {seller_token}"})
    assert res.status_code == 200
    data = res.json()

    assert data["available_payout_cents"] == 4600
    assert data["available_payout_usd"] == 46.0
    assert data["under_review_payout_cents"] == 5520
    assert data["under_review_payout_usd"] == 55.2
    assert data["total_sales_count"] == 2

    # Verify honest, non-accusatory messaging
    held_item = next(o for o in data["orders"] if o["id"] == "o-held")
    assert held_item["display_status"] == "under_review"
    assert "under routine security review" in held_item["status_message"]


def test_get_connect_status_reflects_auth_service_payout_enabled(client, seller_token, monkeypatch):
    """
    GET /payments/seller/connect/status reflects Route linked account status,
    proxying/checking against auth-service's payout_enabled as the single source of truth.
    """
    # 1. Not connected
    res_not_connected = client.get(
        "/payments/seller/connect/status",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res_not_connected.status_code == 200
    data_nc = res_not_connected.json()
    assert data_nc["connected"] is False
    assert data_nc["payout_enabled"] is False

    # Register connected profile in DB
    db = TestingSessionLocal()
    profile = SellerPaymentProfile(user_id="seller-user-123", razorpay_account_id="acc_status_test")
    db.add(profile)
    db.commit()
    db.close()

    # 2. Connected but KYC not yet verified in auth-service
    orig_get = httpx.Client.get
    def mock_get(self, url, *args, **kwargs):
        if "/kyc/seller/" in str(url):
            class MockResp:
                status_code = 200
                def json(self): return {"user_id": "seller-user-123", "payout_enabled": False}
            return MockResp()
        return orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    res_pending = client.get(
        "/payments/seller/connect/status",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res_pending.status_code == 200
    data_pending = res_pending.json()
    assert data_pending["connected"] is True
    assert data_pending["razorpay_account_id"] == "acc_status_test"
    assert data_pending["payout_enabled"] is False

    # 3. Connected and KYC verified in auth-service
    def mock_get_verified(self, url, *args, **kwargs):
        if "/kyc/seller/" in str(url):
            class MockResp:
                status_code = 200
                def json(self): return {"user_id": "seller-user-123", "payout_enabled": True}
            return MockResp()
        return orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", mock_get_verified)
    res_verified = client.get(
        "/payments/seller/connect/status",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res_verified.status_code == 200
    data_ver = res_verified.json()
    assert data_ver["connected"] is True
    assert data_ver["payout_enabled"] is True


def test_order_isolated_hold_does_not_affect_other_orders(client, seller_token):
    """
    PER-ORDER FRAUD HOLD ISOLATION:
    Holding one order does NOT freeze the seller's account or other orders.
    Ordinary unflagged orders remain cleared and available for payout.
    """
    db = TestingSessionLocal()
    order_normal = Order(
        id="ord-clean-1", listing_id="l-1", listing_version_id="v-1",
        buyer_id="b-clean", seller_id="seller-user-123", amount_cents=3000,
        platform_fee_cents=240, seller_payout_cents=2760,
        status=OrderStatus.PAID.value, hold_status=HoldStatus.NONE.value,
    )
    order_held = Order(
        id="ord-held-1", listing_id="l-2", listing_version_id="v-1",
        buyer_id="b-flagged", seller_id="seller-user-123", amount_cents=10000,
        platform_fee_cents=800, seller_payout_cents=9200,
        status=OrderStatus.PAID.value, hold_status=HoldStatus.HELD.value,
        hold_reason="rule: NEW_SELLER_HIGH_AMOUNT",
    )
    db.add_all([order_normal, order_held])
    db.commit()
    db.close()

    res = client.get("/payments/seller/dashboard", headers={"Authorization": f"Bearer {seller_token}"})
    assert res.status_code == 200
    data = res.json()

    # Normal order payout remains completely available
    assert data["available_payout_cents"] == 2760
    assert data["available_payout_usd"] == 27.60

    # Held order payout is segregated as under review
    assert data["under_review_payout_cents"] == 9200
    assert data["under_review_payout_usd"] == 92.00

    # Ensure no account-wide freeze
    clean_item = next(o for o in data["orders"] if o["id"] == "ord-clean-1")
    assert clean_item["display_status"] == "cleared"
    assert "Funds cleared" in clean_item["status_message"]


def test_test_confirm_order_and_entitlement_creation(client, buyer_token):
    """
    Simulated test-mode payment confirmation endpoint transitions order to PAID,
    creates Entitlement record, and enables secure download.
    """
    db = TestingSessionLocal()
    order = Order(
        id="ord-test-confirm",
        listing_id="lst-quick-1",
        listing_version_id="ver-quick-1",
        buyer_id="buyer-user-456",
        seller_id="seller-user-123",
        amount_cents=1500,
        platform_fee_cents=120,
        seller_payout_cents=1380,
        status=OrderStatus.PENDING_PAYMENT.value,
    )
    db.add(order)
    db.commit()
    db.close()

    # Confirm order in test environment
    confirm_res = client.post(
        "/orders/ord-test-confirm/test-confirm",
        headers={"Authorization": f"Bearer {buyer_token}"}
    )
    assert confirm_res.status_code == 200
    assert confirm_res.json()["status"] == "paid"

    # Verify Entitlement exists
    db = TestingSessionLocal()
    ent = db.query(Entitlement).filter(Entitlement.order_id == "ord-test-confirm").first()
    assert ent is not None
    assert ent.buyer_id == "buyer-user-456"
    assert ent.status == EntitlementStatus.ACTIVE.value
    db.close()

    # Verify download succeeds now that order is paid
    dl_res = client.get(
        "/orders/ord-test-confirm/download",
        headers={"Authorization": f"Bearer {buyer_token}"}
    )
    assert dl_res.status_code == 200
    assert "download_url" in dl_res.json()


def test_test_confirm_refused_and_fails_closed_in_production(monkeypatch):
    """
    FAIL-CLOSED PRODUCTION SAFETY:
    When ENVIRONMENT='production', lifespan fails closed if test-confirm is present.
    """
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "RAZORPAY_KEY_ID", "rzp_live_" + "a" * 20)
    monkeypatch.setattr(settings, "RAZORPAY_KEY_SECRET", "sec_" + "b" * 32)
    monkeypatch.setattr(settings, "RAZORPAY_WEBHOOK_SECRET", "whsec_" + "c" * 32)
    from src.main import lifespan

    mock_app = MagicMock()
    mock_route = MagicMock()
    mock_route.path = "/orders/{order_id}/test-confirm"
    mock_app.routes = [mock_route]

    with pytest.raises(RuntimeError, match="SECURITY FATAL"):
        async def run_lifespan():
            async with lifespan(mock_app):
                pass
        asyncio.run(run_lifespan())


def test_check_entitlement_access_control_and_verification(client, buyer_token):
    """
    Verifies hardened anti-enumeration and entitlement check:
    1. Unauthenticated probing -> 401
    2. Invalid X-Internal-Secret -> 401
    3. Valid X-Internal-Secret -> 200 (True when paid, False when not)
    4. Buyer checking own entitlement -> 200
    5. Buyer probing different user's entitlement -> 401
    """
    db = TestingSessionLocal()
    paid_order = Order(
        id="order-entitled-test",
        listing_id="listing-entitled-99",
        listing_version_id="version-v1",
        buyer_id="buyer-user-456",
        seller_id="seller-user-123",
        amount_cents=5000,
        platform_fee_cents=400,
        seller_payout_cents=4600,
        status=OrderStatus.PAID.value,
    )
    db.add(paid_order)
    db.commit()
    db.close()

    # 1. Unauthenticated probing fails closed (401)
    res_probe = client.get("/orders/check-entitlement/buyer-user-456/listing-entitled-99")
    assert res_probe.status_code == 401

    # 2. Invalid internal secret fails closed (401)
    res_bad_secret = client.get(
        "/orders/check-entitlement/buyer-user-456/listing-entitled-99",
        headers={"X-Internal-Secret": "wrong-secret"},
    )
    assert res_bad_secret.status_code == 401

    # 3. Valid X-Internal-Secret succeeds with has_entitlement=True
    res_internal = client.get(
        "/orders/check-entitlement/buyer-user-456/listing-entitled-99",
        headers={"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET},
    )
    assert res_internal.status_code == 200
    data = res_internal.json()
    assert data["has_entitlement"] is True
    assert data["order_id"] == "order-entitled-test"
    assert data["listing_version_id"] == "version-v1"

    # 4. Valid X-Internal-Secret on unpurchased listing -> has_entitlement=False
    res_unpurchased = client.get(
        "/orders/check-entitlement/buyer-user-456/non-existent-listing",
        headers={"X-Internal-Secret": settings.INTERNAL_SERVICE_SECRET},
    )
    assert res_unpurchased.status_code == 200
    assert res_unpurchased.json()["has_entitlement"] is False

    # 5. Buyer self-check via JWT succeeds
    res_self = client.get(
        "/orders/check-entitlement/buyer-user-456/listing-entitled-99",
        headers={"Authorization": f"Bearer {buyer_token}"},
    )
    assert res_self.status_code == 200
    assert res_self.json()["has_entitlement"] is True

    # 6. Another buyer attempting to probe this buyer's purchase fails closed (401)
    other_buyer_token = generate_test_token("another-unrelated-buyer", ["customer"])
    res_other = client.get(
        "/orders/check-entitlement/buyer-user-456/listing-entitled-99",
        headers={"Authorization": f"Bearer {other_buyer_token}"},
    )
    assert res_other.status_code == 401


def test_seller_connect_and_payouts_alias_routes(client, seller_token, monkeypatch):
    """Verifies that /seller/connect/* and /seller/payouts alias routes work identically to /payments/seller/*."""
    monkeypatch.setattr(
        razorpay_client,
        "create_linked_account",
        lambda user_id, email, business_name=None: "acc_alias_123"
    )

    headers = {"Authorization": f"Bearer {seller_token}"}

    # Connect status alias
    res_stat = client.get("/seller/connect/status", headers=headers)
    assert res_stat.status_code == 200
    assert "payout_enabled" in res_stat.json()

    # Connect onboard alias
    res_onboard = client.post("/seller/connect/onboard", headers=headers)
    assert res_onboard.status_code == 200
    assert "onboarding_url" in res_onboard.json()

    # Seller dashboard / payouts alias
    res_dash = client.get("/seller/dashboard", headers=headers)
    assert res_dash.status_code == 200
    data_dash = res_dash.json()
    assert "available_payout_usd" in data_dash
    assert "available_usd" in data_dash

    res_payouts = client.get("/seller/payouts", headers=headers)
    assert res_payouts.status_code == 200
    assert res_payouts.json() == data_dash
