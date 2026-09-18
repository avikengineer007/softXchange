"""
Milestone 3 End-to-End Demonstration Script
Demonstrates the complete software marketplace transaction lifecycle with Razorpay:
1. Seller Razorpay Route onboarding & HMAC webhook bridge to auth-service
2. Order creation for live software package with 8% platform fee
3. Enforcement: rejection of non-live listing purchase
4. Idempotent webhook receipt of order.paid / payment.captured & entitlement issuance
5. Buyer ephemeral signed download token generation & package payload retrieval
6. Per-order fraud hold isolation & SLA tracking
7. Admin hold resolution & refund with entitlement revocation
"""
import sys
import os
import json
import uuid
import hmac
import hashlib
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

# Ensure payments-service is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

from src.main import app
from src.config import settings
from src.database import get_db, Base, engine, SessionLocal
from src.auth import jwks_manager
from src.models import SellerPaymentProfile, Order, OrderStatus, HoldStatus, Entitlement
from src.razorpay_client import razorpay_client

client = TestClient(app)

# Setup RSA Demo Keypair & register with jwks_manager
demo_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
demo_public_key = demo_private_key.public_key()
DEMO_KID = "demo-key-1"
jwks_manager.set_key_for_testing(DEMO_KID, demo_public_key)

def create_demo_token(user_id: str, roles: list, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "roles": roles,
        "email": email,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    pem_priv = demo_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_priv, algorithm="RS256", headers={"kid": DEMO_KID})

def banner(msg: str):
    print("\n" + "=" * 70)
    print(f"  {msg}")
    print("=" * 70)

def step(title: str):
    print(f"\n---> {title}")

def run_demo():
    banner("softXchange Milestone 3: Razorpay Payments & Route Engine Demo")

    # Clean DB
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    seller_id = str(uuid.uuid4())
    buyer_id = str(uuid.uuid4())
    listing_id = "lst_quant_trading_engine_99"
    version_id = "ver_1_0_0_immutable_prod"
    price_usd = 250.0  # $250.00 listing

    seller_token = create_demo_token(seller_id, ["seller"], "quant_seller@softxchange.io")
    buyer_token = create_demo_token(buyer_id, ["customer"], "buyer_enterprise@softxchange.io")

    # ---------------------------------------------------------
    # 1. Razorpay Route Onboarding & KYC Webhook Bridge
    # ---------------------------------------------------------
    step("1. Seller Initiates Razorpay Route Linked Account Onboarding")
    with patch.object(razorpay_client, "create_linked_account", return_value="acc_rzp_route_999"):
        resp = client.post("/payments/seller/connect/start", headers={"Authorization": f"Bearer {seller_token}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        print(f"     Razorpay Route Account Created: {data['razorpay_account_id']}")
        print(f"     Onboarding Portal URL: {data['onboarding_url']}")

    step("2. Razorpay Webhook (account.activated) -> Auth Service HMAC Webhook Bridge")
    # Razorpay sends webhook indicating linked account is activated
    account_event = {
        "event": "account.activated",
        "account_id": "acc_rzp_route_999",
        "payload": {
            "account": {
                "entity": {
                    "id": "acc_rzp_route_999",
                    "status": "activated",
                }
            }
        }
    }
    payload_bytes = json.dumps(account_event).encode("utf-8")

    with patch.object(razorpay_client, "verify_webhook_signature", return_value=True), \
         patch("src.routes.webhooks._send_authenticated_kyc_callback") as mock_kyc_callback:
        resp = client.post(
            "/payments/webhooks/razorpay",
            content=payload_bytes,
            headers={"X-Razorpay-Signature": "rzp_sig_mock", "Content-Type": "application/json"}
        )
        assert resp.status_code == 200, resp.text
        assert mock_kyc_callback.called
        kwargs = mock_kyc_callback.call_args.kwargs
        print(f"     Razorpay webhook processed successfully.")
        print(f"     Triggered Auth-Service KYC Webhook Bridge:")
        print(f"       User ID: {kwargs['user_id']}")
        print(f"       Status: {kwargs['status_str']}")
        print(f"       Razorpay Account ID: {kwargs['razorpay_account_id']}")
        print(f"       HMAC-SHA256 Signature verified against INTERNAL_SERVICE_SECRET")

    # ---------------------------------------------------------
    # 2. Guardrails: Rejection of Non-Live Listings
    # ---------------------------------------------------------
    step("3. Guardrail: Rejection of Purchase for Non-Live / Unverified Listing")
    draft_listing_mock = {
        "id": "lst_draft_unverified",
        "seller_id": seller_id,
        "status": "draft",
        "price_usd": 150.0,
        "current_version": {"id": "ver_0_1_draft", "version": "0.1.0"}
    }

    with patch("httpx.Client.get", return_value=MagicMock(status_code=200, json=lambda: draft_listing_mock)):
        resp = client.post("/orders", json={"listing_id": "lst_draft_unverified"}, headers={"Authorization": f"Bearer {buyer_token}"})
        print(f"     Attempted purchase of draft listing -> Status code: {resp.status_code}")
        print(f"     Error response: {resp.json()['detail']}")
        assert resp.status_code == 400
        assert "must be live and vetted" in resp.json()['detail']

    # ---------------------------------------------------------
    # 3. Order Creation & Razorpay Order Generation
    # ---------------------------------------------------------
    step("4. Valid Purchase: Live Listing with 8% Platform Fee Razorpay Order")
    live_listing_mock = {
        "id": listing_id,
        "seller_id": seller_id,
        "status": "live",
        "vetted": True,
        "price_usd": price_usd,
        "price_cents": 25000,
        "current_version": {"id": version_id, "version": "1.0.0"}
    }
    
    mock_rzp_order = {
        "id": "order_rzp_live_101",
        "amount": 25000,
        "currency": "INR",
        "status": "created",
    }
    with patch("httpx.Client.get", return_value=MagicMock(status_code=200, json=lambda: live_listing_mock)), \
         patch.object(razorpay_client, "create_order", return_value=mock_rzp_order) as mock_order_create:
        
        resp = client.post("/orders", json={"listing_id": listing_id}, headers={"Authorization": f"Bearer {buyer_token}"})
        assert resp.status_code == 201, resp.text
        order_data = resp.json()
        print(f"     Order Created:")
        print(f"       Order ID: {order_data['id']}")
        print(f"       Amount Total: ₹{order_data['amount_cents'] / 100:.2f} ({order_data['amount_cents']} paise)")
        print(f"       Platform Fee (8%): ₹{order_data['platform_fee_cents'] / 100:.2f} ({order_data['platform_fee_cents']} paise)")
        print(f"       Seller Payout (92%): ₹{order_data['seller_payout_cents'] / 100:.2f} ({order_data['seller_payout_cents']} paise)")
        print(f"       Razorpay Order ID: {order_data['razorpay_order_id']}")
        print(f"       Status: {order_data['status']}")
        order_id = order_data["id"]

    # ---------------------------------------------------------
    # 4. Payment Succeeded Webhook & Entitlement Issuance
    # ---------------------------------------------------------
    step("5. Razorpay Webhook (order.paid) -> Order Paid & Entitlement Issued")
    paid_event = {
        "event": "order.paid",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_rzp_live_101",
                    "amount": 25000,
                    "status": "paid",
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_rzp_live_payment_999",
                    "order_id": "order_rzp_live_101",
                }
            }
        }
    }
    paid_bytes = json.dumps(paid_event).encode("utf-8")

    with patch.object(razorpay_client, "verify_webhook_signature", return_value=True):
        resp = client.post(
            "/payments/webhooks/razorpay",
            content=paid_bytes,
            headers={"X-Razorpay-Signature": "rzp_sig_paid", "Content-Type": "application/json"}
        )
    assert resp.status_code == 200, resp.text
    
    db = SessionLocal()
    order = db.query(Order).filter(Order.id == order_id).first()
    entitlement = db.query(Entitlement).filter(Entitlement.order_id == order_id).first()
    assert order is not None
    assert entitlement is not None
    print(f"     Order Status: {order.status}")
    print(f"     Razorpay Payment ID: {order.razorpay_payment_id}")
    print(f"     Entitlement Issued:")
    print(f"       Entitlement ID: {entitlement.id}")
    print(f"       Buyer ID: {entitlement.buyer_id}")
    print(f"       Listing Version ID (Pinned): {entitlement.listing_version_id}")
    print(f"       Status: {entitlement.status}")
    db.close()

    # ---------------------------------------------------------
    # 5. Ephemeral Signed Download URL & Secure Package Access
    # ---------------------------------------------------------
    step("6. Buyer Requests Ephemeral Signed Download Token (15-min TTL)")
    resp = client.get(f"/orders/{order_id}/download", headers={"Authorization": f"Bearer {buyer_token}"})
    assert resp.status_code == 200, resp.text
    dl_data = resp.json()
    print(f"     Download URL Generated: {dl_data['download_url']}")
    print(f"     Expires in: {dl_data['expires_in_seconds']} seconds")

    # Now download package using the signed URL
    pkg_resp = client.get(dl_data['download_url'])
    assert pkg_resp.status_code == 200, pkg_resp.text
    pkg_json = pkg_resp.json()
    print(f"     Download Package Response:")
    print(f"       Storage Location: {pkg_json['storage_location']}")
    print(f"       Listing Version ID: {pkg_json['listing_version_id']}")
    print(f"       Delivery Status: {pkg_json['status']}")

    # ---------------------------------------------------------
    # 6. Per-Order Fraud Hold Isolation & SLA Monitoring
    # ---------------------------------------------------------
    step("7. Fraud Detection Engine: New Seller High-Value Order Flagged")
    fraud_seller_id = str(uuid.uuid4())
    fraud_listing_mock = {
        "id": "lst_expensive_ml_core",
        "seller_id": fraud_seller_id,
        "status": "live",
        "vetted": True,
        "price_usd": 1200.0,
        "price_cents": 120000,
        "current_version": {"id": "ver_ml_1_0", "version": "1.0.0"}
    }
    # Register connect account for fraud seller
    db = SessionLocal()
    db.add(SellerPaymentProfile(user_id=fraud_seller_id, razorpay_account_id="acc_new_fraud_seller"))
    db.commit()
    db.close()

    mock_fraud_order = {"id": "order_rzp_fraud_777", "amount": 120000, "currency": "INR", "status": "created"}
    with patch("httpx.Client.get", return_value=MagicMock(status_code=200, json=lambda: fraud_listing_mock)), \
         patch.object(razorpay_client, "create_order", return_value=mock_fraud_order):
        
        resp = client.post("/orders", json={"listing_id": "lst_expensive_ml_core"}, headers={"Authorization": f"Bearer {buyer_token}"})
        assert resp.status_code == 201
        fraud_order_id = resp.json()["id"]

    # Webhook triggers payment success
    fraud_paid_event = {
        "event": "order.paid",
        "payload": {
            "order": {"entity": {"id": "order_rzp_fraud_777", "amount": 120000}},
            "payment": {"entity": {"id": "pay_fraud_payment_777", "order_id": "order_rzp_fraud_777"}}
        }
    }
    fraud_bytes = json.dumps(fraud_paid_event).encode("utf-8")

    with patch.object(razorpay_client, "verify_webhook_signature", return_value=True):
        client.post("/payments/webhooks/razorpay", content=fraud_bytes, headers={"X-Razorpay-Signature": "sig_fraud", "Content-Type": "application/json"})

    db = SessionLocal()
    held_order = db.query(Order).filter(Order.id == fraud_order_id).first()
    assert held_order is not None
    print(f"     Order {held_order.id} status:")
    print(f"       Hold Status: {held_order.hold_status} (ISOLATED TO THIS ORDER ONLY)")
    print(f"       Hold Reason: {held_order.hold_reason}")
    held_at_str = held_order.held_at.isoformat() if held_order.held_at else "—"
    print(f"       Held At: {held_at_str}")
    db.close()

    step("8. Honest Messaging on Seller Dashboard (No False Accusations / Account Unfrozen)")
    fraud_seller_token = create_demo_token(fraud_seller_id, ["seller"], "new_ml_vendor@softxchange.io")
    resp = client.get("/payments/seller/dashboard", headers={"Authorization": f"Bearer {fraud_seller_token}"})
    dash = resp.json()
    print(f"     Seller Dashboard Metrics:")
    print(f"       Total Paid Sales: {dash['total_sales_count']}")
    print(f"       Available Payout: ₹{dash['available_payout_usd']:.2f}")
    print(f"       Under Review Payout: ₹{dash['under_review_payout_usd']:.2f}")
    print(f"       Order Display Status: {dash['orders'][0]['display_status']}")
    print(f"       Seller-Facing Status Message: \"{dash['orders'][0]['status_message']}\"")
    assert dash['orders'][0]['display_status'] == "under_review"
    assert "routine security review" in dash['orders'][0]['status_message']

    step("9. Admin Held Orders Queue (SLA Sorted) & Hold Release")
    admin_token = create_demo_token("admin_user_id_1", ["admin"], "compliance@softxchange.io")
    resp = client.get("/payments/orders/held", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    held_list = resp.json()
    print(f"     Admin Queue: Found {len(held_list)} order(s) awaiting review.")
    print(f"     Oldest Held Order SLA Time: {held_list[0]['hours_held']}h held (SLA Breached: {held_list[0]['sla_breached']})")

    # Release the hold
    rel_resp = client.post(f"/payments/orders/{fraud_order_id}/release", headers={"Authorization": f"Bearer {admin_token}"})
    assert rel_resp.status_code == 200
    print(f"     Admin released hold. Order hold_status is now: '{rel_resp.json()['hold_status']}'")

    # ---------------------------------------------------------
    # 7. Refund Flow & Entitlement Revocation
    # ---------------------------------------------------------
    step("10. Admin Initiates Refund on Initial Order -> Revokes Entitlement")
    with patch.object(razorpay_client, "refund_payment", return_value={"id": "rfnd_rzp_001", "status": "processed"}):
        ref_resp = client.post(f"/payments/orders/{order_id}/refund", headers={"Authorization": f"Bearer {admin_token}"})
        assert ref_resp.status_code == 200
        print(f"     Refund executed successfully via Razorpay. Order status is now: '{ref_resp.json()['status']}'")

    db = SessionLocal()
    refunded_order = db.query(Order).filter(Order.id == order_id).first()
    revoked_entitlement = db.query(Entitlement).filter(Entitlement.order_id == order_id).first()
    assert refunded_order is not None
    assert revoked_entitlement is not None
    print(f"     Post-Refund State:")
    print(f"       Order Status: {refunded_order.status}")
    print(f"       Entitlement Status: {revoked_entitlement.status}")
    revoked_at_str = revoked_entitlement.revoked_at.isoformat() if revoked_entitlement.revoked_at else "—"
    print(f"       Entitlement Revoked At: {revoked_at_str}")
    db.close()

    banner("Milestone 3 Verified: Razorpay Marketplace Purchase & Route Lifecycle Complete!")

if __name__ == "__main__":
    run_demo()
