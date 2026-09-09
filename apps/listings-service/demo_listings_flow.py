"""
softXchange listings-service: End-to-End Milestone Verification
Validates the complete listing lifecycle across all 5 prompts:
- Prompt 1: Authenticated CRUD with local RS256 token verification & live version immutability
- Prompt 2: Submission to scan-service intake over HTTP & async polling
- Prompt 3: Strict publish gate (Fail-closed KYC check with distinct unverified vs outage states & lazy self-healing)
- Prompt 4: Seller package management dashboard, redacted findings & soft withdrawal
- Prompt 5: Public marketplace catalog browse, multi-criteria filtering & terminal-style vetted badge
"""

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

# Ensure listings-service is on sys.path
SERVICE_ROOT = Path(__file__).resolve().parent
if str(SERVICE_ROOT) in sys.path:
    sys.path.remove(str(SERVICE_ROOT))
sys.path.insert(0, str(SERVICE_ROOT))
sys.modules.pop("src", None)
for k in list(sys.modules.keys()):
    if k.startswith("src."):
        sys.modules.pop(k, None)

from src.main import app
from src.database import SessionLocal, init_db
from src.auth import jwks_manager
from src.gate import PayoutCheckResult
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus

client = TestClient(app)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_step(title: str):
    print(f"\n{CYAN}{BOLD}==> {title}{RESET}")


def print_success(detail: str):
    print(f"  {GREEN}[PASS]{RESET} {detail}")


def print_info(detail: str):
    print(f"  {YELLOW}[INFO]{RESET} {detail}")


# Generate demo RSA keypair
demo_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
demo_public_key = demo_private_key.public_key()
DEMO_KID = "softxchange-demo-key"
jwks_manager.set_key_for_testing(DEMO_KID, demo_public_key)


def create_token(user_id: str, roles: list) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "roles": roles,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=2)).timestamp()),
    }
    pem_priv = demo_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_priv, algorithm="RS256", headers={"kid": DEMO_KID})


def run_demo():
    init_db()
    print(f"\n{BOLD}softXchange — Listings Service End-to-End Milestone Verification{RESET}")
    print("=" * 70)

    seller_1_id = "seller-corp-alpha"
    seller_2_id = "seller-corp-beta"
    customer_id = "customer-buyer-42"

    seller_token = create_token(seller_1_id, ["seller"])
    other_seller_token = create_token(seller_2_id, ["seller"])
    customer_token = create_token(customer_id, ["customer"])

    # ------------------------------------------------------------------------
    # Prompt 1: Core Listing Model + Authenticated CRUD + Immutability
    # ------------------------------------------------------------------------
    print_step("Prompt 1: Role Enforcement & Draft Listing Creation")
    
    # 1a. Customer role rejection
    resp = client.post("/listings", headers={"Authorization": f"Bearer {customer_token}"}, json={
        "title": "Unauthorized Listing", "description": "Should fail", "price_cents": 1000, "category": "security"
    })
    assert resp.status_code == 403
    print_success("Customer rejected from creating listings (403 Forbidden)")

    # 1b. Seller creates draft
    create_resp = client.post("/listings", headers={"Authorization": f"Bearer {seller_token}"}, json={
        "title": "Cloud Sentry CLI",
        "description": "High-performance cryptographic secret audit tool for AWS and GCP infrastructure.",
        "price_cents": 4900,
        "category": "security",
        "version_label": "1.0.0"
    })
    assert create_resp.status_code == 201
    listing = create_resp.json()
    listing_id = listing["id"]
    assert listing["price_cents"] == 4900
    assert listing["price_usd"] == 49.0
    assert listing["status"] == "draft"
    print_success(f"Draft listing created: '{listing['title']}' (ID: {listing_id}, Price: $49.00)")

    # 1c. Seller isolation
    unauth_edit = client.patch(f"/listings/{listing_id}", headers={"Authorization": f"Bearer {other_seller_token}"}, json={
        "title": "Hijacked"
    })
    assert unauth_edit.status_code == 403
    print_success("Seller isolation enforced: Non-owner blocked from modifying draft (403)")

    # ------------------------------------------------------------------------
    # Prompt 2: Submission to Scan-Service over HTTP
    # ------------------------------------------------------------------------
    print_step("Prompt 2: Version Package Intake & Scan Dispatch")

    # Mock scan-service intake call
    from src.routes.listings import scanner_client
    scanner_client.submit_version = lambda listing_id, version, source_type="upload", git_url=None, package_content=None: {
        "status": "enqueued", "scan_job_id": "scan-job-001"
    }

    sub_resp = client.post(f"/listings/{listing_id}/versions", headers={"Authorization": f"Bearer {seller_token}"}, json={
        "version_label": "1.0.0",
        "source_type": "upload",
        "package_content": "UEsDBAoAAAAIA..."
    })
    assert sub_resp.status_code == 202
    sub_data = sub_resp.json()
    assert sub_data["scan_status"] == "pending_scan"
    assert sub_data["scan_job_id"] == "scan-job-001"
    print_success(f"Version 1.0.0 enqueued for security scanning (Job ID: {sub_data['scan_job_id']})")

    # ------------------------------------------------------------------------
    # Prompt 3: Strict Publish Gate (Fail-Closed KYC & Distinct Outage States)
    # ------------------------------------------------------------------------
    print_step("Prompt 3: Publish Gate & Distinct Fail-Closed State Machine")

    version_id = sub_data["id"]

    # Scenario 3A: Scan passed, but seller KYC payout is NOT enabled
    scanner_client.query_status = lambda listing_id, version: {
        "scan_status": "passed", "severity_counts": {"critical": 0, "high": 0}, "findings": []
    }
    from src.gate import evaluate_publish_gate
    import src.routes.listings as listings_routes

    # Monkeypatch payout check to return PAYOUT_DISABLED
    # pyrefly: ignore [bad-assignment]
    listings_routes.evaluate_publish_gate = lambda listing, version, db: evaluate_publish_gate(listing, version, db, payout_override=PayoutCheckResult.PAYOUT_DISABLED)

    status_resp = client.get(f"/listings/{listing_id}/versions/{version_id}/status", headers={"Authorization": f"Bearer {seller_token}"})
    assert status_resp.status_code == 200
    
    # Check listing status in DB
    db = SessionLocal()
    cur_listing = db.query(Listing).filter(Listing.id == listing_id).first()
    assert cur_listing is not None
    assert cur_listing.status == "scan_passed_awaiting_kyc"
    print_success("Gate Check A: Scan passed + KYC pending -> status: 'scan_passed_awaiting_kyc'")
    print_info(f"Status message: '{cur_listing.status_message}'")

    # Scenario 3B: Scan passed, but auth-service suffers a 503 outage
    # pyrefly: ignore [bad-assignment]
    listings_routes.evaluate_publish_gate = lambda listing, version, db: evaluate_publish_gate(listing, version, db, payout_override=PayoutCheckResult.SYSTEM_UNAVAILABLE)
    client.get(f"/listings/{listing_id}/versions/{version_id}/status", headers={"Authorization": f"Bearer {seller_token}"})
    db.refresh(cur_listing)
    assert cur_listing.status == "scan_passed_verification_unavailable"
    print_success("Gate Check B: Scan passed + Auth outage -> status: 'scan_passed_verification_unavailable'")
    print_info(f"Notice: Distinct transient state avoids falsely accusing seller of lacking KYC!")

    # Scenario 3C: Seller completes KYC in auth-service -> Lazy Self-Healing
    print_step("Prompt 3 & 4: Lazy Self-Healing on Seller Dashboard Visit")
    import src.gate as gate_mod
    gate_mod.check_seller_payout_status = lambda seller_id, timeout=4.0: PayoutCheckResult.PAYOUT_ENABLED
    listings_routes.evaluate_publish_gate = evaluate_publish_gate

    # When seller views their dashboard GET /listings/mine, sync_seller_kyc triggers automatically
    mine_resp = client.get("/listings/mine", headers={"Authorization": f"Bearer {seller_token}"})
    assert mine_resp.status_code == 200
    mine_items = mine_resp.json()
    my_listing = next(i for i in mine_items if i["id"] == listing_id)
    assert my_listing["status"] == "live"
    assert my_listing["next_action"] == "listing is active"
    print_success(f"Self-Healing Triggered: Listing promoted to 'live' without requiring a re-scan!")

    # ------------------------------------------------------------------------
    # Prompt 1 (Revisited): Live Version Immutability on Edit
    # ------------------------------------------------------------------------
    print_step("Prompt 1 (Hardening): Version Immutability Protection on Live Listing")
    edit_live_resp = client.patch(f"/listings/{listing_id}", headers={"Authorization": f"Bearer {seller_token}"}, json={
        "price_cents": 5900
    })
    assert edit_live_resp.status_code == 200
    
    # Check that existing live version was NOT mutated, and a new draft version was prepared
    versions = db.query(ListingVersion).filter(ListingVersion.listing_id == listing_id).order_by(ListingVersion.created_at.asc()).all()
    assert len(versions) >= 2
    version_labels = [v.version_label for v in versions]
    assert "1.0.0" in version_labels
    assert "1.0.1" in version_labels
    assert any(v.version_label == "1.0.0" and v.scan_status == "passed" for v in versions)
    print_success("Live version immutability guaranteed: Approved v1.0.0 untouched; new draft v1.0.1 created.")

    # ------------------------------------------------------------------------
    # Prompt 5: Public Marketplace Catalog & Vetted Badges
    # ------------------------------------------------------------------------
    print_step("Prompt 5: Public Marketplace Catalog & Verified Badge")
    
    # Buyer browses public catalog
    cat_resp = client.get("/listings?category=security&max_price_cents=6000")
    assert cat_resp.status_code == 200
    catalog = cat_resp.json()
    assert len(catalog) >= 1
    vetted_item = next(c for c in catalog if c["id"] == listing_id)
    assert vetted_item["status"] == "live"
    assert vetted_item["price_cents"] == 5900
    print_success(f"Public catalog browse returned live verified package '{vetted_item['title']}'")

    # Buyer inspects listing detail view
    detail_resp = client.get(f"/listings/{listing_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["vetted"] is True
    assert "Scanned — 0 critical findings" in detail["badge"]
    print_success(f"Vetted Security Badge rendered: [{detail['badge']}]")

    # ------------------------------------------------------------------------
    # Prompt 4: Soft-Deletion / Withdrawal
    # ------------------------------------------------------------------------
    print_step("Prompt 4: Seller Withdrawal (Immediate Catalog Removal)")
    withdraw_resp = client.delete(f"/listings/{listing_id}", headers={"Authorization": f"Bearer {seller_token}"})
    assert withdraw_resp.status_code == 200
    print_success("Seller withdrew package from publication")

    # Confirm it disappeared immediately from public browse
    cat_after = client.get("/listings").json()
    assert all(c["id"] != listing_id for c in cat_after)
    print_success("Withdrawn listing instantly removed from public catalog view")

    # Anonymous user gets 404 for withdrawn listing
    assert client.get(f"/listings/{listing_id}").status_code == 404
    print_success("Public access to withdrawn package rejected with 404 Not Found")

    db.close()
    print("\n" + "=" * 70)
    print(f"{GREEN}{BOLD}ALL LISTINGS-SERVICE MILESTONE CRITERIA VERIFIED SUCCESSFULLY!{RESET}\n")


if __name__ == "__main__":
    run_demo()
