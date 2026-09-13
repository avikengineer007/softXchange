import os
import sys
import uuid
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

# Ensure apps/listings-service is on sys.path
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
from src.database import Base, get_db
from src.config import settings
from src.auth import jwks_manager
from src.gate import PayoutCheckResult
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus

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
TEST_KID = "test-key-id-1"

# Inject into JWKS manager test hook
jwks_manager.set_key_for_testing(TEST_KID, test_public_key)


def generate_test_token(user_id: str, roles: list, kid: str = TEST_KID, expired: bool = False) -> str:
    """Helper to generate signed RS256 test JWT."""
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
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seller_token():
    return generate_test_token("seller-user-123", ["seller"])


@pytest.fixture
def customer_token():
    return generate_test_token("customer-user-456", ["customer"])


# ============================================================================
# Prompt 1: Core Listing Model & Auth Integration Tests
# ============================================================================

def test_create_listing_requires_authentication(client):
    """Unauthenticated call to POST /listings should return 401."""
    res = client.post("/listings", json={
        "title": "Unauth Tool",
        "description": "Test description",
        "price_cents": 1000,
        "category": "developer-tools"
    })
    assert res.status_code == 401


def test_create_listing_requires_seller_role(client, customer_token):
    """Customer role cannot create listings (403)."""
    res = client.post(
        "/listings",
        headers={"Authorization": f"Bearer {customer_token}"},
        json={
            "title": "Customer Tool",
            "description": "Should fail with forbidden",
            "price_cents": 1500,
            "category": "developer-tools",
        }
    )
    assert res.status_code == 403
    assert "Seller role required" in res.json()["detail"]


def test_create_listing_seller_success(client, seller_token):
    """Seller creates draft listing with integer price_cents and initial version."""
    res = client.post(
        "/listings",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "title": "Cloud Sentry CLI",
            "description": "Enterprise cloud security scanner tool.",
            "price_cents": 4900,
            "category": "security",
            "version_label": "1.0.0"
        }
    )
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == "Cloud Sentry CLI"
    assert data["price_cents"] == 4900
    assert data["price_usd"] == 49.0
    assert data["status"] == "draft"
    assert data["seller_id"] == "seller-user-123"


def test_update_listing_owner_only(client, seller_token):
    """Only listing owner (or admin) can update listing fields."""
    # Create listing with seller-user-123
    create_res = client.post(
        "/listings",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "title": "Owner Test",
            "description": "Testing ownership restrictions",
            "price_cents": 2500,
            "category": "developer-tools",
        }
    )
    listing_id = create_res.json()["id"]

    # Different seller tries to edit
    other_seller_token = generate_test_token("seller-user-999", ["seller"])
    update_res = client.patch(
        f"/listings/{listing_id}",
        headers={"Authorization": f"Bearer {other_seller_token}"},
        json={"title": "Hacked Title"}
    )
    assert update_res.status_code == 403

    # Owner edits successfully
    owner_update = client.patch(
        f"/listings/{listing_id}",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"title": "Updated Title", "price_cents": 2900}
    )
    assert owner_update.status_code == 200
    assert owner_update.json()["title"] == "Updated Title"
    assert owner_update.json()["price_cents"] == 2900


def test_edit_live_listing_creates_new_draft_version(client, seller_token):
    """
    Version Immutability:
    Editing a listing that has a live version creates a new draft version
    and preserves the existing live listing intact.
    """
    db = TestingSessionLocal()
    listing = Listing(
        id="listing-live-1",
        seller_id="seller-user-123",
        title="Live Tool v1",
        description="Currently active live listing",
        price_cents=3000,
        category="security",
        status=ListingStatus.LIVE.value,
    )
    db.add(listing)
    db.commit()

    ver1 = ListingVersion(
        id="ver-1-uuid",
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
    )
    db.add(ver1)
    listing.current_version_id = ver1.id
    db.commit()
    db.close()

    # Now seller edits title on live listing
    res = client.patch(
        "/listings/listing-live-1",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"title": "Live Tool v1 - Revised"}
    )
    assert res.status_code == 200
    assert res.json()["title"] == "Live Tool v1 - Revised"

    # Verify a new draft version was added to preserve immutability
    db = TestingSessionLocal()
    versions = db.query(ListingVersion).filter(ListingVersion.listing_id == "listing-live-1").all()
    assert len(versions) == 2
    labels = [v.version_label for v in versions]
    assert "1.0.0" in labels
    assert "1.0.1" in labels
    db.close()


# ============================================================================
# Prompt 2: Submission to Scan-Service & Polling Tests
# ============================================================================

def test_submit_version_calls_scan_service(client, seller_token, monkeypatch):
    """Submitting a version calls scan-service intake and creates pending ListingVersion."""
    # Create listing
    create_res = client.post(
        "/listings",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "title": "Scanner Intake Test",
            "description": "Package submitting test",
            "price_cents": 1200,
            "category": "utilities",
        }
    )
    listing_id = create_res.json()["id"]

    # Mock scanner_client.submit_version
    def mock_submit_version(listing_id, version, source_type, git_url, package_content):
        return {"status": "enqueued", "scan_job_id": "job-scan-999"}

    from src.routes.listings import scanner_client
    monkeypatch.setattr(scanner_client, "submit_version", mock_submit_version)

    res = client.post(
        f"/listings/{listing_id}/versions",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "version_label": "1.1.0",
            "source_type": "upload",
            "package_content": "dummy-base64-content"
        }
    )
    assert res.status_code == 202
    data = res.json()
    assert data["version_label"] == "1.1.0"
    assert data["scan_status"] == "pending_scan"
    assert data["scan_job_id"] == "job-scan-999"


def test_submit_version_with_github_url_and_version_alias(client, seller_token, monkeypatch):
    """Verifies that version submission accepts 'version' alias and auto-detects GitHub URLs in package_path."""
    create_res = client.post(
        "/listings",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "title": "GitHub Repo Tool",
            "description": "Submitting GitHub repo for scanning",
            "price_cents": 1500,
            "category": "developer-tools",
        }
    )
    listing_id = create_res.json()["id"]

    captured_call = {}
    def mock_submit_version(listing_id, version, source_type, git_url, package_content):
        captured_call.update({
            "listing_id": listing_id,
            "version": version,
            "source_type": source_type,
            "git_url": git_url,
            "package_content": package_content,
        })
        return {"status": "enqueued", "scan_job_id": "job-scan-gh-001"}

    from src.routes.listings import scanner_client
    monkeypatch.setattr(scanner_client, "submit_version", mock_submit_version)

    # Submitting with payload matching frontend form format
    res = client.post(
        f"/listings/{listing_id}/versions",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "version": "1.0.0",
            "package_path": "https://github.com/avikengineer007/Aegis-AI-powered-SOC-Analyst.git",
            "changelog": "Initial public intake",
        }
    )
    assert res.status_code == 202
    data = res.json()
    assert data["version_label"] == "1.0.0"
    assert data["scan_job_id"] == "job-scan-gh-001"
    assert captured_call["source_type"] == "github"
    assert captured_call["git_url"] == "https://github.com/avikengineer007/Aegis-AI-powered-SOC-Analyst.git"
    assert captured_call["version"] == "1.0.0"


def test_poll_version_status_triggers_gate(client, seller_token, monkeypatch):
    """Polling version status updates findings from scan-service and evaluates publish gate."""
    db = TestingSessionLocal()
    listing = Listing(
        id="listing-poll-1",
        seller_id="seller-user-123",
        title="Polling Tool",
        description="Polling verification",
        price_cents=1000,
        category="utilities",
        status=ListingStatus.PENDING_SCAN.value,
    )
    ver = ListingVersion(
        id="ver-poll-1",
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PENDING_SCAN.value,
    )
    db.add_all([listing, ver])
    db.commit()
    db.close()

    # Mock scanner_client.query_status returning scan passed
    def mock_query_status(listing_id, version_label):
        return {
            "scan_status": "passed",
            "storage_location": "s3://vetted/pkg.zip",
            "severity_counts": {"critical": 0, "high": 0},
            "findings": [],
        }

    from src.routes.listings import scanner_client
    monkeypatch.setattr(scanner_client, "query_status", mock_query_status)

    # Mock payout check returning enabled
    monkeypatch.setattr("src.gate.check_seller_payout_status", lambda seller_id: PayoutCheckResult.PAYOUT_ENABLED)

    res = client.get(
        f"/listings/listing-poll-1/versions/ver-poll-1/status",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scan_status"] == "passed"

    # Verify listing transitioned to LIVE
    db = TestingSessionLocal()
    updated_listing = db.query(Listing).filter(Listing.id == "listing-poll-1").first()
    assert updated_listing is not None
    assert updated_listing.status == ListingStatus.LIVE.value
    assert updated_listing.current_version_id == "ver-poll-1"
    db.close()


# ============================================================================
# Prompt 3: Strict Publish Gate & Distinct Fail-Closed States
# ============================================================================

def test_publish_gate_scan_passed_payout_enabled_becomes_live():
    """Scan passed + Payout enabled -> LIVE."""
    from src.gate import evaluate_publish_gate
    db = TestingSessionLocal()
    listing = Listing(
        id="l-1", seller_id="seller-1", title="T", description="D",
        price_cents=100, category="utilities", status="pending_scan"
    )
    ver = ListingVersion(
        id="v-1", listing_id="l-1", version_label="1.0.0", scan_status="passed"
    )
    db.add_all([listing, ver])
    db.commit()

    evaluate_publish_gate(listing, ver, db, payout_override=PayoutCheckResult.PAYOUT_ENABLED)

    assert listing.status == ListingStatus.LIVE.value
    assert listing.current_version_id == "v-1"
    db.close()


def test_publish_gate_scan_passed_payout_disabled_becomes_awaiting_kyc():
    """Scan passed + Payout disabled -> scan_passed_awaiting_kyc."""
    from src.gate import evaluate_publish_gate
    db = TestingSessionLocal()
    listing = Listing(
        id="l-2", seller_id="seller-2", title="T", description="D",
        price_cents=100, category="utilities", status="pending_scan"
    )
    ver = ListingVersion(
        id="v-2", listing_id="l-2", version_label="1.0.0", scan_status="passed"
    )
    db.add_all([listing, ver])
    db.commit()

    evaluate_publish_gate(listing, ver, db, payout_override=PayoutCheckResult.PAYOUT_DISABLED)

    assert listing.status == ListingStatus.SCAN_PASSED_AWAITING_KYC.value
    assert listing.status_message is not None
    assert "Complete seller identity verification" in listing.status_message
    db.close()


def test_publish_gate_scan_passed_system_unavailable_distinct_state():
    """
    Fail-closed & distinct state guarantee:
    Scan passed + auth-service outage -> scan_passed_verification_unavailable
    Does NOT falsely tell seller they lack KYC.
    """
    from src.gate import evaluate_publish_gate
    db = TestingSessionLocal()
    listing = Listing(
        id="l-3", seller_id="seller-3", title="T", description="D",
        price_cents=100, category="utilities", status="pending_scan"
    )
    ver = ListingVersion(
        id="v-3", listing_id="l-3", version_label="1.0.0", scan_status="passed"
    )
    db.add_all([listing, ver])
    db.commit()

    evaluate_publish_gate(listing, ver, db, payout_override=PayoutCheckResult.SYSTEM_UNAVAILABLE)

    assert listing.status == ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value
    assert listing.status_message is not None
    assert "Verification service temporarily unavailable" in listing.status_message
    db.close()


def test_publish_gate_scan_failed_routes_cleanly():
    """Scan failed -> scan_failed."""
    from src.gate import evaluate_publish_gate
    db = TestingSessionLocal()
    listing = Listing(
        id="l-4", seller_id="seller-4", title="T", description="D",
        price_cents=100, category="utilities", status="pending_scan"
    )
    ver = ListingVersion(
        id="v-4", listing_id="l-4", version_label="1.0.0", scan_status="scan_failed"
    )
    db.add_all([listing, ver])
    db.commit()

    evaluate_publish_gate(listing, ver, db)

    assert listing.status == ListingStatus.SCAN_FAILED.value
    assert listing.status_message is not None
    assert "detected secrets or vulnerabilities" in listing.status_message
    db.close()


def test_sync_seller_kyc_promotes_awaiting_listings_to_live():
    """
    Lazy Self-Healing:
    When seller completes KYC in auth-service, calling sync_seller_kyc promotes
    waiting listings to 'live' immediately without re-running the scan.
    """
    from src.gate import sync_seller_kyc
    db = TestingSessionLocal()
    listing = Listing(
        id="l-wait",
        seller_id="seller-healed",
        title="Pending KYC Tool",
        description="Description",
        price_cents=2000,
        category="security",
        status=ListingStatus.SCAN_PASSED_AWAITING_KYC.value,
    )
    ver = ListingVersion(
        id="v-wait",
        listing_id="l-wait",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
    )
    db.add_all([listing, ver])
    db.commit()

    # Trigger sync with payout enabled
    promoted = sync_seller_kyc("seller-healed", db, payout_override=PayoutCheckResult.PAYOUT_ENABLED)
    assert len(promoted) == 1
    assert promoted[0].status == ListingStatus.LIVE.value
    assert promoted[0].current_version_id == "v-wait"

    # Listing is now live in DB
    refreshed = db.query(Listing).filter(Listing.id == "l-wait").first()
    assert refreshed is not None
    assert refreshed.status == ListingStatus.LIVE.value
    db.close()


# ============================================================================
# Prompt 4: Seller Dashboard, Findings & Withdrawal Tests
# ============================================================================

def test_seller_listings_mine_endpoint(client, seller_token, monkeypatch):
    """GET /listings/mine returns listings with next-action hints and triggers lazy KYC sync."""
    db = TestingSessionLocal()
    listing = Listing(
        id="l-mine-1",
        seller_id="seller-user-123",
        title="Mine Tool",
        description="Desc",
        price_cents=1500,
        category="developer-tools",
        status=ListingStatus.SCAN_FAILED.value,
    )
    ver = ListingVersion(
        id="v-mine-1",
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.SCAN_FAILED.value,
        findings_summary={"critical": 2, "high": 1},
    )
    db.add_all([listing, ver])
    db.commit()
    db.close()

    res = client.get("/listings/mine", headers={"Authorization": f"Bearer {seller_token}"})
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    target = next(i for i in items if i["id"] == "l-mine-1")
    assert target["status"] == "scan_failed"
    assert target["next_action"] == "view findings and resubmit"
    assert target["severity_summary"] == {"critical": 2, "high": 1}


def test_get_findings_owner_only_and_redacted(client, seller_token):
    """Findings detail is restricted to the listing owner."""
    db = TestingSessionLocal()
    listing = Listing(
        id="l-findings-1",
        seller_id="seller-user-123",
        title="Findings Tool",
        description="Desc",
        price_cents=1000,
        category="security",
        status=ListingStatus.SCAN_FAILED.value,
    )
    ver = ListingVersion(
        id="v-findings-1",
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.SCAN_FAILED.value,
        findings_detail=[
            {"rule_id": "SEC-001", "file": "config.py", "redacted_snippet": "API_KEY = '***'"}
        ]
    )
    db.add_all([listing, ver])
    db.commit()
    db.close()

    # Other seller gets 403
    other_token = generate_test_token("seller-other", ["seller"])
    res_forbidden = client.get(
        "/listings/l-findings-1/versions/v-findings-1/findings",
        headers={"Authorization": f"Bearer {other_token}"}
    )
    assert res_forbidden.status_code == 403

    # Owner gets 200 with findings
    res_owner = client.get(
        "/listings/l-findings-1/versions/v-findings-1/findings",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res_owner.status_code == 200
    data = res_owner.json()
    assert len(data["findings"]) == 1
    assert data["findings"][0]["redacted_snippet"] == "API_KEY = '***'"


def test_withdraw_listing(client, seller_token):
    """Owner can withdraw a listing, immediately hiding it from the catalog."""
    db = TestingSessionLocal()
    listing = Listing(
        id="l-withdraw-1",
        seller_id="seller-user-123",
        title="Withdraw Tool",
        description="Desc",
        price_cents=500,
        category="utilities",
        status=ListingStatus.LIVE.value,
    )
    db.add(listing)
    db.commit()
    db.close()

    res = client.delete(
        "/listings/l-withdraw-1",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res.status_code == 200

    db = TestingSessionLocal()
    withdrawn = db.query(Listing).filter(Listing.id == "l-withdraw-1").first()
    assert withdrawn is not None
    assert withdrawn.status == ListingStatus.WITHDRAWN.value
    db.close()


# ============================================================================
# Prompt 5: Public Browse, Search & Detail Tests
# ============================================================================

def test_public_browse_only_returns_live_listings(client):
    """
    Public catalog (GET /listings) strictly returns listings with status == 'live'.
    Drafts, scanning, failed, awaiting_kyc, and withdrawn listings are excluded.
    """
    db = TestingSessionLocal()
    listings = [
        Listing(id="l-live", seller_id="s1", title="Live Package", description="D", price_cents=1000, category="dev", status=ListingStatus.LIVE.value),
        Listing(id="l-draft", seller_id="s1", title="Draft Package", description="D", price_cents=1000, category="dev", status=ListingStatus.DRAFT.value),
        Listing(id="l-pending", seller_id="s1", title="Pending Package", description="D", price_cents=1000, category="dev", status=ListingStatus.PENDING_SCAN.value),
        Listing(id="l-kyc", seller_id="s1", title="Awaiting KYC", description="D", price_cents=1000, category="dev", status=ListingStatus.SCAN_PASSED_AWAITING_KYC.value),
        Listing(id="l-unavailable", seller_id="s1", title="Unavailable", description="D", price_cents=1000, category="dev", status=ListingStatus.SCAN_PASSED_VERIFICATION_UNAVAILABLE.value),
        Listing(id="l-failed", seller_id="s1", title="Failed Package", description="D", price_cents=1000, category="dev", status=ListingStatus.SCAN_FAILED.value),
        Listing(id="l-withdrawn", seller_id="s1", title="Withdrawn Package", description="D", price_cents=1000, category="dev", status=ListingStatus.WITHDRAWN.value),
    ]
    db.add_all(listings)
    db.commit()
    db.close()

    res = client.get("/listings")
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 1
    assert items[0]["id"] == "l-live"
    assert items[0]["status"] == "live"


def test_public_browse_filters(client):
    """Filters by category, price bounds, and search query work as expected."""
    db = TestingSessionLocal()
    listings = [
        Listing(id="l-cat-1", seller_id="s1", title="Python Docker Linter", description="Fast linter for container security", price_cents=2000, category="security", status="live"),
        Listing(id="l-cat-2", seller_id="s1", title="SQL Formatter", description="Developer utility for database migrations", price_cents=500, category="developer-tools", status="live"),
        Listing(id="l-cat-3", seller_id="s1", title="Kubernetes Cluster Helm Wizard", description="Infrastructure deployment tool", price_cents=9900, category="infrastructure", status="live"),
    ]
    db.add_all(listings)
    db.commit()
    db.close()

    # Category filter
    res = client.get("/listings?category=security")
    assert len(res.json()) == 1
    assert res.json()[0]["id"] == "l-cat-1"

    # Price max filter
    res_price = client.get("/listings?max_price_cents=1000")
    assert len(res_price.json()) == 1
    assert res_price.json()[0]["id"] == "l-cat-2"

    # Text search
    res_search = client.get("/listings?search=kubernetes")
    assert len(res_search.json()) == 1
    assert res_search.json()[0]["id"] == "l-cat-3"


def test_public_detail_view_permissions(client, seller_token):
    """
    Public gets 404 for non-live listings.
    Owner can view their own non-live listing.
    Live listing returns vetted=True and security badge.
    """
    db = TestingSessionLocal()
    live_listing = Listing(
        id="l-pub-live", seller_id="seller-other", title="Public Live Tool", description="Desc",
        price_cents=3000, category="security", status=ListingStatus.LIVE.value
    )
    draft_listing = Listing(
        id="l-pub-draft", seller_id="seller-user-123", title="My Private Draft", description="Desc",
        price_cents=1000, category="developer-tools", status=ListingStatus.DRAFT.value
    )
    db.add_all([live_listing, draft_listing])
    db.commit()
    db.close()

    # Public requests live listing
    res_live = client.get("/listings/l-pub-live")
    assert res_live.status_code == 200
    assert res_live.json()["vetted"] is True
    assert "Scanned — 0 critical findings" in res_live.json()["badge"]

    # Public requests draft listing -> 404
    res_draft_anon = client.get("/listings/l-pub-draft")
    assert res_draft_anon.status_code == 404

    # Owner requests own draft listing -> 200
    res_draft_owner = client.get(
        "/listings/l-pub-draft",
        headers={"Authorization": f"Bearer {seller_token}"}
    )
    assert res_draft_owner.status_code == 200
    assert res_draft_owner.json()["vetted"] is False
    assert res_draft_owner.json()["badge"] == "Unvetted Draft"


def test_listing_detail_github_badge_and_resilient_fallback(client, monkeypatch):
    """
    Tests that ListingDetailResponse includes seller_github when auth-service provides it,
    and falls back cleanly to None without blocking when auth-service is unreachable.
    """
    db = TestingSessionLocal()
    listing = Listing(
        id="l-gh-test",
        seller_id="seller-gh-user",
        title="GitHub Powered Package",
        description="A great developer tool",
        price_cents=2500,
        category="developer-tools",
        status=ListingStatus.LIVE.value,
    )
    db.add(listing)
    db.commit()
    db.close()

    # 1. Successful upstream trust fetch
    from src.models.listing import SellerGitHubBadgeResponse

    def mock_fetch_trust(seller_id):
        return SellerGitHubBadgeResponse(
            github_username="dev-octo",
            github_user_id="998877",
            public_repo_count=42,
            account_age_years=3.5,
        )

    monkeypatch.setattr("src.routes.listings.fetch_seller_public_trust", mock_fetch_trust)
    res = client.get("/listings/l-gh-test")
    assert res.status_code == 200
    data = res.json()
    assert data["seller_github"] is not None
    assert data["seller_github"]["github_username"] == "dev-octo"
    assert data["seller_github"]["public_repo_count"] == 42
    assert data["seller_github"]["account_age_years"] == 3.5

    # 2. Resilient fallback when auth-service returns None or fails
    monkeypatch.setattr("src.routes.listings.fetch_seller_public_trust", lambda sid: None)
    res_fallback = client.get("/listings/l-gh-test")
    assert res_fallback.status_code == 200
    data_fallback = res_fallback.json()
    assert data_fallback["seller_github"] is None

