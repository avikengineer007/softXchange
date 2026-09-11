import sys
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
from src.auth import jwks_manager
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from src.models.embedding import ListingEmbedding
from src.indexer import sync_live_listing_embedding

TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_public_key = test_private_key.public_key()
TEST_KID = "admin-mod-key-1"
jwks_manager.set_key_for_testing(TEST_KID, test_public_key)


def generate_test_token(user_id: str, roles: list) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=1)
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
    return jwt.encode(payload, pem_priv, algorithm="RS256", headers={"kid": TEST_KID})


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


def _seed_listing(db, title="Test Package", status=ListingStatus.LIVE.value):
    listing = Listing(
        seller_id="seller-123",
        title=title,
        description="A great developer tool for verification.",
        price_cents=4900,
        category="developer-tools",
        status=status,
    )
    db.add(listing)
    db.flush()

    version = ListingVersion(
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
    )
    db.add(version)
    db.commit()
    listing.current_version_id = version.id
    db.commit()
    db.refresh(listing)
    return listing


# ============================================================================
# Admin Moderation & Embedding Purge Tests (Prompt 4)
# ============================================================================

def test_admin_all_listings_requires_admin_role(client):
    """GET /listings/admin/all is forbidden for non-admin callers."""
    db = TestingSessionLocal()
    _seed_listing(db, title="Live Tool")
    db.close()

    seller_token = generate_test_token("seller-123", ["seller"])
    resp = client.get(
        "/listings/admin/all",
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert resp.status_code == 403
    assert "Admin role required" in resp.json()["detail"]


def test_admin_all_listings_returns_all_statuses(client):
    """GET /listings/admin/all returns listings across all statuses."""
    db = TestingSessionLocal()
    _seed_listing(db, title="Draft Tool", status=ListingStatus.DRAFT.value)
    _seed_listing(db, title="Live Tool", status=ListingStatus.LIVE.value)
    _seed_listing(db, title="Suspended Tool", status=ListingStatus.SUSPENDED.value)
    db.close()

    admin_token = generate_test_token("admin-456", ["admin"])
    resp = client.get(
        "/listings/admin/all",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    listings = resp.json()
    assert len(listings) == 3

    statuses = {l["status"] for l in listings}
    assert statuses == {"draft", "live", "suspended"}


def test_admin_suspend_listing_removes_search_embedding(client):
    """
    CRITICAL REUSE CONFIRMATION:
    Suspending a listing sets status to 'suspended' and purges the
    vector embedding from the index via remove_listing_embedding().
    """
    db = TestingSessionLocal()
    listing = _seed_listing(db, title="Embeddable Tool", status=ListingStatus.LIVE.value)

    # Index listing embedding
    sync_live_listing_embedding(listing=listing, version=None, db=db)
    emb_before = db.query(ListingEmbedding).filter(ListingEmbedding.listing_id == listing.id).first()
    assert emb_before is not None, "Embedding must exist prior to suspension"


    admin_token = generate_test_token("admin-456", ["admin"])

    # Non-admin cannot suspend
    non_admin_token = generate_test_token("hacker", ["seller"])
    resp_unauth = client.post(
        f"/listings/{listing.id}/suspend",
        headers={"Authorization": f"Bearer {non_admin_token}"},
    )
    assert resp_unauth.status_code == 403

    # Admin suspends listing
    resp = client.post(
        f"/listings/{listing.id}/suspend",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "suspended"

    # Embedding must be purged from database
    db.expire_all()
    emb_after = db.query(ListingEmbedding).filter(ListingEmbedding.listing_id == listing.id).first()
    assert emb_after is None, "Embedding must be completely purged after suspension"
    db.close()
