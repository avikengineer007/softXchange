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
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus, SavedListing

# Isolated test DB
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_public_key = test_private_key.public_key()
TEST_KID = "test-key-wishlist-1"
jwks_manager.set_key_for_testing(TEST_KID, test_public_key)


def generate_test_token(user_id: str, roles: list) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "roles": roles,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
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
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=test_engine)


def _create_listing(title: str, status_val: str = ListingStatus.LIVE.value) -> Listing:
    db = TestingSessionLocal()
    listing = Listing(
        id=str(uuid.uuid4()),
        seller_id="seller-wishlist",
        title=title,
        description=f"Description for {title}",
        price_cents=1900,
        category="utilities",
        status=status_val,
        status_message="Test status",
    )
    db.add(listing)
    db.commit()
    db.refresh(listing)
    db.close()
    return listing


def test_save_and_unsave_idempotency():
    listing = _create_listing("Fast Cache Tool")
    buyer_id = "buyer-wish-1"
    auth = {"Authorization": f"Bearer {generate_test_token(buyer_id, ['customer'])}"}

    # 1. Check initial saved status
    res = client.get(f"/listings/{listing.id}/saved-status", headers=auth)
    assert res.status_code == 200
    assert res.json()["saved"] is False

    # 2. Save
    res_save = client.post(f"/listings/{listing.id}/save", headers=auth)
    assert res_save.status_code == 200
    assert res_save.json()["saved"] is True

    # 3. Save again (idempotent)
    res_save2 = client.post(f"/listings/{listing.id}/save", headers=auth)
    assert res_save2.status_code == 200
    assert res_save2.json()["saved"] is True

    # Status is now True
    res = client.get(f"/listings/{listing.id}/saved-status", headers=auth)
    assert res.json()["saved"] is True

    # 4. Unsave
    res_unsave = client.delete(f"/listings/{listing.id}/save", headers=auth)
    assert res_unsave.status_code == 200
    assert res_unsave.json()["saved"] is False

    # 5. Unsave again (idempotent)
    res_unsave2 = client.delete(f"/listings/{listing.id}/save", headers=auth)
    assert res_unsave2.status_code == 200
    assert res_unsave2.json()["saved"] is False


def test_toggle_save():
    listing = _create_listing("Toggle Utility")
    buyer_id = "buyer-wish-2"
    auth = {"Authorization": f"Bearer {generate_test_token(buyer_id, ['customer'])}"}

    # First toggle -> saved: True
    t1 = client.post(f"/listings/{listing.id}/toggle-save", headers=auth)
    assert t1.status_code == 200
    assert t1.json()["saved"] is True

    # Second toggle -> saved: False
    t2 = client.post(f"/listings/{listing.id}/toggle-save", headers=auth)
    assert t2.status_code == 200
    assert t2.json()["saved"] is False

    # Third toggle -> saved: True
    t3 = client.post(f"/listings/{listing.id}/toggle-save", headers=auth)
    assert t3.status_code == 200
    assert t3.json()["saved"] is True


def test_get_saved_listings_preserves_withdrawn_and_suspended_items():
    buyer_id = "buyer-wish-3"
    auth = {"Authorization": f"Bearer {generate_test_token(buyer_id, ['customer'])}"}

    l_live = _create_listing("Live App", status_val=ListingStatus.LIVE.value)
    l_withdrawn = _create_listing("Withdrawn App", status_val=ListingStatus.WITHDRAWN.value)
    l_suspended = _create_listing("Suspended App", status_val=ListingStatus.SUSPENDED.value)

    # Save all three
    client.post(f"/listings/{l_live.id}/save", headers=auth)
    client.post(f"/listings/{l_withdrawn.id}/save", headers=auth)
    client.post(f"/listings/{l_suspended.id}/save", headers=auth)

    # Public browse ONLY returns live
    public_browse = client.get("/listings").json()
    assert len([l for l in public_browse if l["id"] == l_withdrawn.id]) == 0
    assert len([l for l in public_browse if l["id"] == l_suspended.id]) == 0

    # GET /listings/saved returns all 3 with honest statuses preserved
    saved_res = client.get("/listings/saved", headers=auth)
    assert saved_res.status_code == 200
    items = saved_res.json()
    assert len(items) == 3

    statuses_by_id = {item["id"]: item["status"] for item in items}
    assert statuses_by_id[l_live.id] == "live"
    assert statuses_by_id[l_withdrawn.id] == "withdrawn"
    assert statuses_by_id[l_suspended.id] == "suspended"


def test_saved_listings_unauthenticated_rejected():
    res = client.get("/listings/saved")
    assert res.status_code == 401

    res_post = client.post("/listings/some-id/save")
    assert res_post.status_code == 401
