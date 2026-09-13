import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
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
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus, Review
import src.routes.listings as listings_routes

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
TEST_KID = "test-key-reviews-1"
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


def _create_live_listing(seller_id: str = "seller-123") -> Listing:
    db = TestingSessionLocal()
    listing = Listing(
        id=str(uuid.uuid4()),
        seller_id=seller_id,
        title="Production Analytics SDK",
        description="Enterprise analytics package with zero telemetry leak.",
        price_cents=4900,
        category="developer-tools",
        status=ListingStatus.LIVE.value,
        status_message="Listing is live in the marketplace.",
    )
    db.add(listing)
    db.flush()

    ver = ListingVersion(
        id=str(uuid.uuid4()),
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
    )
    db.add(ver)
    listing.current_version_id = ver.id
    db.commit()
    db.refresh(listing)
    db.close()
    return listing


def test_post_review_requires_verified_purchase():
    listing = _create_live_listing()
    buyer_id = "buyer-456"
    token = generate_test_token(buyer_id, ["customer"])

    # 1. When payments-service returns has_purchased: false -> 403 Forbidden
    with patch.object(listings_routes, "check_buyer_purchase_entitlement", return_value=False):
        res = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 5, "review_text": "Great software!"},
        )
        assert res.status_code == 403
        assert "Verified purchase required" in res.json()["detail"]

    # 2. When payments-service returns has_purchased: true -> 200 OK
    with patch.object(listings_routes, "check_buyer_purchase_entitlement", return_value=True), \
         patch.object(listings_routes, "emit_notification") as mock_emit:
        res = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 5, "review_text": "Great software!"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["rating"] == 5
        assert data["review_text"] == "Great software!"
        assert data["buyer_id"] == buyer_id
        assert data["listing_id"] == listing.id
        assert data["is_edited"] is False

        # Verify notification emitted to seller
        mock_emit.assert_called_once()
        call_kwargs = mock_emit.call_args[1]
        assert call_kwargs["user_id"] == listing.seller_id
        assert call_kwargs["notification_type"] == "listing_review_received"


def test_review_resubmission_updates_not_duplicates_and_sets_is_edited():
    listing = _create_live_listing()
    buyer_id = "buyer-789"
    token = generate_test_token(buyer_id, ["customer"])

    with patch.object(listings_routes, "check_buyer_purchase_entitlement", return_value=True), \
         patch.object(listings_routes, "emit_notification"):
        # First submission
        res1 = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 4, "review_text": "Initial review."},
        )
        assert res1.status_code == 200
        review_id_1 = res1.json()["id"]

        # Resubmission (edit)
        res2 = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 5, "review_text": "Updated review - even better!"},
        )
        assert res2.status_code == 200
        data2 = res2.json()

        # Same review row updated
        assert data2["id"] == review_id_1
        assert data2["rating"] == 5
        assert data2["review_text"] == "Updated review - even better!"
        assert data2["is_edited"] is True

    # Confirm only 1 review row exists in DB
    db = TestingSessionLocal()
    reviews = db.query(Review).filter(Review.listing_id == listing.id).all()
    assert len(reviews) == 1
    db.close()


def test_average_rating_and_review_count_aggregation():
    listing = _create_live_listing()
    buyer1 = "buyer-1"
    buyer2 = "buyer-2"

    # Initial: 0 reviews -> average_rating is None, review_count is 0
    detail_res = client.get(f"/listings/{listing.id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["average_rating"] is None
    assert detail_res.json()["review_count"] == 0

    browse_res = client.get("/listings")
    assert browse_res.status_code == 200
    assert browse_res.json()[0]["average_rating"] is None
    assert browse_res.json()[0]["review_count"] == 0

    # Add 2 reviews: rating 5 and rating 4 -> average 4.5
    with patch.object(listings_routes, "check_buyer_purchase_entitlement", return_value=True), \
         patch.object(listings_routes, "emit_notification"):
        client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {generate_test_token(buyer1, ['customer'])}"},
            json={"rating": 5, "review_text": "Five stars"},
        )
        client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {generate_test_token(buyer2, ['customer'])}"},
            json={"rating": 4, "review_text": "Four stars"},
        )

    # 1. GET /listings/{id}/reviews
    reviews_res = client.get(f"/listings/{listing.id}/reviews")
    assert reviews_res.status_code == 200
    rdata = reviews_res.json()
    assert rdata["total"] == 2
    assert rdata["review_count"] == 2
    assert rdata["average_rating"] == 4.5
    assert len(rdata["reviews"]) == 2

    # 2. GET /listings/{id} detail
    detail_res2 = client.get(f"/listings/{listing.id}")
    assert detail_res2.status_code == 200
    assert detail_res2.json()["average_rating"] == 4.5
    assert detail_res2.json()["review_count"] == 2

    # 3. GET /listings browse
    browse_res2 = client.get("/listings")
    assert browse_res2.status_code == 200
    assert browse_res2.json()[0]["average_rating"] == 4.5
    assert browse_res2.json()[0]["review_count"] == 2


def test_rating_bounds_validation():
    listing = _create_live_listing()
    token = generate_test_token("buyer-val", ["customer"])

    with patch("src.routes.listings.check_buyer_purchase_entitlement", return_value=True):
        res_low = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 0},
        )
        assert res_low.status_code in [400, 422]

        res_high = client.post(
            f"/listings/{listing.id}/reviews",
            headers={"Authorization": f"Bearer {token}"},
            json={"rating": 6},
        )
        assert res_high.status_code in [400, 422]
