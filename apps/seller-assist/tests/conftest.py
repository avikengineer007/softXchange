"""
apps/seller-assist/tests/conftest.py

Test fixtures and isolated SQLite setup for seller-assist service tests.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LISTINGS_SERVICE_ROOT = REPO_ROOT / "apps" / "listings-service"
SELLER_ASSIST_ROOT = REPO_ROOT / "apps" / "seller-assist"
ML_SHARED_SRC = REPO_ROOT / "packages" / "ml-shared" / "src"

if str(LISTINGS_SERVICE_ROOT) in sys.path:
    sys.path.remove(str(LISTINGS_SERVICE_ROOT))
sys.path.insert(0, str(LISTINGS_SERVICE_ROOT))

if str(SELLER_ASSIST_ROOT) not in sys.path:
    sys.path.insert(0, str(SELLER_ASSIST_ROOT))

if str(ML_SHARED_SRC) not in sys.path:
    sys.path.insert(0, str(ML_SHARED_SRC))

from src.database import Base, get_db
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from src.models.embedding import ListingEmbedding
from src.indexer import sync_live_listing_embedding
from seller_assist.main import app
from seller_assist.auth import key_manager

TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Setup RSA Test Keypair
test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_public_key = test_private_key.public_key()
TEST_KID = "test-seller-key-1"

# Inject into seller-assist key manager
key_manager.set_key_for_testing(TEST_KID, test_public_key)


def generate_token(user_id: str, roles: list, kid: str = TEST_KID, expired: bool = False) -> str:
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


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seller_token():
    return generate_token(user_id="seller-1", roles=["seller"])


@pytest.fixture
def other_seller_token():
    return generate_token(user_id="seller-99", roles=["seller"])


@pytest.fixture
def buyer_token():
    return generate_token(user_id="buyer-1", roles=["buyer"])


@pytest.fixture
def seeded_listings(db_session):
    """
    Seeds a draft listing for seller-1 plus comparable live listings in security category.
    """
    db_session.query(ListingEmbedding).delete()
    db_session.query(ListingVersion).delete()
    db_session.query(Listing).delete()
    db_session.commit()

    # Target draft listing owned by seller-1
    target = Listing(
        id="draft-target-001",
        seller_id="seller-1",
        title="ZeroSec Vulnerability Sentinel",
        description="Continuous scanning CLI detecting leaked keys and credentials.",
        price_cents=4500,
        category="security",
        status=ListingStatus.DRAFT.value,
    )
    db_session.add(target)

    # 3 Live comparable listings in security with prices: $39.00, $59.00, $89.00
    comp1 = Listing(
        id="comp-sec-001",
        seller_id="other-seller-1",
        title="Cloud Sentry Security CLI",
        description="Static security scanner for cloud credentials and API keys.",
        price_cents=3900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-comp-1",
    )
    v1 = ListingVersion(
        id="ver-comp-1",
        listing_id="comp-sec-001",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(comp1)
    db_session.add(v1)

    comp2 = Listing(
        id="comp-sec-002",
        seller_id="other-seller-2",
        title="VaultGuard Credential Inspector",
        description="Hardcoded secrets detection and credential scanner for enterprise CI/CD.",
        price_cents=5900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-comp-2",
    )
    v2 = ListingVersion(
        id="ver-comp-2",
        listing_id="comp-sec-002",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(comp2)
    db_session.add(v2)

    comp3 = Listing(
        id="comp-sec-003",
        seller_id="other-seller-3",
        title="Perimeter Defense Security Mesh",
        description="Network and code vulnerability auditing and scanner suite.",
        price_cents=8900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-comp-3",
    )
    v3 = ListingVersion(
        id="ver-comp-3",
        listing_id="comp-sec-003",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(comp3)
    db_session.add(v3)
    db_session.commit()

    # Index embeddings for all live listings
    sync_live_listing_embedding(comp1, v1, db_session)
    sync_live_listing_embedding(comp2, v2, db_session)
    sync_live_listing_embedding(comp3, v3, db_session)

    return {
        "target": target,
        "comp1": comp1,
        "comp2": comp2,
        "comp3": comp3,
    }
