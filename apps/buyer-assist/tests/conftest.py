"""
apps/buyer-assist/tests/conftest.py

Test configuration and isolated test fixtures for buyer-assist.
Ensures clean database isolation and seeded listing fixtures.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LISTINGS_SERVICE_ROOT = REPO_ROOT / "apps" / "listings-service"
BUYER_ASSIST_ROOT = REPO_ROOT / "apps" / "buyer-assist"
ML_SHARED_SRC = REPO_ROOT / "packages" / "ml-shared" / "src"

# Clear cached src module if any so listings-service src is cleanly loaded
if str(LISTINGS_SERVICE_ROOT) in sys.path:
    sys.path.remove(str(LISTINGS_SERVICE_ROOT))
sys.path.insert(0, str(LISTINGS_SERVICE_ROOT))

if str(BUYER_ASSIST_ROOT) not in sys.path:
    sys.path.insert(0, str(BUYER_ASSIST_ROOT))

if str(ML_SHARED_SRC) not in sys.path:
    sys.path.insert(0, str(ML_SHARED_SRC))

sys.modules.pop("src", None)
for k in list(sys.modules.keys()):
    if k.startswith("src.") and not k.startswith("src.models") and not k.startswith("src.database"):
        pass

from src.database import Base, get_db
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from src.models.embedding import ListingEmbedding
from src.indexer import sync_live_listing_embedding
from buyer_assist.main import app

TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


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
def seeded_catalog(db_session):
    """
    Seeds a representative fixture set:
    1. Live: Cloud Sentry CLI (Security vulnerability scanning)
    2. Live: FastPay Checkout SDK (Stripe payments & subscriptions)
    3. Live: LogStash Parser (Log parsing & distributed tracing)
    4. Withdrawn: Secret Keeper Vault (Cryptographic key vault)
    5. Draft: Network Firewall Mesh (Packet filter)
    """
    # Clean up before seeding
    db_session.query(ListingEmbedding).delete()
    db_session.query(ListingVersion).delete()
    db_session.query(Listing).delete()
    db_session.commit()

    # 1. Cloud Sentry CLI (Live)
    l1 = Listing(
        id="list-sec-001",
        seller_id="seller-1",
        title="Cloud Sentry CLI",
        description="High performance automated cloud vulnerability scanner auditing AWS, GCP, and Kubernetes clusters.",
        price_cents=5900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-sec-001",
    )
    v1 = ListingVersion(
        id="ver-sec-001",
        listing_id="list-sec-001",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l1)
    db_session.add(v1)
    db_session.flush()
    sync_live_listing_embedding(l1, v1, db_session)

    # 2. FastPay Checkout SDK (Live)
    l2 = Listing(
        id="list-pay-002",
        seller_id="seller-2",
        title="FastPay Checkout SDK",
        description="Python and TypeScript payments client for processing credit cards, Stripe webhooks, and billing subscriptions.",
        price_cents=4900,
        category="payments",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-pay-002",
    )
    v2 = ListingVersion(
        id="ver-pay-002",
        listing_id="list-pay-002",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l2)
    db_session.add(v2)
    db_session.flush()
    sync_live_listing_embedding(l2, v2, db_session)

    # 3. LogStash JSON Parser (Live)
    l3 = Listing(
        id="list-log-003",
        seller_id="seller-3",
        title="LogStash JSON Parser",
        description="High throughput structured log ingestion pipeline, log parsing utility, and distributed tracing collector.",
        price_cents=1900,
        category="developer-tools",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-log-003",
    )
    v3 = ListingVersion(
        id="ver-log-003",
        listing_id="list-log-003",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l3)
    db_session.add(v3)
    db_session.flush()
    sync_live_listing_embedding(l3, v3, db_session)

    # 4. Secret Keeper Vault (Withdrawn)
    l4 = Listing(
        id="list-withdrawn-004",
        seller_id="seller-4",
        title="Secret Keeper Vault",
        description="Secure cryptographic key vault and secret management daemon with encrypted hardware storage.",
        price_cents=8900,
        category="security",
        status=ListingStatus.WITHDRAWN.value,
        current_version_id="ver-withdrawn-004",
    )
    v4 = ListingVersion(
        id="ver-withdrawn-004",
        listing_id="list-withdrawn-004",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l4)
    db_session.add(v4)
    db_session.commit()

    # 5. Network Firewall Mesh (Draft)
    l5 = Listing(
        id="list-draft-005",
        seller_id="seller-5",
        title="Network Firewall Mesh",
        description="Zero trust software defined perimeter and network firewall packet filter.",
        price_cents=3500,
        category="security",
        status=ListingStatus.DRAFT.value,
        current_version_id="ver-draft-005",
    )
    v5 = ListingVersion(
        id="ver-draft-005",
        listing_id="list-draft-005",
        version_label="1.0.0",
        scan_status=ScanStatus.PENDING_SCAN.value,
    )
    db_session.add(l5)
    db_session.add(v5)
    db_session.commit()

    return {
        "security": l1,
        "payments": l2,
        "logging": l3,
        "withdrawn": l4,
        "draft": l5,
    }
