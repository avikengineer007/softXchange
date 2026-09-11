"""
apps/broker/tests/conftest.py

Test fixtures and isolated SQLite in-memory database for broker microservice.
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
SELLER_ASSIST_ROOT = REPO_ROOT / "apps" / "seller-assist"
BROKER_ROOT = REPO_ROOT / "apps" / "broker"
ML_SHARED_SRC = REPO_ROOT / "packages" / "ml-shared" / "src"

for p in [LISTINGS_SERVICE_ROOT, BUYER_ASSIST_ROOT, SELLER_ASSIST_ROOT, BROKER_ROOT, ML_SHARED_SRC]:
    p_str = str(p)
    while p_str in sys.path:
        sys.path.remove(p_str)
    sys.path.insert(0, p_str)

for k in list(sys.modules.keys()):
    if k == "src" or k.startswith("src."):
        sys.modules.pop(k, None)

from src.database import Base, get_db
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus, BuyerQuestion, SearchEvent
from broker.main import app

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
def seeded_broker_catalog(db_session):
    """
    Seeds a live listing, an inactive listing, and baseline buyer questions.
    """
    db_session.query(SearchEvent).delete()
    db_session.query(BuyerQuestion).delete()
    db_session.query(ListingVersion).delete()
    db_session.query(Listing).delete()
    db_session.commit()

    # 1. Live security tool
    l1 = Listing(
        id="brk-sec-101",
        seller_id="seller-alpha",
        title="SecScan Auditor",
        description="Comprehensive automated vulnerability scanner auditing cloud infrastructure.",
        price_cents=4500,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-brk-101",
    )
    v1 = ListingVersion(
        id="ver-brk-101",
        listing_id="brk-sec-101",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l1)
    db_session.add(v1)

    # 2. Live payments library
    l2 = Listing(
        id="brk-pay-102",
        seller_id="seller-alpha",
        title="OmniPay Gateway",
        description="Payment gateway integration for global credit card processing.",
        price_cents=3500,
        category="payments",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-brk-102",
    )
    v2 = ListingVersion(
        id="ver-brk-102",
        listing_id="brk-pay-102",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(l2)
    db_session.add(v2)

    # 3. Draft listing (seller-beta)
    l3 = Listing(
        id="brk-draft-103",
        seller_id="seller-beta",
        title="Draft Cloud Router",
        description="High throughput packet router under development.",
        price_cents=2000,
        category="networking",
        status=ListingStatus.DRAFT.value,
    )
    db_session.add(l3)

    db_session.commit()

    return {
        "security": l1,
        "payments": l2,
        "draft": l3,
    }
