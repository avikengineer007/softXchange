"""
ml-shared test configuration and isolated fixtures.
Guarantees 100% test isolation without polluting or reading ambient shared dev databases.
"""

import sys
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure listings-service and ml-shared are in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LISTINGS_SERVICE_PATH = REPO_ROOT / "apps" / "listings-service"
SCAN_SERVICE_PATH = REPO_ROOT / "apps" / "scan-service"
ML_SHARED_SRC_PATH = REPO_ROOT / "packages" / "ml-shared" / "src"

if str(LISTINGS_SERVICE_PATH) in sys.path:
    sys.path.remove(str(LISTINGS_SERVICE_PATH))
sys.path.insert(0, str(LISTINGS_SERVICE_PATH))

if str(ML_SHARED_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(ML_SHARED_SRC_PATH))

sys.modules.pop("src", None)

from src.database import Base
from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from ml_shared.context import SellerDocument, ListingContextBundle, ScanSummary, ListingMetadata

# Isolated in-memory SQLite database dedicated to this test suite
TEST_DB_URL = "sqlite:///:memory:"
isolated_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
IsolatedSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=isolated_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_isolated_db():
    """Create isolated schema for the entire test session."""
    Base.metadata.create_all(bind=isolated_engine)
    yield
    Base.metadata.drop_all(bind=isolated_engine)


@pytest.fixture
def db_session():
    """Provides a transactional database session rolled back after each test."""
    session = IsolatedSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def seeded_live_listing(db_session) -> Listing:
    """
    Seeds a dedicated, deterministic live listing fixture with zero findings.
    Isolated from any external dev database.
    """
    listing_id = "test-live-listing-001"
    version_id = "test-ver-001"

    # Clean prior test runs if any
    db_session.query(ListingVersion).filter(ListingVersion.listing_id == listing_id).delete()
    db_session.query(Listing).filter(Listing.id == listing_id).delete()
    db_session.flush()

    listing = Listing(
        id=listing_id,
        seller_id="seller-seed-user-123",
        title="Cloud Sentry CLI",
        description="High performance automated cloud vulnerability scanner with instant reporting.",
        price_cents=5900,  # $59.00
        category="security",
        status=ListingStatus.LIVE.value,
        status_message="Listing active and security vetted.",
        current_version_id=version_id,
    )
    db_session.add(listing)
    db_session.flush()

    version = ListingVersion(
        id=version_id,
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        scan_job_id="scan-job-isolated-001",
        storage_location="s3://softxchange-packages/cloud-sentry-1.0.0.zip",
        findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
        findings_detail=[],
    )
    db_session.add(version)
    db_session.commit()
    db_session.refresh(listing)
    return listing


@pytest.fixture
def seeded_listing_with_findings(db_session) -> Listing:
    """
    Seeds a dedicated listing fixture that has active security findings.
    Used to test guardrails against falsely claiming a clean scan.
    """
    listing_id = "test-findings-listing-002"
    version_id = "test-ver-002"

    db_session.query(ListingVersion).filter(ListingVersion.listing_id == listing_id).delete()
    db_session.query(Listing).filter(Listing.id == listing_id).delete()
    db_session.flush()

    listing = Listing(
        id=listing_id,
        seller_id="seller-seed-user-456",
        title="Legacy Gateway Proxy",
        description="Legacy API proxy gateway with deprecated authentication tokens.",
        price_cents=2900,  # $29.00
        category="developer-tools",
        status=ListingStatus.LIVE.value,
        status_message="Listing active with recorded warnings.",
        current_version_id=version_id,
    )
    db_session.add(listing)
    db_session.flush()

    version = ListingVersion(
        id=version_id,
        listing_id=listing.id,
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        scan_job_id="scan-job-isolated-002",
        storage_location="s3://softxchange-packages/legacy-gateway-1.0.0.zip",
        findings_summary={"critical": 0, "high": 1, "medium": 2, "low": 0},
        findings_detail=[
            {"rule": "hardcoded_token", "severity": "high", "snippet": "tok_123***"},
            {"rule": "deprecated_tls", "severity": "medium", "snippet": "TLSv1.0"},
            {"rule": "debug_mode", "severity": "medium", "snippet": "DEBUG=True"},
        ],
    )
    db_session.add(version)
    db_session.commit()
    db_session.refresh(listing)
    return listing


@pytest.fixture
def sample_seller_docs() -> list[SellerDocument]:
    """Provides sample seller-provided documentation."""
    return [
        SellerDocument(
            title="README.md",
            content="# Cloud Sentry CLI\nInstall with `pip install cloud-sentry`.\nConfigure AWS/GCP credentials in ~/.cloud-sentry/config.",
            doc_type="readme",
        ),
        SellerDocument(
            title="API_GUIDE.md",
            content="## API Reference\nUse `cloud_sentry.scan(target='...')` to trigger automated audits.",
            doc_type="api_docs",
        ),
    ]
