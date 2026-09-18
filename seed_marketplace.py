import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone

import importlib

# Add listings-service to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "apps" / "listings-service"))

_db_mod = importlib.import_module("src.database")
SessionLocal = _db_mod.SessionLocal
init_db = _db_mod.init_db

_listing_mod = importlib.import_module("src.models.listing")
Listing = _listing_mod.Listing
ListingVersion = _listing_mod.ListingVersion
ListingStatus = _listing_mod.ListingStatus
ScanStatus = _listing_mod.ScanStatus
utc_now = _listing_mod.utc_now

_indexer_mod = importlib.import_module("src.indexer")
sync_live_listing_embedding = _indexer_mod.sync_live_listing_embedding

# Seed packages for marketplace initialization.
# Note: price_cents represents integer minor currency units (paise, where 1 INR = 100 paise; e.g. 4900 = ₹49.00).
SEED_PACKAGES = [
    {
        "title": "Cloud Sentry CLI",
        "category": "security",
        "price_cents": 4900,
        "version_label": "1.2.0",
        "description": "Automated AWS and GCP infrastructure security scanner and IAM policy auditor. Detects privilege escalation risks, open S3 buckets, and non-compliant firewall rules directly in your CI/CD pipelines.",
    },
    {
        "title": "DataFlow ETL Toolkit",
        "category": "developer-tools",
        "price_cents": 8900,
        "version_label": "2.1.0",
        "description": "High-throughput streaming ETL pipeline connectors for Kafka, Apache Spark, and Parquet data lakes. Includes automatic schema drift detection and resilient dead-letter queue handling.",
    },
    {
        "title": "AuthShield MFA & Passkeys SDK",
        "category": "security",
        "price_cents": 2900,
        "version_label": "1.4.2",
        "description": "Zero-knowledge FIDO2 / WebAuthn passwordless authentication SDK for Python and Node.js. Fully compliant with NIST 800-63B standards with built-in cryptographic replay protection.",
    },
    {
        "title": "KubeWatch Observability Suite",
        "category": "infrastructure",
        "price_cents": 0,
        "version_label": "1.0.0",
        "description": "Lightweight Kubernetes cluster monitoring and OpenTelemetry tracing agent. Instant anomaly detection on container crash loops, OOM kills, and DNS resolution latency.",
    },
    {
        "title": "GitHistory Sanitizer Pro",
        "category": "utilities",
        "price_cents": 1900,
        "version_label": "3.0.1",
        "description": "Deep repository forensic analysis and automated secret stripping tool. Safely purges leaked API keys, tokens, and private SSH keys from git commit trees without breaking commit history.",
    },
    {
        "title": "TaskMatrix Automation Engine",
        "category": "productivity",
        "price_cents": 3900,
        "version_label": "1.1.0",
        "description": "High-efficiency async distributed task queue with priority scheduling, cron-style recurring workflows, and instant retry backoffs for modern microservice architectures.",
    },
]


def seed():
    if os.getenv("ENVIRONMENT", "").lower() == "production":
        raise RuntimeError(
            "SECURITY FATAL: seed_marketplace.py injects synthetic mock listings directly without "
            "passing the scan gate or uploading real package archives to storage. "
            "Direct mock seeding is prohibited in production. Onboard founding sellers via the verified "
            "seller upload and security scan pipeline."
        )
    init_db()
    db = SessionLocal()
    try:
        # Check if already seeded with live packages
        live_count = db.query(Listing).filter(Listing.status == ListingStatus.LIVE.value).count()
        if live_count > 0:
            print(f"Database already contains {live_count} live listings.")
            return

        print(f"Seeding {len(SEED_PACKAGES)} vetted software packages...")
        seller_id = "seller-verified-corp-001"

        for pkg in SEED_PACKAGES:
            listing = Listing(
                seller_id=seller_id,
                title=pkg["title"],
                description=pkg["description"],
                price_cents=pkg["price_cents"],
                category=pkg["category"],
                status=ListingStatus.LIVE.value,
                status_message="Security scan passed. Seller identity verified.",
            )
            db.add(listing)
            db.flush()

            version = ListingVersion(
                listing_id=listing.id,
                version_label=pkg["version_label"],
                scan_status=ScanStatus.PASSED.value,
                scan_job_id=f"scan-job-{uuid.uuid4().hex[:8]}",
                findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                findings_detail=[],
            )
            db.add(version)
            db.commit()

            listing.current_version_id = version.id
            db.commit()
            db.refresh(listing)

            # Synchronize vector embedding for search
            try:
                sync_live_listing_embedding(listing=listing, version=version, db=db)
            except Exception as e:
                print(f"Note: Embedding generation skipped for {listing.title}: {e}")

            print(f"  + Added: {listing.title} ({listing.category}, ${listing.price_cents/100:.2f})")

        print("Seeding complete! All packages are live and vetted.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
