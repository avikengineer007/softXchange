"""
Integration tests for ListingContextBundle.
Verifies that the context bundle accurately represents real listings-service / scan-service data
using dedicated, isolated fixtures (never synthetic mocks, and never ambient dev database remnants).
"""

import pytest
from ml_shared.context import ListingContextBundle, ListingMetadata, ScanSummary, SellerDocument
from src.models.listing import Listing, ListingVersion


def test_context_bundle_from_real_orm_listing(seeded_live_listing: Listing, sample_seller_docs: list[SellerDocument]):
    """
    Integration test: Loads an authentic SQLAlchemy Listing and ListingVersion instance
    created in the database, verifying all fields without re-derivation.
    """
    # Act: Construct bundle using the canonical factory
    bundle = ListingContextBundle.from_listing_and_scan(
        listing_data=seeded_live_listing,
        seller_docs=sample_seller_docs,
    )

    # Assert: Core listing metadata
    assert bundle.listing.id == "test-live-listing-001"
    assert bundle.listing.title == "Cloud Sentry CLI"
    assert bundle.listing.seller_id == "seller-seed-user-123"
    assert bundle.listing.description == "High performance automated cloud vulnerability scanner with instant reporting."
    assert bundle.listing.category == "security"
    assert bundle.listing.status == "live"
    assert bundle.listing.version_label == "1.0.0"

    # Assert: Exact price conversion
    assert bundle.listing.price_cents == 5900
    assert bundle.price_usd == 59.00
    assert bundle.formatted_price == "$59.00"

    # Assert: Scan summary is pulled directly and NOT re-derived
    assert bundle.scan_summary.scan_status == "passed"
    assert bundle.scan_summary.vetted is True
    assert bundle.scan_summary.badge == "Scanned — 0 critical findings"
    assert bundle.scan_summary.severity_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert bundle.scan_summary.scan_job_id == "scan-job-isolated-001"

    # Assert: Seller documents attached
    assert len(bundle.seller_docs) == 2
    assert bundle.seller_docs[0].title == "README.md"
    assert bundle.seller_docs[0].doc_type == "readme"
    assert "pip install cloud-sentry" in bundle.seller_docs[0].content


def test_context_bundle_from_service_api_payload(sample_seller_docs: list[SellerDocument]):
    """
    Integration test: Verifies bundle construction from the exact JSON dictionary
    payload returned by listings-service GET /listings/{id} and scan-service GET /status/{id}/{ver}.
    """
    # Real payload structure from listings-service get_listing_detail
    listing_api_payload = {
        "id": "1b8643a9-a673-4995-a91a-73330e3eb072",
        "seller_id": "seller-42",
        "title": "Cloud Sentry CLI",
        "description": "Enterprise cloud security audit utility.",
        "price_cents": 5900,
        "price_usd": 59.0,
        "category": "security",
        "status": "live",
        "status_message": "Vetted and active.",
        "vetted": True,
        "badge": "Scanned — 0 critical findings",
        "current_version": {
            "id": "ver-abc-123",
            "listing_id": "1b8643a9-a673-4995-a91a-73330e3eb072",
            "version_label": "1.0.0",
            "scan_status": "passed",
            "scan_job_id": "scan-job-999",
            "storage_location": "s3://softxchange/cloud-sentry.zip",
            "created_at": "2026-09-09T10:00:00Z",
        },
        "created_at": "2026-09-09T09:00:00Z",
        "updated_at": "2026-09-09T10:00:00Z",
    }

    # Real payload structure from scan-service get_scan_status
    scan_api_payload = {
        "listing_id": "1b8643a9-a673-4995-a91a-73330e3eb072",
        "version": "1.0.0",
        "scan_status": "passed",
        "scan_job_id": "scan-job-999",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
    }

    bundle = ListingContextBundle.from_listing_and_scan(
        listing_data=listing_api_payload,
        scan_data=scan_api_payload,
        seller_docs=sample_seller_docs,
    )

    assert bundle.listing.id == "1b8643a9-a673-4995-a91a-73330e3eb072"
    assert bundle.listing.price_cents == 5900
    assert bundle.price_usd == 59.00
    assert bundle.scan_summary.vetted is True
    assert bundle.scan_summary.severity_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert bundle.listing.version_label == "1.0.0"


def test_context_bundle_prompt_rendering(seeded_live_listing: Listing, sample_seller_docs: list[SellerDocument]):
    """
    Verifies that the bundle formats into a single, structured representation
    used identically by both buyer-assist and seller-assist models.
    """
    bundle = ListingContextBundle.from_listing_and_scan(
        listing_data=seeded_live_listing,
        seller_docs=sample_seller_docs,
    )
    prompt_text = bundle.to_prompt_context()

    # Must contain essential groundings
    assert "# Listing: Cloud Sentry CLI" in prompt_text
    assert "- **Price**: $59.00 (5900 cents)" in prompt_text
    assert "- **Marketplace Status**: live" in prompt_text
    assert "- **Vetted Status**: Verified / Vetted" in prompt_text
    assert "- **Scan Status**: passed" in prompt_text
    assert "- **Severity Counts**: critical: 0, high: 0, medium: 0, low: 0" in prompt_text
    assert "## Seller Documentation" in prompt_text
    assert "### README.md (readme)" in prompt_text
    assert "pip install cloud-sentry" in prompt_text
