"""
apps/buyer-assist/tests/test_search.py

Tests for buyer-assist natural language listing search:
1. Sensible ranking across realistic technical queries.
2. Relevance floor prunes false-positive noise on unrelated queries.
3. Embedding updates when a listing's live version changes.
4. Strict live-only enforcement (non-live / withdrawn listings are never returned).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus
from src.models.embedding import ListingEmbedding
from src.indexer import sync_live_listing_embedding, remove_listing_embedding


def test_sensible_query_ranking(client: TestClient, seeded_catalog: dict):
    """
    Verifies that realistic natural language queries rank the most relevant
    live software package at the top of the search results.
    """
    # Test 1: Security search
    resp_sec = client.post("/assist/search", json={
        "query": "scan cloud infrastructure for security vulnerabilities and audit AWS",
    })
    assert resp_sec.status_code == 200
    data_sec = resp_sec.json()
    assert data_sec["total"] >= 1
    assert data_sec["results"][0]["listing_id"] == "list-sec-001"
    assert data_sec["results"][0]["title"] == "Cloud Sentry CLI"
    assert data_sec["results"][0]["price_cents"] == 5900
    assert data_sec["results"][0]["price_usd"] == 59.00
    assert data_sec["results"][0]["similarity_score"] >= 0.25

    # Test 2: Payments search
    resp_pay = client.post("/assist/search", json={
        "query": "process credit card payments and stripe webhook integration",
    })
    assert resp_pay.status_code == 200
    data_pay = resp_pay.json()
    assert data_pay["total"] >= 1
    assert data_pay["results"][0]["listing_id"] == "list-pay-002"
    assert data_pay["results"][0]["title"] == "FastPay Checkout SDK"

    # Test 3: Logging search
    resp_log = client.post("/assist/search", json={
        "query": "structured log ingestion pipeline and distributed tracing collector",
    })
    assert resp_log.status_code == 200
    data_log = resp_log.json()
    assert data_log["total"] >= 1
    assert data_log["results"][0]["listing_id"] == "list-log-003"
    assert data_log["results"][0]["title"] == "LogStash JSON Parser"


def test_relevance_floor_on_unrelated_query(client: TestClient, seeded_catalog: dict):
    """
    Verifies that a completely unrelated query (e.g. recipe for cake) returns 0 results
    because all similarity scores fall below the default min_score = 0.25 floor.
    """
    resp = client.post("/assist/search", json={
        "query": "recipe for grandma's homemade chocolate fudge birthday cake",
        "min_score": 0.25,
    })
    assert resp.status_code == 200
    data = resp.json()
    # Must prune out false positives rather than confidently showing unrelated software
    assert data["total"] == 0
    assert data["results"] == []


def test_embedding_updates_when_live_version_changes(client: TestClient, db_session: Session, seeded_catalog: dict):
    """
    Verifies that when a listing's live version changes, its embedding updates,
    and subsequent searches immediately reflect the new focus.
    """
    listing: Listing = seeded_catalog["security"]

    # Initial check: querying kubernetes container telemetry does NOT match Cloud Sentry CLI as #1
    # Now simulate a new version going live with container focus
    new_version = ListingVersion(
        id="ver-sec-002",
        listing_id=listing.id,
        version_label="2.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(new_version)

    listing.title = "KubePulse Container Monitor"
    listing.description = "Real-time Kubernetes container pod monitor, cluster telemetry, and memory diagnostics."
    listing.current_version_id = new_version.id
    db_session.commit()

    # Trigger live embedding sync (as done by evaluate_publish_gate / sync_seller_kyc)
    sync_live_listing_embedding(listing, new_version, db_session)

    # Verify that the stored embedding row updated its content hash and version_id
    emb_row = db_session.query(ListingEmbedding).filter(ListingEmbedding.listing_id == listing.id).first()
    assert emb_row is not None
    assert emb_row.version_id == "ver-sec-002"

    # Search for kubernetes container telemetry
    resp = client.post("/assist/search", json={
        "query": "kubernetes container pod telemetry and memory diagnostics",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert data["results"][0]["listing_id"] == listing.id
    assert data["results"][0]["title"] == "KubePulse Container Monitor"
    assert data["results"][0]["version_label"] == "2.0.0"


def test_live_only_guarantee_excludes_withdrawn_and_draft(client: TestClient, db_session: Session, seeded_catalog: dict):
    """
    Verifies that search never returns withdrawn or draft listings,
    reusing listings-service's own live-only guarantee.
    """
    # 1. Withdrawn listing test
    # "Secret Keeper Vault" is withdrawn, even though query matches its description directly
    resp_vault = client.post("/assist/search", json={
        "query": "cryptographic key vault and secret management daemon with encrypted storage",
        "min_score": 0.1,  # Low floor to test exclusion
    })
    assert resp_vault.status_code == 200
    results_vault = resp_vault.json()["results"]
    listing_ids = [r["listing_id"] for r in results_vault]
    assert "list-withdrawn-004" not in listing_ids

    # 2. Draft listing test
    # "Network Firewall Mesh" is draft
    resp_draft = client.post("/assist/search", json={
        "query": "zero trust software defined perimeter network firewall",
        "min_score": 0.1,
    })
    assert resp_draft.status_code == 200
    results_draft = resp_draft.json()["results"]
    draft_ids = [r["listing_id"] for r in results_draft]
    assert "list-draft-005" not in draft_ids

    # 3. Dynamic withdrawal test: Withdrawing a live listing purges it from search immediately
    live_listing = seeded_catalog["payments"]
    live_listing.status = ListingStatus.WITHDRAWN.value
    db_session.commit()
    remove_listing_embedding(live_listing.id, db_session)

    resp_pay = client.post("/assist/search", json={
        "query": "credit card stripe payments",
    })
    assert resp_pay.status_code == 200
    after_ids = [r["listing_id"] for r in resp_pay.json()["results"]]
    assert "list-pay-002" not in after_ids
