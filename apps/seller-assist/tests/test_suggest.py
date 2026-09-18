"""
apps/seller-assist/tests/test_suggest.py

Test suite for Prompt 1: Listing copy & pricing suggestions.
Verifies grounding, multi-currency support, sparse inventory degradation,
zero database side effects, authorization, and guardrail protection.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, ListingStatus  # type: ignore # pyrefly: ignore
from src.models.embedding import ListingEmbedding  # type: ignore # pyrefly: ignore
from seller_assist.suggest import (
    generate_listing_suggestions,
    CopySuggestionRequest,
)


def test_suggest_copy_grounded_in_comparables(client: TestClient, seller_token: str, seeded_listings):
    """
    Verifies that suggestions are grounded in real comparable listings,
    and pricing guidance accurately computes min (₹39.00), median (₹59.00), max (₹89.00).
    """
    res = client.post(
        "/assist/seller/listings/draft-target-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"currency": "INR", "region": "IN"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["listing_id"] == "draft-target-001"
    assert "suggested_title" in data
    assert "suggested_description" in data
    assert "Key Features & Highlights" in data["suggested_description"]

    # Price guidance
    guidance = data["price_guidance"]
    assert guidance is not None
    assert guidance["currency"] == "INR"
    assert guidance["base_min_cents"] == 3900
    assert guidance["base_median_cents"] == 5900
    assert guidance["base_max_cents"] == 8900
    assert guidance["recommended_range"] == "₹39.00 - ₹89.00"

    # Comparables
    comps = data["comparable_listings"]
    assert len(comps) == 3
    for comp in comps:
        assert comp["similarity_score"] > 0
        assert comp["category"] == "security"

    assert "Robust market data based on 3 comparable live listings" in data["confidence_note"]


def test_suggest_copy_canonical_inr_currency(client: TestClient, seller_token: str, seeded_listings):
    """
    Verifies single canonical INR currency localization across regions:
    All requests resolve to INR (₹).
    """
    res = client.post(
        "/assist/seller/listings/draft-target-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()
    guidance = data["price_guidance"]
    assert guidance["currency"] == "INR"
    assert guidance["currency_symbol"] == "₹"
    assert "₹" in guidance["recommended_range"]
    assert data["currency"] == "INR"


def test_suggest_copy_sparse_inventory_degradation(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies graceful degradation when marketplace inventory is sparse:
    - 0 comparables: price_guidance is null, explicit note to determine independently.
    - 1 comparable: price_guidance calculated, explicit limited market data note.
    """
    # Create isolated draft in a brand-new unique category with 0 live listings
    new_draft = Listing(
        id="draft-quantum-001",
        seller_id="seller-1",
        title="Quantum Cryptography Simulator",
        description="Post-quantum cryptographic simulation toolkit.",
        price_cents=10000,
        category="quantum-computing",
        status=ListingStatus.DRAFT.value,
    )
    db_session.add(new_draft)
    db_session.commit()

    # Case A: 0 comparables in category
    # Temporarily remove other listings to simulate brand new platform inventory
    db_session.query(ListingEmbedding).delete()
    db_session.commit()

    res_zero = client.post(
        "/assist/seller/listings/draft-quantum-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"k": 3},
    )
    assert res_zero.status_code == 200
    data_zero = res_zero.json()
    assert data_zero["price_guidance"] is None
    assert len(data_zero["comparable_listings"]) == 0
    assert "Insufficient market data: 0 comparable live listings" in data_zero["confidence_note"]

    # Case B: 1 comparable
    single_comp = Listing(
        id="live-quantum-002",
        seller_id="other-seller",
        title="Quantum Key Exchange Lib",
        description="Lattice-based cryptography library.",
        price_cents=7500,
        category="quantum-computing",
        status=ListingStatus.LIVE.value,
    )
    db_session.add(single_comp)
    db_session.commit()

    # Index single comp
    from ml_shared.embeddings import default_embedder
    vec = default_embedder.embed_document("Quantum Key Exchange Lib Lattice-based cryptography library.")
    emb = ListingEmbedding(
        listing_id="live-quantum-002",
        version_id="ver-1",
        embedding=vec,
        content_hash="hash1",
    )
    db_session.add(emb)
    db_session.commit()

    res_single = client.post(
        "/assist/seller/listings/draft-quantum-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"k": 3},
    )
    assert res_single.status_code == 200
    data_single = res_single.json()
    assert data_single["price_guidance"] is not None
    assert len(data_single["comparable_listings"]) == 1
    assert "Limited market data: calculated from only 1 comparable listing(s)" in data_single["confidence_note"]


def test_zero_database_side_effects(client: TestClient, seller_token: str, db_session: Session, seeded_listings):
    """
    Verifies that calling /suggest-copy has strictly ZERO side effects on the database.
    The Listing record remains 100% unchanged.
    """
    # Fetch initial state
    initial_listing = db_session.query(Listing).filter(Listing.id == "draft-target-001").first()
    initial_title = initial_listing.title
    initial_desc = initial_listing.description
    initial_price = initial_listing.price_cents
    initial_updated_at = initial_listing.updated_at

    # Call endpoint
    res = client.post(
        "/assist/seller/listings/draft-target-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "title": "A Brand New Suggested Name Overridden",
            "description": "Overridden description",
            "rough_price_cents": 12000,
        },
    )
    assert res.status_code == 200

    # Query afresh from DB
    db_session.expire_all()
    post_listing = db_session.query(Listing).filter(Listing.id == "draft-target-001").first()

    assert post_listing.title == initial_title
    assert post_listing.description == initial_desc
    assert post_listing.price_cents == initial_price
    assert post_listing.updated_at == initial_updated_at
    assert post_listing.status == ListingStatus.DRAFT.value


def test_authorization_checks(client: TestClient, other_seller_token: str, buyer_token: str, seeded_listings):
    """
    Verifies seller-only and owner-only authorization:
    - 401 without token
    - 403 with buyer token
    - 403 with another seller's token (not owner)
    """
    url = "/assist/seller/listings/draft-target-001/suggest-copy"

    # 1. No token
    res_no_auth = client.post(url, json={})
    assert res_no_auth.status_code == 401

    # 2. Buyer token
    res_buyer = client.post(url, headers={"Authorization": f"Bearer {buyer_token}"}, json={})
    assert res_buyer.status_code == 403

    # 3. Different seller (not owner)
    res_other = client.post(url, headers={"Authorization": f"Bearer {other_seller_token}"}, json={})
    assert res_other.status_code == 403
    assert "permission" in res_other.json()["detail"].lower()


def test_guardrail_catches_adversarial_draft_overclaim(client: TestClient, seller_token: str, seeded_listings):
    """
    Adversarial test on actual generation path:
    If a seller submits a draft attempting to provoke unsupported security claims
    (e.g. '100% bug-free and completely malware-free'), the generation path
    triggers enforce_guardrails and returns a 422 refusal, never leaking the unsafe copy.
    """
    res = client.post(
        "/assist/seller/listings/draft-target-001/suggest-copy",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={
            "description": "Our scanner ensures this package is completely malware-free and 100% safe for all environments.",
        },
    )
    assert res.status_code == 422
    err_detail = res.json()["detail"]
    assert err_detail["error"] == "guardrail_violation"
    assert "cannot make unsubstantiated safety or malware claims" in err_detail["message"]
    assert any("RULE_1" in r for r in err_detail["violated_rules"])
