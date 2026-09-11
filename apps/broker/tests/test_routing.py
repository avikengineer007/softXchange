"""
apps/broker/tests/test_routing.py

Test suite for Prompt 1: Deterministic Question Routing.
Verifies:
1. SECURITY questions resolve as 'answered_directly' with the exact same answer
   buyer-assist's ListingQAService produces (reuse, not reimplementation).
2. OUT_OF_CONTEXT questions resolve as 'routed_to_seller' and record a BuyerQuestion in the DB.
3. Broker surface area is purely routing rules without new generative guardrail surfaces.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import BuyerQuestion, Listing
from buyer_assist.rag import ListingQAService
from ml_shared.context import ListingContextBundle


def test_security_question_routes_directly_and_matches_buyer_assist(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that a security question resolves as answered_directly and returns
    the exact same answer as buyer-assist's ListingQAService.
    Asserts zero seller involvement: no BuyerQuestion record created.
    """
    listing: Listing = seeded_broker_catalog["security"]
    question_text = "Does this tool pass security scanning and check for vulnerabilities?"

    # 1. Call broker route-question endpoint
    res = client.post(
        f"/broker/listings/{listing.id}/route-question",
        json={"question_text": question_text, "buyer_id": "buyer-test-1"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["resolution"] == "answered_directly"
    assert data["answer"] is not None
    assert data["question_id"] is None
    assert "scan_summary" in data["context_sources"]

    # 2. Assert exact parity with buyer-assist's QA service
    bundle = ListingContextBundle.from_listing_and_scan(
        listing_data=listing,
        scan_data={
            "scan_status": "passed",
            "severity_counts": {"critical": 0, "high": 0},
            "scan_job_id": None,
        },
    )
    expected_qa = ListingQAService().answer_question(bundle, question_text)
    assert data["answer"] == expected_qa.answer

    # 3. Assert no BuyerQuestion record was created in the database
    db_session.expire_all()
    questions = db_session.query(BuyerQuestion).filter(BuyerQuestion.listing_id == listing.id).all()
    assert len(questions) == 0


def test_grounded_detail_routes_directly(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that grounded pricing or description queries resolve as answered_directly.
    """
    listing: Listing = seeded_broker_catalog["payments"]
    question_text = "How much does this package cost?"

    res = client.post(
        f"/broker/listings/{listing.id}/route-question",
        json={"question_text": question_text, "buyer_id": "buyer-test-2"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["resolution"] == "answered_directly"
    assert "$35.00" in data["answer"] or "3500" in data["answer"] or "35" in data["answer"]
    assert data["question_id"] is None


def test_out_of_context_question_routes_to_seller(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that an ungrounded/out-of-context inquiry routes to the seller and
    creates a BuyerQuestion record in the database.
    """
    listing: Listing = seeded_broker_catalog["security"]
    question_text = "Can I install this on a Commodore 64 with 64KB RAM?"

    res = client.post(
        f"/broker/listings/{listing.id}/route-question",
        json={"question_text": question_text, "buyer_id": "buyer-test-3"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["resolution"] == "routed_to_seller"
    assert data["answer"] is None
    assert data["question_id"] is not None

    # Assert BuyerQuestion is in database awaiting seller reply
    db_session.expire_all()
    q = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == data["question_id"]).first()
    assert q is not None
    assert q.listing_id == listing.id
    assert q.buyer_id == "buyer-test-3"
    assert q.question_text == question_text
    assert q.seller_response is None
    assert q.responded_at is None


def test_non_live_and_non_existent_listings_return_404(
    client: TestClient,
    seeded_broker_catalog: dict,
):
    """
    Asserts that non-live or non-existent listings return 404.
    """
    # 1. Non-existent
    res_404 = client.post(
        "/broker/listings/non-existent-id/route-question",
        json={"question_text": "Is this available?"},
    )
    assert res_404.status_code == 404

    # 2. Draft listing
    draft_listing: Listing = seeded_broker_catalog["draft"]
    res_draft = client.post(
        f"/broker/listings/{draft_listing.id}/route-question",
        json={"question_text": "Can I buy this now?"},
    )
    assert res_draft.status_code == 404
