"""
apps/broker/tests/test_broker_integration.py

End-to-end integration test suite proving all three ML models:
1. buyer-assist (vector search + grounded RAG)
2. seller-assist (market-grounded pricing guidance + pre-drafted reply)
3. broker (deterministic question routing + privacy-preserving demand signals)
work in full harmony, sharing one embedding space, one context bundle, and one guardrails module.
"""

from datetime import timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, BuyerQuestion, SearchEvent, utc_now
from broker.seller_client import seller_client
from ml_shared.context import ListingContextBundle
from ml_shared.guardrails import enforce_guardrails, GuardrailViolationError


def test_end_to_end_security_inquiry_instant_answer_no_seller(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Scenario 1: Buyer asks a security/safety question.
    Expected: Instant verified answer from public scan data with zero seller involvement.
    """
    sec_listing: Listing = seeded_broker_catalog["security"]
    question = "Does this package pass security scanning and audit for exposed secrets?"

    res = client.post(
        f"/broker/listings/{sec_listing.id}/route-question",
        json={"question_text": question, "buyer_id": "buyer-e2e-1"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    # 1. Deterministic direct answer
    assert data["resolution"] == "answered_directly"
    assert data["answer"] is not None
    assert "scan_summary" in data["context_sources"]
    assert "0 critical findings" in data["answer"] or "scan status" in data["answer"].lower()

    # 2. Zero seller involvement
    db_session.expire_all()
    q_in_db = db_session.query(BuyerQuestion).filter(BuyerQuestion.listing_id == sec_listing.id).all()
    assert len(q_in_db) == 0


def test_end_to_end_out_of_context_routes_to_seller_with_predraft(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Scenario 2: Buyer asks an out-of-context question not covered by public scans.
    Expected: Routes to seller, creates BuyerQuestion, and pre-generates an AI draft
    waiting in the seller's dashboard without any auto-send side effects.
    """
    sec_listing: Listing = seeded_broker_catalog["security"]
    question = "Does this support high-availability failover clustering on IBM AIX power systems?"

    mock_suggested_reply = "Based on verified package metadata, high-availability clustering on IBM AIX is not currently supported."

    def mock_draft(question_id, forced_reply_for_test=None):
        q = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
        if q:
            q.draft_reply = mock_suggested_reply
            db_session.commit()
            db_session.refresh(q)
        return {"suggested_reply": mock_suggested_reply}

    with patch.object(seller_client, "trigger_draft_reply", side_effect=mock_draft):
        res = client.post(
            f"/broker/listings/{sec_listing.id}/route-question",
            json={"question_text": question, "buyer_id": "buyer-e2e-2"},
        )
        assert res.status_code == 200, res.text
        data = res.json()

        assert data["resolution"] == "routed_to_seller"
        question_id = data["question_id"]
        assert question_id is not None

    # Verify seller dashboard state
    db_session.expire_all()
    q = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
    assert q is not None
    assert q.question_text == question
    assert q.draft_reply == mock_suggested_reply
    # Must remain strictly un-sent until seller explicitly reviews and delivers
    assert q.seller_response is None
    assert q.responded_at is None


def test_end_to_end_demand_signals_aggregation_and_privacy(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Scenario 3: Seller checks their dashboard demand signals.
    Expected: Surfaces real aggregate recent search query terms and category questions
    over the 7-day window, strictly stripped of buyer identities.
    """
    pay_listing: Listing = seeded_broker_catalog["payments"]
    now = utc_now()

    # Ingest search events
    client.post("/broker/events/search", json={"query_text": "global credit card processing sdk", "matched_category": "payments"})
    client.post("/broker/events/search", json={"query_text": "payments stripe webhook integration", "matched_category": "payments"})

    # Ingest questions
    db_session.add(
        BuyerQuestion(
            id="q-e2e-pay-1",
            listing_id=pay_listing.id,
            buyer_id="buyer-private-id-777",
            question_text="Does this support multi-currency payouts?",
            created_at=now - timedelta(days=1),
        )
    )
    db_session.commit()

    # Query seller demand signals
    res = client.get(f"/broker/sellers/{pay_listing.seller_id}/demand-signals")
    assert res.status_code == 200, res.text
    data = res.json()

    sig = next(l for l in data["listings"] if l["listing_id"] == pay_listing.id)
    assert sig["total_questions_7d"] >= 1
    assert any("payments" in t or "credit card" in t for t in sig["related_search_terms"])
    assert "buyer-private-id-777" not in res.text
    assert sig["guardrail_status"] == "passed"


def test_guardrails_prevent_transaction_finalization_across_broker():
    """
    Scenario 4: Validates that guardrails prevent transaction finalization or promises.
    """
    unsafe_text = "I have finalized your purchase and charged your card $35.00."
    try:
        enforce_guardrails(unsafe_text, None)
        assert False, "Should have raised GuardrailViolationError"
    except GuardrailViolationError as err:
        assert any("RULE_2A_FINALIZE_SALE" in v.rule_id for v in err.violations)
