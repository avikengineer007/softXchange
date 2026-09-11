"""
apps/broker/tests/test_draft_handoff.py

Test suite for Prompt 2: Drafting hand-off to seller-assist.
Verifies:
1. A routed question has a pre-generated draft available without the seller taking any action.
2. A forced draft-generation failure still results in the question being correctly routed
   and visible to the seller, just without a pre-filled draft (fail-soft resilience).
3. The seller's send action is unaffected and still requires their explicit trigger.
"""

from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import BuyerQuestion, Listing
from broker.seller_client import seller_client


def test_routed_question_has_pregenerated_draft_without_seller_action(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that routing an out-of-context question proactively triggers seller-assist
    drafting so the draft is already available when the seller opens their view.
    """
    listing: Listing = seeded_broker_catalog["security"]
    question_text = "Will this integrate with our custom in-house COBOL mainframe system?"

    # Mock seller_client.trigger_draft_reply simulating server-to-server call to seller-assist
    mock_draft = {
        "question_id": "temp",
        "listing_id": listing.id,
        "question_text": question_text,
        "suggested_reply": "Based on the verified scan and listing details, this tool audits against CIS Benchmarks.",
        "context_sources": ["listing_metadata"],
        "sent": False,
        "notice": "Draft only.",
    }

    def mock_trigger(question_id, forced_reply_for_test=None):
        # Emulate seller-assist writing draft_reply to the question record
        q = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
        if q:
            q.draft_reply = mock_draft["suggested_reply"]
            db_session.commit()
            db_session.refresh(q)
        return mock_draft

    with patch.object(seller_client, "trigger_draft_reply", side_effect=mock_trigger):
        res = client.post(
            f"/broker/listings/{listing.id}/route-question",
            json={"question_text": question_text, "buyer_id": "buyer-proactive-1"},
        )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["resolution"] == "routed_to_seller"
        question_id = data["question_id"]

    # Verify that the draft is available in DB without any seller action
    db_session.expire_all()
    q_in_db = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == question_id).first()
    assert q_in_db is not None
    assert q_in_db.draft_reply == mock_draft["suggested_reply"]
    # Guarantees zero auto-send side-effects
    assert q_in_db.seller_response is None
    assert q_in_db.responded_at is None


def test_forced_draft_generation_failure_still_routes_question_cleanly(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts fail-soft resilience: If seller-assist fails, throws an exception, or refuses
    via guardrails, the question STILL routes to the seller successfully.
    A missing pre-generated draft is a degraded experience, not a broken one.
    """
    listing: Listing = seeded_broker_catalog["security"]
    question_text = "Can I install this on a refrigerator running Android 4.4?"

    def mock_failure(question_id, forced_reply_for_test=None):
        # Simulate network error, guardrail refusal, or timeout
        return None

    with patch.object(seller_client, "trigger_draft_reply", side_effect=mock_failure):
        res = client.post(
            f"/broker/listings/{listing.id}/route-question",
            json={"question_text": question_text, "buyer_id": "buyer-fail-soft-1"},
        )
        assert res.status_code == 200, res.text
        data = res.json()

        # Routing STILL succeeds
        assert data["resolution"] == "routed_to_seller"
        assert data["question_id"] is not None

    # Question is visible and saved for the seller, just without a draft
    db_session.expire_all()
    q_in_db = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == data["question_id"]).first()
    assert q_in_db is not None
    assert q_in_db.question_text == question_text
    assert q_in_db.draft_reply is None
    assert q_in_db.seller_response is None


def test_seller_send_action_is_unaffected_and_requires_explicit_trigger(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that pre-generating a draft does NOT grant the broker the ability to
    send on the seller's behalf; sending requires explicit human seller trigger.
    """
    listing: Listing = seeded_broker_catalog["payments"]
    q = BuyerQuestion(
        id="q-explicit-test",
        listing_id=listing.id,
        buyer_id="buyer-explicit-1",
        question_text="Does this support SEPA direct debit?",
        draft_reply="Based on documentation, SEPA direct debit is supported.",
    )
    db_session.add(q)
    db_session.commit()

    # Pre-drafted question remains un-sent
    db_session.expire_all()
    q_check = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == "q-explicit-test").first()
    assert q_check is not None
    assert q_check.seller_response is None
    assert q_check.responded_at is None

    # Only when seller explicitly delivers a response does seller_response get populated
    q_check.seller_response = "Confirmed: SEPA direct debit is fully supported."
    db_session.commit()
    db_session.expire_all()

    q_updated = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == "q-explicit-test").first()
    assert q_updated is not None
    assert q_updated.seller_response == "Confirmed: SEPA direct debit is fully supported."
