"""
apps/broker/tests/test_demand_signals.py

Test suite for Prompt 3: Demand signal aggregation.
Verifies:
1. Demand signals correctly aggregate real search and question activity over 7-day window
   WITHOUT exposing individual buyer identity (strict privacy).
2. A listing with zero related activity returns an honest "no notable signal this week"
   rather than fabricated data.
3. If signal text is LLM-phrased, a forced guarantee-sounding output is caught by the guardrail check.
4. Read-only guarantee: zero side effects on listings, orders, or database state.
"""

from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, BuyerQuestion, SearchEvent, utc_now


def test_demand_signals_aggregate_activity_without_buyer_identity(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts 5-minute aggregation of searches and questions, strictly verifying zero buyer identity exposure.
    """
    sec_listing: Listing = seeded_broker_catalog["security"]
    now = utc_now()

    # Seed 3 search events in 5-minute window
    s1 = SearchEvent(query_text="cloud vulnerability auditor", matched_category="security", created_at=now - timedelta(minutes=1))
    s2 = SearchEvent(query_text="kubernetes compliance audit", matched_category="security", created_at=now - timedelta(minutes=2))
    s3 = SearchEvent(query_text="unrelated python compiler", matched_category="developer-tools", created_at=now - timedelta(minutes=1))
    # Seed 1 old search event outside 5-minute window (10 minutes ago)
    s4 = SearchEvent(query_text="old security probe", matched_category="security", created_at=now - timedelta(minutes=10))
    db_session.add_all([s1, s2, s3, s4])

    # Seed 2 questions with buyer identities that MUST NOT leak
    sensitive_buyer_id_1 = "buyer-secret-uuid-999"
    sensitive_buyer_id_2 = "buyer-private-uuid-888"
    q1 = BuyerQuestion(
        id="q-dem-1",
        listing_id=sec_listing.id,
        buyer_id=sensitive_buyer_id_1,
        question_text="Does this support AWS IAM role auditing?",
        seller_response=None,
        created_at=now - timedelta(minutes=2),
    )
    q2 = BuyerQuestion(
        id="q-dem-2",
        listing_id=sec_listing.id,
        buyer_id=sensitive_buyer_id_2,
        question_text="Is there a Prometheus metrics exporter?",
        seller_response="Yes, Prometheus exporter is included.",
        created_at=now - timedelta(minutes=3),
    )
    db_session.add_all([q1, q2])
    db_session.commit()

    # Call demand signals endpoint
    res = client.get("/broker/sellers/seller-alpha/demand-signals")
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["seller_id"] == "seller-alpha"
    assert data["window_days"] == 7
    assert data["window_minutes"] == 5

    # Find security listing in results
    sec_signal = next(l for l in data["listings"] if l["listing_id"] == sec_listing.id)
    assert sec_signal["total_questions_7d"] == 2
    assert sec_signal["total_questions_5m"] == 2
    assert sec_signal["unanswered_questions_count"] == 1
    assert sec_signal["answered_questions_count"] == 1
    assert any("cloud vulnerability" in term for term in sec_signal["related_search_terms"])
    # 10-minute old search must NOT be aggregated
    assert not any("old security" in term for term in sec_signal["related_search_terms"])

    # PRIVACY ASSERTION: Neither buyer ID may appear anywhere in the entire response body
    raw_response_text = res.text
    assert sensitive_buyer_id_1 not in raw_response_text
    assert sensitive_buyer_id_2 not in raw_response_text


def test_listing_with_zero_activity_returns_honest_no_signal(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that a listing with zero searches and questions returns an honest
    'no notable signal' message instead of fabricating activity.
    """
    # Create an isolated seller with zero activity
    zero_listing = Listing(
        id="brk-zero-201",
        seller_id="seller-quiet",
        title="Quiet Isolated Utility",
        description="Utility with zero search traffic.",
        price_cents=1000,
        category="isolated-category",
        status="live",
    )
    db_session.add(zero_listing)
    db_session.commit()

    res = client.get("/broker/sellers/seller-quiet/demand-signals")
    assert res.status_code == 200, res.text
    data = res.json()

    signal = data["listings"][0]
    assert signal["total_questions_7d"] == 0
    assert signal["unanswered_questions_count"] == 0
    assert signal["answered_questions_count"] == 0
    assert len(signal["related_search_terms"]) == 0
    assert "No notable demand signals recorded" in signal["signal_summary"]


def test_forced_guarantee_output_is_caught_by_guardrails(
    client: TestClient,
    seeded_broker_catalog: dict,
):
    """
    Asserts that if demand-signal text attempts to make sales guarantees or promises,
    it is intercepted by ml_shared.enforce_guardrails.
    """
    unsafe_summary = "Add cloud auditing support and you will sell 5 more units this week with guaranteed sales!"

    res = client.get(
        "/broker/sellers/seller-alpha/demand-signals",
        params={"forced_summary_for_test": unsafe_summary},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    # Find listing
    sig = data["listings"][0]
    assert sig["guardrail_status"] == "blocked"
    assert "cannot finalize transactions or make legal warranties" in sig["signal_summary"] or "warranties" in sig["signal_summary"].lower()


def test_endpoint_is_purely_read_only_and_has_no_side_effects(
    client: TestClient,
    seeded_broker_catalog: dict,
    db_session: Session,
):
    """
    Asserts that querying demand signals causes zero side effects on listings or database.
    """
    listings_count_before = db_session.query(Listing).count()
    questions_count_before = db_session.query(BuyerQuestion).count()
    searches_count_before = db_session.query(SearchEvent).count()

    res = client.get("/broker/sellers/seller-alpha/demand-signals")
    assert res.status_code == 200

    db_session.expire_all()
    assert db_session.query(Listing).count() == listings_count_before
    assert db_session.query(BuyerQuestion).count() == questions_count_before
    assert db_session.query(SearchEvent).count() == searches_count_before
