"""
apps/seller-assist/tests/test_reply.py

Test suite for Prompt 3: Drafted buyer-reply suggestions.
Verifies grounded draft generation, strict draft-only behavior (zero auto-send side effects),
explicit manual delivery, guardrail interception before the seller sees it, and owner authorization.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus, BuyerQuestion


def test_draft_reply_grounded_and_no_send_side_effects(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies:
    1. A draft reply is generated and accurately grounded in the listing's scan results.
    2. Calling the draft endpoint has ZERO side effect of sending anything to the buyer
       (seller_response and responded_at remain None).
    """
    listing = Listing(
        id="list-qa-001",
        seller_id="seller-1",
        title="Cloud Audit Probe",
        description="Comprehensive AWS and GCP auditing scanner.",
        price_cents=6900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-qa-1",
    )
    db_session.add(listing)

    version = ListingVersion(
        id="ver-qa-1",
        listing_id="list-qa-001",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(version)

    question = BuyerQuestion(
        id="q-001",
        listing_id="list-qa-001",
        buyer_id="buyer-42",
        question_text="Does this tool pass security scanning and check for vulnerabilities?",
    )
    db_session.add(question)
    db_session.commit()

    # Call draft-reply endpoint
    res = client.post(
        "/assist/seller/questions/q-001/draft-reply",
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["question_id"] == "q-001"
    assert data["sent"] is False
    assert "Draft only" in data["notice"]
    assert "suggested_reply" in data
    # Grounded answer quotes real scan result
    assert "0 critical findings" in data["suggested_reply"] or "scan" in data["suggested_reply"].lower()

    # Verify zero side effect on database: question remains unanswered
    db_session.expire_all()
    q_in_db = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == "q-001").first()
    assert q_in_db.seller_response is None
    assert q_in_db.responded_at is None


def test_explicit_send_delivers_reply(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies that sending requires a separate, explicit action (POST .../send),
    which writes seller_response and updates responded_at.
    """
    listing = Listing(
        id="list-qa-002",
        seller_id="seller-1",
        title="Database Sharding Router",
        description="High throughput SQL router.",
        price_cents=4500,
        category="infrastructure",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-qa-2",
    )
    db_session.add(listing)

    version = ListingVersion(
        id="ver-qa-2",
        listing_id="list-qa-002",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(version)

    question = BuyerQuestion(
        id="q-002",
        listing_id="list-qa-002",
        buyer_id="buyer-99",
        question_text="Can this handle PostgreSQL connection pooling?",
    )
    db_session.add(question)
    db_session.commit()

    # Explicit send
    send_payload = {
        "response_text": "Yes, it fully supports PostgreSQL connection pooling up to 10,000 active connections."
    }
    res = client.post(
        "/assist/seller/questions/q-002/send",
        headers={"Authorization": f"Bearer {seller_token}"},
        json=send_payload,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["sent"] is True
    assert data["seller_response"] == send_payload["response_text"]
    assert data["responded_at"] is not None

    # Query DB to confirm persistence
    db_session.expire_all()
    q_in_db = db_session.query(BuyerQuestion).filter(BuyerQuestion.id == "q-002").first()
    assert q_in_db.seller_response == send_payload["response_text"]
    assert q_in_db.responded_at is not None


def test_guardrail_catches_unsupported_claim_in_draft(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies that a forced guardrail violation in a draft is caught and refused
    before the seller ever sees it.
    """
    listing = Listing(
        id="list-qa-003",
        seller_id="seller-1",
        title="Microservice Tracer",
        description="OpenTelemetry distributed tracing agent.",
        price_cents=3900,
        category="developer-tools",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-qa-3",
    )
    db_session.add(listing)

    version = ListingVersion(
        id="ver-qa-3",
        listing_id="list-qa-003",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
    )
    db_session.add(version)

    question = BuyerQuestion(
        id="q-003",
        listing_id="list-qa-003",
        buyer_id="buyer-77",
        question_text="Is this completely malware-free?",
    )
    db_session.add(question)
    db_session.commit()

    # Injected draft containing absolute safety claim
    unsafe_draft = "Yes, our team guarantees this tracer is 100% safe and completely malware-free."

    res = client.post(
        "/assist/seller/questions/q-003/draft-reply",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"forced_reply_for_test": unsafe_draft},
    )
    assert res.status_code == 422
    err_detail = res.json()["detail"]
    assert err_detail["error"] == "guardrail_violation"
    assert "cannot make unsubstantiated safety or malware claims" in err_detail["message"]
    assert any("RULE_1" in r for r in err_detail["violated_rules"])


def test_reply_authorization_checks(client: TestClient, other_seller_token: str, buyer_token: str, db_session: Session):
    """
    Verifies owner-only authorization for drafting and sending replies:
    - 401 without token
    - 403 with buyer token
    - 403 with non-owner seller token
    """
    listing = Listing(
        id="list-qa-auth",
        seller_id="seller-1",
        title="Auth Test Listing",
        description="Listing to test reply auth.",
        price_cents=2900,
        category="security",
        status=ListingStatus.LIVE.value,
    )
    db_session.add(listing)

    question = BuyerQuestion(
        id="q-auth-1",
        listing_id="list-qa-auth",
        buyer_id="buyer-1",
        question_text="Is this available?",
    )
    db_session.add(question)
    db_session.commit()

    url_draft = "/assist/seller/questions/q-auth-1/draft-reply"
    url_send = "/assist/seller/questions/q-auth-1/send"

    # 1. No auth
    assert client.post(url_draft).status_code == 401
    assert client.post(url_send, json={"response_text": "hello"}).status_code == 401

    # 2. Buyer token
    assert client.post(url_draft, headers={"Authorization": f"Bearer {buyer_token}"}).status_code == 403
    assert client.post(url_send, headers={"Authorization": f"Bearer {buyer_token}"}, json={"response_text": "hello"}).status_code == 403

    # 3. Other seller token
    assert client.post(url_draft, headers={"Authorization": f"Bearer {other_seller_token}"}).status_code == 403
    assert client.post(url_send, headers={"Authorization": f"Bearer {other_seller_token}"}, json={"response_text": "hello"}).status_code == 403
