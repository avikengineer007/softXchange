"""
packages/ml-shared/tests/test_rag.py

Unit and integration tests for ListingQAService and AnswerResult in ml_shared.
"""

import pytest
from ml_shared.context import ListingContextBundle, ListingMetadata, ScanSummary, SellerDocument
from ml_shared.rag import ListingQAService, AnswerResult


@pytest.fixture
def sample_bundle() -> ListingContextBundle:
    metadata = ListingMetadata(
        id="test-listing-rag-1",
        seller_id="seller-rag-user",
        title="Payment Gateway SDK",
        description="Fast and secure Python SDK for multi-currency payment processing.",
        category="developer-tools",
        price_cents=4900,
        status="live",
        version_label="2.1.0",
    )
    scan = ScanSummary(
        scan_status="passed",
        vetted=True,
        badge="Scanned — 0 critical findings",
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=0,
        severity_counts={"medium": 1},
        scanned_at="2026-09-01T12:00:00Z",
    )
    docs = [
        SellerDocument(
            title="Setup Guide",
            content="To initialize, configure your API key with `client = PaymentClient(api_key=...)`.",
        )
    ]
    return ListingContextBundle(
        listing=metadata,
        scan_summary=scan,
        seller_docs=docs,
        price_usd=49.0,
        formatted_price="$49.00",
    )


def test_qa_service_empty_question(sample_bundle: ListingContextBundle):
    qa = ListingQAService()
    res = qa.answer_question(sample_bundle, "   ")
    assert res.grounded is False
    assert res.guardrail_status == "passed"
    assert "specific question" in res.answer


def test_qa_service_price_question(sample_bundle: ListingContextBundle):
    qa = ListingQAService()
    res = qa.answer_question(sample_bundle, "How much does this cost?")
    assert res.grounded is True
    assert "$49.00" in res.answer
    assert "listing_metadata" in res.context_sources


def test_qa_service_security_question(sample_bundle: ListingContextBundle):
    qa = ListingQAService()
    res = qa.answer_question(sample_bundle, "Is this secure?")
    assert res.grounded is True
    assert "scan_summary" in res.context_sources
    assert "passed" in res.answer
    assert "medium: 1" in res.answer


def test_qa_service_doc_question(sample_bundle: ListingContextBundle):
    qa = ListingQAService()
    res = qa.answer_question(sample_bundle, "How do I initialize the client setup?")
    assert res.grounded is True
    assert "seller_doc: Setup Guide" in res.context_sources
    assert "PaymentClient" in res.answer


def test_qa_service_out_of_context(sample_bundle: ListingContextBundle):
    qa = ListingQAService()
    res = qa.answer_question(sample_bundle, "Can this make a pizza delivery?")
    assert res.grounded is False
    assert "not covered in the verified listing details" in res.answer
