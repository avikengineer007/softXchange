"""
apps/seller-assist/tests/test_explain.py

Test suite for Prompt 2: Plain-English scan finding summaries.
Verifies accurate reflection of mixed-severity findings, honest zero-findings handling,
guardrail enforcement against severity minimization (RULE_4_SEVERITY_MINIMIZATION),
and owner-only authorization.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus


def test_explain_findings_mixed_severities(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies that findings with a mix of severities (CRITICAL, HIGH, MEDIUM, LOW)
    are accurately grouped and translated into plain English, restating engine remediation hints.
    """
    listing = Listing(
        id="list-flawed-001",
        seller_id="seller-1",
        title="Payment Gateway Adapter",
        description="Stripe and PayPal integration adapter.",
        price_cents=4900,
        category="developer-tools",
        status=ListingStatus.SCAN_FAILED.value,
        current_version_id="ver-flawed-1",
    )
    db_session.add(listing)

    raw_findings = [
        {
            "rule_id": "RULE_AWS_KEY",
            "severity": "CRITICAL",
            "file_path": "config/aws.py",
            "line_number": 14,
            "description": "Hardcoded AWS Secret Access Key detected",
            "remediation_hint": "Store credentials in environment variables or AWS Secrets Manager.",
        },
        {
            "rule_id": "RULE_STRIPE_KEY",
            "severity": "HIGH",
            "file_path": "src/payments.py",
            "line_number": 42,
            "description": "Live Stripe Secret Key hardcoded in source",
            "remediation_hint": "Rotate key immediately and pass via STRIPE_SECRET_KEY env var.",
        },
        {
            "rule_id": "RULE_DEBUG_FLAG",
            "severity": "MEDIUM",
            "file_path": "main.py",
            "line_number": 8,
            "description": "Debug mode enabled in production build",
            "remediation_hint": "Set DEBUG=False before publishing package.",
        },
        {
            "rule_id": "RULE_TODO_COMMENT",
            "severity": "LOW",
            "file_path": "utils.py",
            "line_number": 105,
            "description": "Security TODO comment found in production code",
            "remediation_hint": "Resolve security TODO before submitting version.",
        },
    ]

    version = ListingVersion(
        id="ver-flawed-1",
        listing_id="list-flawed-001",
        version_label="1.0.0",
        scan_status=ScanStatus.SCAN_FAILED.value,
        findings_summary={"critical": 1, "high": 1, "medium": 1, "low": 1},
        findings_detail=raw_findings,
    )
    db_session.add(version)
    db_session.commit()

    res = client.post(
        "/assist/seller/versions/ver-flawed-1/explain-findings",
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["version_id"] == "ver-flawed-1"
    assert data["total_findings"] == 4
    assert data["has_issues"] is True

    # Check severity counts
    counts = data["severity_counts"]
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1

    # Check grouped findings
    grouped = data["grouped_findings"]
    assert len(grouped["CRITICAL"]) == 1
    assert grouped["CRITICAL"][0]["rule_id"] == "RULE_AWS_KEY"
    assert "config/aws.py" in grouped["CRITICAL"][0]["plain_english_summary"]
    assert "AWS Secrets Manager" in grouped["CRITICAL"][0]["remediation_action"]

    assert len(grouped["HIGH"]) == 1
    assert grouped["HIGH"][0]["rule_id"] == "RULE_STRIPE_KEY"
    assert "Rotate key immediately" in grouped["HIGH"][0]["remediation_action"]

    # Check overall plain-English summary
    summary = data["overall_summary"]
    assert "1 Critical, 1 High, 1 Medium, 1 Low" in summary
    assert "CRITICAL Severity (1):" in summary
    assert "Next Steps:" in summary


def test_explain_findings_zero_findings_clean_scan(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies that a version with zero findings produces an honest 'no issues found'
    confirmation rather than fabricated filler content.
    """
    listing = Listing(
        id="list-clean-001",
        seller_id="seller-1",
        title="Secure Hash Validator",
        description="Cryptographic hash verification tool.",
        price_cents=2900,
        category="security",
        status=ListingStatus.LIVE.value,
        current_version_id="ver-clean-1",
    )
    db_session.add(listing)

    version = ListingVersion(
        id="ver-clean-1",
        listing_id="list-clean-001",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0, "high": 0},
        findings_detail=[],
    )
    db_session.add(version)
    db_session.commit()

    res = client.post(
        "/assist/seller/versions/ver-clean-1/explain-findings",
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["version_id"] == "ver-clean-1"
    assert data["total_findings"] == 0
    assert data["has_issues"] is False
    assert "0 security findings" in data["overall_summary"]
    assert "completed successfully" in data["overall_summary"]


def test_guardrail_catches_severity_minimization(client: TestClient, seller_token: str, db_session: Session):
    """
    Verifies that a summary attempting to downplay or trivialize a CRITICAL finding
    is caught by RULE_4_SEVERITY_MINIMIZATION and refused before reaching the seller.
    """
    listing = Listing(
        id="list-flawed-002",
        seller_id="seller-1",
        title="Cloud Identity Broker",
        description="SSO and SAML broker.",
        price_cents=9900,
        category="security",
        status=ListingStatus.SCAN_FAILED.value,
        current_version_id="ver-flawed-2",
    )
    db_session.add(listing)

    version = ListingVersion(
        id="ver-flawed-2",
        listing_id="list-flawed-002",
        version_label="1.0.0",
        scan_status=ScanStatus.SCAN_FAILED.value,
        findings_summary={"critical": 1, "high": 0},
        findings_detail=[
            {
                "rule_id": "RULE_RSA_PRIVATE_KEY",
                "severity": "CRITICAL",
                "file_path": "certs/server.key",
                "line_number": 1,
                "description": "Unencrypted RSA Private Key committed to repo",
                "remediation_hint": "Remove private key from repo and rotate certificate.",
            }
        ],
    )
    db_session.add(version)
    db_session.commit()

    # Injected downplaying summary minimizing the CRITICAL finding
    downplaying_summary = (
        "The security scan detected a critical finding in certs/server.key, but don't worry about it. "
        "This critical finding is harmless and can be safely ignored."
    )

    res = client.post(
        "/assist/seller/versions/ver-flawed-2/explain-findings",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"forced_summary_for_test": downplaying_summary},
    )
    assert res.status_code == 422
    err_detail = res.json()["detail"]
    assert err_detail["error"] == "guardrail_violation"
    assert "cannot minimize or understate the severity" in err_detail["message"]
    assert "RULE_4_SEVERITY_MINIMIZATION" in err_detail["violated_rules"]


def test_explain_findings_authorization(client: TestClient, other_seller_token: str, buyer_token: str, db_session: Session):
    """
    Verifies seller-only and owner-only authorization:
    - 401 without token
    - 403 with buyer token
    - 403 with non-owner seller token
    """
    listing = Listing(
        id="list-owner-test",
        seller_id="seller-1",
        title="Owner Test Package",
        description="Package to test owner auth.",
        price_cents=1900,
        category="utilities",
        status=ListingStatus.DRAFT.value,
    )
    db_session.add(listing)
    version = ListingVersion(
        id="ver-owner-test",
        listing_id="list-owner-test",
        version_label="1.0.0",
        scan_status=ScanStatus.PASSED.value,
        findings_summary={"critical": 0},
        findings_detail=[],
    )
    db_session.add(version)
    db_session.commit()

    url = "/assist/seller/versions/ver-owner-test/explain-findings"

    # 1. No auth
    res_no_auth = client.post(url)
    assert res_no_auth.status_code == 401

    # 2. Buyer token
    res_buyer = client.post(url, headers={"Authorization": f"Bearer {buyer_token}"})
    assert res_buyer.status_code == 403

    # 3. Non-owner seller token
    res_other = client.post(url, headers={"Authorization": f"Bearer {other_seller_token}"})
    assert res_other.status_code == 403
