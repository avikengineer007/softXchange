"""
Unit tests for ml_shared.guardrails.
Verifies that:
1. Every individual hard-block rule has a dedicated test blocking a fabricated output.
2. Clean output matching the context bundle passes through completely unchanged.
3. Callers have a clean refusal contract (format_guardrail_refusal) preventing unhandled 500s.
"""

import pytest
from ml_shared.context import ListingContextBundle, ListingMetadata, ScanSummary
from ml_shared.guardrails import (
    check_guardrails,
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
)
from src.models.listing import Listing


@pytest.fixture
def verified_context(seeded_live_listing: Listing) -> ListingContextBundle:
    """Provides a verified context bundle ($59.00, passed scan, 0 findings)."""
    return ListingContextBundle.from_listing_and_scan(listing_data=seeded_live_listing)


@pytest.fixture
def context_with_vulnerabilities(seeded_listing_with_findings: Listing) -> ListingContextBundle:
    """Provides a context bundle with real recorded scan findings."""
    return ListingContextBundle.from_listing_and_scan(listing_data=seeded_listing_with_findings)


# ============================================================================
# Rule 1: Security & Safety Claims
# ============================================================================

def test_rule_1_blocks_unsupported_malware_free_claim(verified_context: ListingContextBundle):
    """
    Rule 1: Model must NEVER assert that software is 'malware-free' or '100% safe',
    as the scanner only looks for secrets/keys, not malware.
    """
    fabricated_output = (
        "Cloud Sentry CLI is an excellent security tool. Our team verified that this package "
        "is completely malware-free, virus-free, and 100% safe to deploy in production."
    )

    result = check_guardrails(fabricated_output, verified_context)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_1_SECURITY_SAFETY_CLAIM" in rule_ids

    # Verify enforce_guardrails raises GuardrailViolationError
    with pytest.raises(GuardrailViolationError) as exc_info:
        enforce_guardrails(fabricated_output, verified_context)

    # Verify clean caller refusal message (contract)
    refusal = format_guardrail_refusal(exc_info.value)
    assert "cannot make unsubstantiated safety or malware claims" in refusal


def test_rule_1_blocks_clean_scan_claim_when_findings_exist(context_with_vulnerabilities: ListingContextBundle):
    """
    Rule 1: Model must NEVER assert zero findings or clean scan when actual severity_counts
    indicates findings exist.
    """
    fabricated_output = (
        "You can safely buy Legacy Gateway Proxy. The security scan passed with zero findings "
        "and no issues found in the source code."
    )

    result = check_guardrails(fabricated_output, context_with_vulnerabilities)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_1_SECURITY_CONTRADICTS_SCAN" in rule_ids


# ============================================================================
# Rule 2: Transaction Finalization, Price Quoting & Warranty/Legal Claims
# ============================================================================

def test_rule_2a_blocks_sale_finalization(verified_context: ListingContextBundle):
    """
    Rule 2A: Model must NEVER finalize a sale or assert a completed transaction.
    """
    fabricated_output = (
        "Great choice! I have finalized the sale for Cloud Sentry CLI and charged your account. "
        "Your order is confirmed and the download license has been issued."
    )

    result = check_guardrails(fabricated_output, verified_context)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_2A_FINALIZE_SALE" in rule_ids

    with pytest.raises(GuardrailViolationError) as exc_info:
        enforce_guardrails(fabricated_output, verified_context)

    refusal = format_guardrail_refusal(exc_info.value)
    assert "cannot finalize transactions" in refusal


def test_rule_2b_blocks_incorrect_price_quote(verified_context: ListingContextBundle):
    """
    Rule 2B: Model must NEVER quote a price different from the listing's actual price_cents.
    Actual price is 5900 cents ($59.00). Model quotes $29.00.
    """
    fabricated_output = (
        "Cloud Sentry CLI is currently available on softXchange for only $29.00! "
        "Click the link to check it out."
    )

    result = check_guardrails(fabricated_output, verified_context)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_2B_PRICE_MISMATCH" in rule_ids

    with pytest.raises(GuardrailViolationError) as exc_info:
        enforce_guardrails(fabricated_output, verified_context)

    refusal = format_guardrail_refusal(exc_info.value)
    assert "cannot quote a different price" in refusal


def test_rule_2c_blocks_warranty_and_legal_claims(verified_context: ListingContextBundle):
    """
    Rule 2C: Model must NEVER make warranty, guarantee, or legal liability claims.
    """
    fabricated_output = (
        "Cloud Sentry CLI is $59.00 and comes with a 30-day money-back guarantee and full "
        "liability coverage if any secrets leak."
    )

    result = check_guardrails(fabricated_output, verified_context)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_2C_WARRANTY_LEGAL" in rule_ids

    with pytest.raises(GuardrailViolationError):
        enforce_guardrails(fabricated_output, verified_context)


# ============================================================================
# Rule 3: Platform Bypass (Off-Platform Transactions)
# ============================================================================

def test_rule_3_blocks_platform_bypass_attempt(verified_context: ListingContextBundle):
    """
    Rule 3: Model must NEVER draft content that suggests bypassing softXchange
    (e.g. paying via PayPal directly or contacting on Telegram).
    """
    fabricated_output = (
        "If you would like a discount on Cloud Sentry CLI, pay me via PayPal directly or "
        "contact me on Telegram @cloud_author to avoid platform fees."
    )

    result = check_guardrails(fabricated_output, verified_context)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_3_PLATFORM_BYPASS" in rule_ids

    with pytest.raises(GuardrailViolationError) as exc_info:
        enforce_guardrails(fabricated_output, verified_context)

    refusal = format_guardrail_refusal(exc_info.value)
    assert "cannot assist with off-platform payments" in refusal


# ============================================================================
# Rule 4: Severity Minimization (Seller-Assist Advisory)
# ============================================================================

def test_rule_4_blocks_minimizing_critical_or_high_severity():
    """
    Rule 4: Summary or draft must not downplay, minimize, or advise ignoring
    critical or high security findings.
    """
    downplaying_text = (
        "The security scan detected a critical finding, but don't worry about it. "
        "This critical finding is harmless and can be safely ignored."
    )

    result = check_guardrails(downplaying_text)
    assert not result.passed
    rule_ids = [v.rule_id for v in result.violations]
    assert "RULE_4_SEVERITY_MINIMIZATION" in rule_ids

    with pytest.raises(GuardrailViolationError) as exc_info:
        enforce_guardrails(downplaying_text)

    refusal = format_guardrail_refusal(exc_info.value)
    assert "cannot minimize or understate the severity" in refusal


def test_skip_price_check_allows_prepublish_draft_copy(verified_context: ListingContextBundle):
    """
    For pre-publish draft suggestions, the price is not yet finalized, so
    skip_price_check=True must allow mentioning a hypothetical or recommended price
    without triggering Rule 2B price mismatch.
    """
    draft_copy = (
        "Suggested description: Powerful cloud monitoring tool. "
        "Estimated market value around $45.00 based on comparable listings."
    )

    # Without skip_price_check, quoting $45.00 against verified_context ($59.00) fails Rule 2B
    result_default = check_guardrails(draft_copy, verified_context)
    assert not result_default.passed
    assert any("RULE_2B_PRICE_MISMATCH" in v.rule_id for v in result_default.violations)

    # With skip_price_check=True, price mismatch is skipped, other rules still enforced
    result_skip = check_guardrails(draft_copy, verified_context, skip_price_check=True)
    assert result_skip.passed

    # But unsupported security claims or platform bypass are STILL blocked even with skip_price_check=True
    bad_draft = draft_copy + " 100% safe and malware-free software."
    with pytest.raises(GuardrailViolationError):
        enforce_guardrails(bad_draft, verified_context, skip_price_check=True)


# ============================================================================
# Clean Output Verification
# ============================================================================

def test_clean_output_passes_through_unchanged(verified_context: ListingContextBundle):
    """
    Clean output:
    - Quotes actual price accurately ($59.00)
    - Quotes literal scan findings accurately ("0 critical findings")
    - Makes no warranty or legal claims
    - Makes no sale finalization claims
    - Keeps all transactions within softXchange
    
    Must pass through enforce_guardrails completely unchanged.
    """
    clean_output = (
        "Cloud Sentry CLI is available in the security category for $59.00. "
        "The automated security scan passed with 0 critical findings and 0 high findings. "
        "You can inspect the listing details and purchase the package on softXchange."
    )

    result = check_guardrails(clean_output, verified_context)
    assert result.passed
    assert len(result.violations) == 0

    checked_text = enforce_guardrails(clean_output, verified_context)
    assert checked_text == clean_output

