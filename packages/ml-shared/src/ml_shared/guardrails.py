"""
ml_shared.guardrails

Hard-block guardrail rules enforced in code (not just prompt instructions)
before any model output reaches a user:

1. RULE_SECURITY_CLAIMS:
   Never assert a security/safety claim the scan result doesn't literally support
   (e.g. model must not say 'malware-free' — it can only say what the scan actually found,
   quoting the real severity_counts from the context bundle).

2. RULE_TRANSACTION_PRICE_LEGAL:
   - Never finalize a sale or assert a completed transaction.
   - Never quote a different price than the listing's actual price_cents.
   - Never make a warranty, guarantee, or legal liability claim.

3. RULE_PLATFORM_BYPASS:
   Never draft content that bypasses the platform's existing systems
   (e.g. suggesting buyer/seller transact or communicate outside softXchange).

HONEST LABELING NOTE ON RULE 3:
Rule 3 uses high-precision regex and phrase pattern matching. Like all textual filters,
it is a defense-in-depth barrier, not an airtight semantic guarantee against indirect
adversarial evasion. Edge cases should be logged for human audit/review.

CALLER REFUSAL CONTRACT:
When enforce_guardrails raises GuardrailViolationError, API callers (/assist/search,
/assist/listings/{id}/ask) MUST catch this exception and return a clean refusal response
via format_guardrail_refusal() or structured refusal payload, rather than failing with an
unhandled 500 error.
"""

from __future__ import annotations
import logging
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from ml_shared.context import ListingContextBundle

logger = logging.getLogger("ml_shared.guardrails")


class RuleViolation(BaseModel):
    """Details of a single violated guardrail rule."""
    rule_id: str
    rule_name: str
    message: str
    evidence: str


class GuardrailResult(BaseModel):
    """Outcome of evaluating guardrails against generated text."""
    passed: bool
    violations: List[RuleViolation] = Field(default_factory=list)
    output_text: str


class GuardrailRefusal(BaseModel):
    """Standard structured refusal payload for API endpoints."""
    blocked: bool = True
    refusal_message: str
    violated_rules: List[str]


class GuardrailViolationError(ValueError):
    """Raised by enforce_guardrails when one or more hard-block rules are violated."""
    def __init__(self, violations: List[RuleViolation], output_text: str):
        self.violations = violations
        self.output_text = output_text
        summary = "; ".join(f"[{v.rule_id}] {v.message} (matched: '{v.evidence}')" for v in violations)
        super().__init__(f"Guardrail check failed: {summary}")


# ============================================================================
# Rule 1: Security & Safety Claims
# ============================================================================

# Terms asserting absolute security/malware absence which our scanner engine
# (which detects hardcoded secrets/keys) does not literally test for or guarantee.
_ABSOLUTE_SAFETY_PATTERNS = [
    r"\bmalware[- ]free\b",
    r"\bvirus[- ]free\b",
    r"\b100%\s+safe\b",
    r"\bcompletely\s+safe\b",
    r"\btotally\s+safe\b",
    r"\bguaranteed\s+safe\b",
    r"\bunhackable\b",
    r"\bzero\s+vulnerabilit(?:y|ies)\b",
    r"\bno\s+vulnerabilit(?:y|ies)\b",
    r"\bflawless\s+security\b",
    r"\bimmune\s+to\s+attacks?\b",
    r"\bbug[- ]free\b",
    r"\bcompletely\s+secure\b",
    r"\b100%\s+secure\b",
    r"\bzero\s+security\s+risks?\b",
]

_ABSOLUTE_SAFETY_REGEX = re.compile("|".join(_ABSOLUTE_SAFETY_PATTERNS), re.IGNORECASE)

_CLEAN_SCAN_ASSERTION_PATTERNS = [
    r"\b(?:found\s+)?0\s+findings\b",
    r"\bno\s+findings\b",
    r"\bclean\s+scan\b",
    r"\bno\s+issues\s+found\b",
    r"\bpassed\s+with\s+zero\b",
]
_CLEAN_SCAN_REGEX = re.compile("|".join(_CLEAN_SCAN_ASSERTION_PATTERNS), re.IGNORECASE)


def check_rule_security_claims(output_text: str, context: ListingContextBundle) -> List[RuleViolation]:
    violations: List[RuleViolation] = []

    # 1. Absolute safety / malware claims
    match = _ABSOLUTE_SAFETY_REGEX.search(output_text)
    if match:
        violations.append(
            RuleViolation(
                rule_id="RULE_1_SECURITY_SAFETY_CLAIM",
                rule_name="Unsupported Security/Safety Assertion",
                message=(
                    "Output makes an absolute security or malware assertion that the scan result "
                    "does not literally support. The model must only state what the scanner checked "
                    "and quote the actual severity_counts."
                ),
                evidence=match.group(0),
            )
        )

    # 2. Asserting zero findings or clean scan when severity_counts contains findings > 0
    if context and context.scan_summary:
        sev = context.scan_summary.severity_counts or {}
        total_findings = sum(sev.values())
        if total_findings > 0:
            clean_match = _CLEAN_SCAN_REGEX.search(output_text)
            if clean_match:
                violations.append(
                    RuleViolation(
                        rule_id="RULE_1_SECURITY_CONTRADICTS_SCAN",
                        rule_name="Scan Results Contradicted",
                        message=(
                            f"Output asserts zero findings or clean scan, but actual scan summary has "
                            f"{total_findings} findings: {sev}"
                        ),
                        evidence=clean_match.group(0),
                    )
                )

    return violations


# ============================================================================
# Rule 2: Transaction Finalization, Price Accuracy, & Legal/Warranty Claims
# ============================================================================

_SALE_FINALIZATION_PATTERNS = [
    r"\b(?:i\s+have\s+)?(?:finalized|completed)\s+(?:the|your)\s+(?:sale|purchase|order|transaction)\b",
    r"\border\s+(?:is\s+)?confirmed\b",
    r"\bpayment\s+(?:has\s+been\s+)?(?:processed|charged|received)\b",
    r"\bcharged\s+your\s+(?:card|account|credit\s+card)\b",
    r"\bsale\s+(?:is\s+)?finalized\b",
    r"\btransaction\s+(?:is\s+)?complete(?:d)?\b",
    r"\byou\s+now\s+own\s+this\s+package\b",
    r"\btransferred\s+ownership\s+to\s+you\b",
    r"\bcontract\s+(?:has\s+been\s+)?executed\b",
]
_SALE_FINALIZATION_REGEX = re.compile("|".join(_SALE_FINALIZATION_PATTERNS), re.IGNORECASE)

_WARRANTY_LEGAL_PATTERNS = [
    r"\bmoney[- ]back\s+guarantee\b",
    r"\blifetime\s+warranty\b",
    r"\bfull\s+warranty\b",
    r"\bwe\s+legally\s+(?:warrant|guarantee)\b",
    r"\blegally\s+binding\s+(?:promise|warranty|guarantee)\b",
    r"\bfull\s+liability\s+(?:coverage|protection|indemnity)\b",
    r"\bindemnif(?:y|ication)\s+guaranteed\b",
    r"\bguaranteed\s+refund\b",
    r"\b100%\s+money\s+back\b",
]
_WARRANTY_LEGAL_REGEX = re.compile("|".join(_WARRANTY_LEGAL_PATTERNS), re.IGNORECASE)

# Pattern to find prices quoted in output like $49, $49.00, 49 dollars, $59.99
_PRICE_QUOTE_REGEX = re.compile(
    r"""
    (?:[\$\€\£\₹\₽\¥]\s*([0-9]+(?:\.[0-9]{1,2})?))            # e.g. $49, €49, £49, ₹49, ₽49
    |
    (?:\b([0-9]+(?:\.[0-9]{1,2})?)\s*(?:usd|dollars|rub|rubles|inr|rupees|eur|euros|gbp|pounds|yen)\b)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def check_rule_transaction_price_legal(
    output_text: str,
    context: Optional[ListingContextBundle] = None,
    skip_price_check: bool = False,
) -> List[RuleViolation]:
    violations: List[RuleViolation] = []

    # 1. Finalize sale
    match_sale = _SALE_FINALIZATION_REGEX.search(output_text)
    if match_sale:
        violations.append(
            RuleViolation(
                rule_id="RULE_2A_FINALIZE_SALE",
                rule_name="Sale Finalization Forbidden",
                message="AI models assist in discovery but must never finalize a sale or claim a transaction occurred.",
                evidence=match_sale.group(0),
            )
        )

    # 2. Warranty / Legal claim
    match_warranty = _WARRANTY_LEGAL_REGEX.search(output_text)
    if match_warranty:
        violations.append(
            RuleViolation(
                rule_id="RULE_2C_WARRANTY_LEGAL",
                rule_name="Warranty/Legal Claim Forbidden",
                message="AI models must never assert legal warranties, indemnification, or money-back guarantees.",
                evidence=match_warranty.group(0),
            )
        )

    # 3. Quoting a different price than actual price_cents (skipped if skip_price_check=True)
    if not skip_price_check and context is not None:
        actual_cents = context.listing.price_cents
        actual_usd = context.price_usd

        for p_match in _PRICE_QUOTE_REGEX.finditer(output_text):
            num_str = p_match.group(1) or p_match.group(2)
            if not num_str:
                continue
            try:
                val = float(num_str)
                quoted_cents = int(round(val * 100))
                # Price matches if within 1 cent tolerance (handles floating point rounding)
                if abs(quoted_cents - actual_cents) > 1:
                    violations.append(
                        RuleViolation(
                            rule_id="RULE_2B_PRICE_MISMATCH",
                            rule_name="Price Quoted Does Not Match Listing",
                            message=(
                                f"Quoted price of ${val:.2f} does not match listing's actual price of "
                                f"${actual_usd:.2f} ({actual_cents} cents)."
                            ),
                            evidence=p_match.group(0),
                        )
                    )
                    break
            except ValueError:
                continue

    return violations


# ============================================================================
# Rule 3: Platform Bypass (Off-Platform Transactions)
# ============================================================================

_BYPASS_PATTERNS = [
    # External Payment Methods
    r"\b(?:pay|wire|send\s+money)\s+(?:me|via)\s+(?:crypto|bitcoin|btc|eth|usdt|paypal|venmo|cashapp|zelle|bank\s+transfer)\b",
    r"\bpay\s+outside\s+softxchange\b",
    r"\btransact\s+outside\s+(?:the\s+)?platform\b",
    r"\bdeal\s+directly\s+outside\b",
    r"\bbypass\s+(?:softxchange|the\s+platform|platform\s+fees?)\b",
    r"\bavoid\s+(?:platform|marketplace)\s+fees?\b",
    r"\boff[- ]platform\s+(?:deal|transaction|payment)\b",
    # Off-platform communication to circumvent platform
    r"\bcontact\s+(?:me|us)\s+(?:on|via)\s+(?:telegram|whatsapp|signal|discord|wechat)\b",
    r"\bmessage\s+(?:me|us)\s+(?:on|via)\s+(?:telegram|whatsapp|signal|discord)\b",
    r"\bemail\s+me\s+directly\s+(?:at|to\s+buy)\b",
]

_BYPASS_REGEX = re.compile("|".join(_BYPASS_PATTERNS), re.IGNORECASE)


def check_rule_platform_bypass(output_text: str, context: Optional[ListingContextBundle] = None) -> List[RuleViolation]:
    violations: List[RuleViolation] = []
    match = _BYPASS_REGEX.search(output_text)
    if match:
        violations.append(
            RuleViolation(
                rule_id="RULE_3_PLATFORM_BYPASS",
                rule_name="Platform Bypass Forbidden",
                message=(
                    "Output suggests transacting or communicating outside softXchange to bypass "
                    "platform protections or fees."
                ),
                evidence=match.group(0),
            )
        )
    return violations


# ============================================================================
# Rule 4: Severity Minimization (Seller-Assist Advisory)
# ============================================================================

_SEVERITY_MINIMIZATION_PATTERNS = [
    r"\b(?:this|the)?\s*(?:critical|high)\s*(?:finding|issue|vulnerability|risk|alert|warning)?\s*(?:is|are)?\s*(?:harmless|minor|trivial|negligible|not a big deal|nothing to worry about|safe to ignore|can be ignored|unimportant)\b",
    r"\bignore\s+(?:this|the|any)?\s*(?:critical|high)\s*(?:finding|issue|vulnerability|alert|severity)\b",
    r"\b(?:not\s+a\s+big\s+deal|nothing\s+to\s+worry\s+about|don't\s+worry\s+about\s+it)\b",
    r"\b(?:safely\s+ignore(?:d)?|safe\s+to\s+disregard)\b",
    r"\b(?:critical|high)\s+(?:issue|finding|vulnerability)\s+(?:is\s+actually\s+(?:low|minor|trivial))\b",
    r"\bdescrib(?:e|ing)\s+(?:a\s+)?critical\s+finding\s+as\s+(?:minor|low|harmless)\b",
]

_SEVERITY_MINIMIZATION_REGEX = re.compile("|".join(_SEVERITY_MINIMIZATION_PATTERNS), re.IGNORECASE)


def check_rule_severity_minimization(output_text: str, context: Optional[ListingContextBundle] = None) -> List[RuleViolation]:
    violations: List[RuleViolation] = []
    match = _SEVERITY_MINIMIZATION_REGEX.search(output_text)
    if match:
        violations.append(
            RuleViolation(
                rule_id="RULE_4_SEVERITY_MINIMIZATION",
                rule_name="Severity Minimization Forbidden",
                message=(
                    "Output inappropriately understates, minimizes, or advises ignoring "
                    "critical or high security findings."
                ),
                evidence=match.group(0),
            )
        )
    return violations


# ============================================================================
# Public Guardrails API
# ============================================================================

def check_guardrails(
    output_text: str,
    context: Optional[ListingContextBundle] = None,
    skip_price_check: bool = False,
) -> GuardrailResult:
    """
    Evaluates all hard-block rules against generated model output.
    Returns a GuardrailResult containing pass/fail status and any violations found.
    """
    violations: List[RuleViolation] = []
    violations.extend(check_rule_security_claims(output_text, context))
    violations.extend(check_rule_transaction_price_legal(output_text, context, skip_price_check=skip_price_check))
    violations.extend(check_rule_platform_bypass(output_text, context))
    violations.extend(check_rule_severity_minimization(output_text, context))

    return GuardrailResult(
        passed=len(violations) == 0,
        violations=violations,
        output_text=output_text,
    )


def enforce_guardrails(
    output_text: str,
    context: Optional[ListingContextBundle] = None,
    skip_price_check: bool = False,
) -> str:
    """
    Enforces all hard-block rules on model output before returning to user.
    
    Returns:
        output_text unchanged if all rules pass.
        
    Raises:
        GuardrailViolationError: If any hard-block rule is violated.
        Callers must catch this exception and return a clean refusal response
        (via format_guardrail_refusal()) rather than an unhandled 500 error.
    """
    result = check_guardrails(output_text, context, skip_price_check=skip_price_check)
    if not result.passed:
        logger.warning(
            f"Guardrail hard-block triggered: {[v.rule_id for v in result.violations]}"
        )
        raise GuardrailViolationError(violations=result.violations, output_text=output_text)

    return output_text


def format_guardrail_refusal(exc: GuardrailViolationError) -> str:
    """
    Produces a safe, polite user-facing refusal response when guardrails trip.
    Guarantees callers do not propagate raw 500 internal server errors.
    """
    rule_ids = {v.rule_id for v in exc.violations}

    if any("RULE_1" in rid for rid in rule_ids):
        return (
            "I cannot make unsubstantiated safety or malware claims. "
            "I can only provide verified facts directly recorded by our security scanner."
        )
    if "RULE_2B_PRICE_MISMATCH" in rule_ids:
        return (
            "I cannot quote a different price than the verified price listed on softXchange."
        )
    if any("RULE_2" in rid for rid in rule_ids):
        return (
            "I cannot finalize transactions or make legal warranties. "
            "All purchases must be completed through the official softXchange checkout."
        )
    if "RULE_3_PLATFORM_BYPASS" in rule_ids:
        return (
            "I cannot assist with off-platform payments or transactions. "
            "All softXchange transactions must occur within the platform to maintain buyer protections."
        )
    if "RULE_4_SEVERITY_MINIMIZATION" in rule_ids:
        return (
            "I cannot minimize or understate the severity of detected security findings. "
            "All findings must be remediated or presented with full factual accuracy."
        )

    return (
        "I cannot fulfill this request because the response violates softXchange marketplace safety policies."
    )
