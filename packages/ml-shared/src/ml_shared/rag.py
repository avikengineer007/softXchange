"""
packages/ml-shared/src/ml_shared/rag.py

Grounded Question-Answering (RAG) Engine over ListingContextBundle.
Shared ML Foundation component for softXchange (buyer-assist, seller-assist, broker).

Core Invariants:
1. Strictly Grounded: Answers only from facts present in the listing bundle and seller docs.
2. Exact Security Claims: For security/safety questions, quotes real severity_counts and
   badge status. Explicitly states what the scanner does NOT check (e.g. malware, runtime bugs)
   rather than providing false reassurance.
3. Honest Refusal: Explicitly states when questions are outside the context bundle rather
   than hallucinating or guessing from general knowledge.
4. Genuine Provenance: Accurately tracks which specific sources (scan_summary, listing_metadata,
   seller_doc: <name>) were genuinely referenced.
5. Fail-Closed Guardrails: Routes all generated answers through ml_shared.enforce_guardrails.
   Never returns an unchecked response to a user.
"""

from __future__ import annotations
import logging
import re
from typing import List, Tuple, Optional
from pydantic import BaseModel, Field

from ml_shared.context import ListingContextBundle
from ml_shared.guardrails import (
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
)

logger = logging.getLogger("ml_shared.rag")

# Keyword patterns indicating security / safety inquiries
_SECURITY_INTENT_PATTERNS = [
    r"\bsaf(?:e|ety)\b",
    r"\bvulnerabilit(?:y|ies)\b",
    r"\bmalware\b",
    r"\bvirus(?:es)?\b",
    r"\blegit(?:imate)?\b",
    r"\bsecur(?:e|ity)\b",
    r"\bscan(?:ned|ner)?\b",
    r"\bfindings?\b",
    r"\brisk\b",
    r"\baudit\b",
    r"\bhack(?:ed|able)?\b",
    r"\bbreach\b",
    r"\bsecrets?\b",
    r"\bcredentials?\b",
]
_SECURITY_INTENT_REGEX = re.compile("|".join(_SECURITY_INTENT_PATTERNS), re.IGNORECASE)

# Keywords indicating specific requests for absolute reassurance
_ADVERSARIAL_REASSURANCE_PATTERNS = [
    r"\breassure\b",
    r"\bjust\s+tell\s+me\b",
    r"\b100%\b",
    r"\bcompletely\s+safe\b",
    r"\btotally\s+safe\b",
    r"\bmalware[- ]free\b",
    r"\bvirus[- ]free\b",
    r"\bpromise\b",
    r"\bguarantee\b",
]
_ADVERSARIAL_REGEX = re.compile("|".join(_ADVERSARIAL_REASSURANCE_PATTERNS), re.IGNORECASE)


class AnswerResult(BaseModel):
    """Result of the RAG generation and guardrail enforcement."""
    answer: str
    grounded: bool
    context_sources: List[str] = Field(default_factory=list)
    guardrail_status: str = "passed"


class ListingQAService:
    """
    RAG service answering buyer questions grounded strictly in ListingContextBundle.
    """

    def __init__(self, force_guardrail_violation_for_testing: Optional[str] = None):
        """
        Optional hook to inject a forced output for testing fail-closed guardrail interception.
        """
        self._test_injection = force_guardrail_violation_for_testing

    def answer_question(self, bundle: ListingContextBundle, question: str) -> AnswerResult:
        """
        Generates grounded answer and enforces guardrails. Fail-closed.
        """
        clean_q = question.strip()
        if not clean_q:
            return AnswerResult(
                answer="Please provide a specific question about this listing.",
                grounded=False,
                context_sources=[],
                guardrail_status="passed",
            )

        # 1. Synthesize candidate response and dynamic provenance
        if self._test_injection:
            candidate_answer = self._test_injection
            sources = ["test_injection"]
            is_grounded = True
        else:
            candidate_answer, sources, is_grounded = self._synthesize_answer(bundle, clean_q)

        # 2. Strict Fail-Closed Guardrail Check
        try:
            verified_answer = enforce_guardrails(candidate_answer, bundle)
            return AnswerResult(
                answer=verified_answer,
                grounded=is_grounded,
                context_sources=sources,
                guardrail_status="passed",
            )
        except GuardrailViolationError as gv_err:
            logger.warning(f"Guardrail intercepted violation in generated answer: {gv_err}")
            refusal_text = format_guardrail_refusal(gv_err)
            return AnswerResult(
                answer=refusal_text,
                grounded=False,
                context_sources=sources,
                guardrail_status="blocked",
            )
        except Exception as exc:
            logger.error(f"Unexpected error evaluating guardrails: {exc}", exc_info=True)
            # Fail closed: never leak an unchecked answer
            return AnswerResult(
                answer="I cannot answer this question at this time because security policy checks could not be completed.",
                grounded=False,
                context_sources=[],
                guardrail_status="error_refusal",
            )

    def _synthesize_answer(
        self, bundle: ListingContextBundle, question: str
    ) -> Tuple[str, List[str], bool]:
        """
        Synthesizes an answer grounded only in the context bundle.
        Determines genuine provenance based on facts used.
        """
        q_lower = question.lower()
        is_security_question = bool(_SECURITY_INTENT_REGEX.search(q_lower))
        is_adversarial_pressure = bool(_ADVERSARIAL_REGEX.search(q_lower))

        sources: List[str] = []
        answer_parts: List[str] = []

        # --------------------------------------------------------------------
        # 1. Security Aspect (Strictest Rule Applied)
        # --------------------------------------------------------------------
        if is_security_question:
            sources.append("scan_summary")
            sev = bundle.scan_summary.severity_counts or {}
            sev_strs = [f"{k}: {v}" for k, v in sev.items()] if sev else ["0 critical findings"]
            sev_display = ", ".join(sev_strs)

            if is_adversarial_pressure:
                answer_parts.append(
                    f"I cannot make absolute safety claims or declare absence of malware. "
                    f"The softXchange automated security scan specifically audits packages for exposed secrets, "
                    f"private credentials, and hardcoded API tokens. It does not perform dynamic malware analysis. "
                    f"According to the verified scan result, this listing has status '{bundle.scan_summary.scan_status}' "
                    f"with the following recorded findings: {sev_display} ({bundle.scan_summary.badge})."
                )

            else:
                answer_parts.append(
                    f"According to the automated security scan, this listing has a scan status of '{bundle.scan_summary.scan_status}' "
                    f"and holds the '{bundle.scan_summary.badge}' badge. "
                    f"The recorded severity counts are: {sev_display}. "
                    f"Note: The security scan verifies that no secrets, credentials, or private keys were leaked in the source; "
                    f"it does not evaluate dynamic malware or general software bugs."
                )

        # --------------------------------------------------------------------
        # 2. Capability, Description, Pricing, & Documentation Aspects
        # --------------------------------------------------------------------
        # Check listing metadata relevance
        listing_text = f"{bundle.listing.title} {bundle.listing.description} {bundle.listing.category}".lower()
        question_words = [w for w in re.findall(r"[a-zA-Z0-9]+", q_lower) if len(w) > 3]

        # Check if question asks about price / cost
        is_price_question = any(w in q_lower for w in ["price", "cost", "how much", "cents", "pricing"])
        if is_price_question:
            sources.append("listing_metadata")
            answer_parts.append(
                f"The verified price for {bundle.listing.title} is {bundle.formatted_price}."
            )

        # Check for matches in description or category
        meta_matches = [w for w in question_words if w in listing_text and w not in ["safe", "security", "price", "cost"]]
        if meta_matches and not is_price_question:
            sources.append("listing_metadata")
            answer_parts.append(
                f"Based on the listing description: {bundle.listing.description.strip()}"
            )

        # Check seller-provided docs
        for doc in bundle.seller_docs:
            doc_content_lower = doc.content.lower()
            doc_matches = [w for w in question_words if w in doc_content_lower and w not in meta_matches]
            if doc_matches:
                doc_source_name = f"seller_doc: {doc.title}"
                if doc_source_name not in sources:
                    sources.append(doc_source_name)
                # Extract snippet
                answer_parts.append(
                    f"According to {doc.title}: {doc.content.strip()}"
                )

        # --------------------------------------------------------------------
        # 3. Uncovered / Out-of-Context Check
        # --------------------------------------------------------------------
        # If no security and no metadata/doc matches were found, honestly refuse
        if not answer_parts:
            return (
                f"This information is not covered in the verified listing details or seller documentation for "
                f"'{bundle.listing.title}'. The marketplace assistant cannot make assumptions or answer from "
                f"outside the provided listing context.",
                [],
                False,
            )

        combined_answer = " ".join(answer_parts)
        return combined_answer, sources, True
