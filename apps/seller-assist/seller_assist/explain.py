"""
apps/seller-assist/seller_assist/explain.py

Plain-English translation layer for raw security scan findings.
Faithfully translates rule_id, severity, and remediation_hint from deterministic
scanner reports into clear, actionable seller guidance without adding new claims.

Strict guarantees:
1. Rules decide, LLM only explains: strictly grounded in actual findings.
2. Only consumes already-redacted findings from scan_status/findings_detail.
3. Groups findings by severity (CRITICAL, HIGH, MEDIUM, LOW).
4. Restates engine's remediation_hint in plain language rather than inventing new advice.
5. Honest zero-findings handling ("no issues found", no fabricated filler).
6. Code-enforced guardrail against severity minimization (RULE_4_SEVERITY_MINIMIZATION).
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ml_shared.guardrails import (
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
)
from ml_shared.context import ListingContextBundle

from src.models.listing import Listing, ListingVersion, ListingStatus, ScanStatus


class FindingExplanationItem(BaseModel):
    rule_id: str
    severity: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: str
    plain_english_summary: str
    remediation_action: str


class ExplainFindingsResponse(BaseModel):
    version_id: str
    listing_id: str
    version_label: str
    scan_status: str
    total_findings: int
    severity_counts: Dict[str, int]
    overall_summary: str
    grouped_findings: Dict[str, List[FindingExplanationItem]]
    has_issues: bool
    advisory_note: str = (
        "Advisory explanation: strictly translates deterministic scan findings and "
        "remediation hints without altering severity or inventing new rules."
    )


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def translate_finding_item(finding: Dict[str, Any]) -> FindingExplanationItem:
    """
    Translates a single redacted scanner finding into clear, plain language.
    Restates the scanner engine's own remediation_hint and description.
    """
    rule_id = finding.get("rule_id", "UNKNOWN_RULE")
    severity = str(finding.get("severity", "LOW")).upper()
    file_path = finding.get("file_path") or finding.get("file")
    line_number = finding.get("line_number") or finding.get("line")
    desc = finding.get("description") or finding.get("message") or f"Issue detected by {rule_id}"
    hint = finding.get("remediation_hint") or finding.get("hint") or "Remove or rotate the exposed secret."

    location_str = f" in `{file_path}`" if file_path else ""
    if line_number:
        location_str += f" (line {line_number})"

    summary = f"Detected {desc}{location_str}."
    remediation = f"Scanner Remediation: {hint}"

    return FindingExplanationItem(
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        description=desc,
        plain_english_summary=summary,
        remediation_action=remediation,
    )


def generate_findings_explanation(
    version: ListingVersion,
    listing: Listing,
    forced_summary_for_test: Optional[str] = None,
) -> ExplainFindingsResponse:
    """
    Generates a structured, plain-English explanation for a ListingVersion's findings.
    Validates output through enforce_guardrails().
    """
    raw_findings = version.findings_detail or []
    sev_counts = version.findings_summary or {}

    total_findings = len(raw_findings)
    if not total_findings and sev_counts:
        total_findings = sum(sev_counts.values())

    grouped: Dict[str, List[FindingExplanationItem]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }

    # If version has 0 findings (clean scan)
    if total_findings == 0:
        overall_summary = (
            f"The automated security scan for version {version.version_label} completed successfully "
            f"with 0 security findings. No hardcoded secrets, private keys, or security policy violations "
            f"were identified in this package."
        )
        if forced_summary_for_test:
            overall_summary = forced_summary_for_test

        scan_data = {
            "scan_status": version.scan_status,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing, scan_data=scan_data)
        enforce_guardrails(overall_summary, bundle, skip_price_check=True)

        return ExplainFindingsResponse(
            version_id=version.id,
            listing_id=listing.id,
            version_label=version.version_label,
            scan_status=version.scan_status,
            total_findings=0,
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            overall_summary=overall_summary,
            grouped_findings=grouped,
            has_issues=False,
        )

    # Process findings and populate severity groups
    for item in raw_findings:
        translated = translate_finding_item(item)
        sev_key = translated.severity if translated.severity in grouped else "LOW"
        grouped[sev_key].append(translated)

    # Compute actual counts
    computed_counts = {
        "critical": len(grouped["CRITICAL"]),
        "high": len(grouped["HIGH"]),
        "medium": len(grouped["MEDIUM"]),
        "low": len(grouped["LOW"]),
    }

    # Synthesize plain-English overall summary
    summary_parts = [
        f"The automated security scan for version {version.version_label} identified {total_findings} "
        f"finding(s): {computed_counts['critical']} Critical, {computed_counts['high']} High, "
        f"{computed_counts['medium']} Medium, {computed_counts['low']} Low."
    ]

    for sev in SEVERITY_ORDER:
        items = grouped[sev]
        if items:
            summary_parts.append(f"\n{sev} Severity ({len(items)}):")
            for idx, it in enumerate(items, 1):
                loc = f" at {it.file_path}:{it.line_number}" if it.file_path and it.line_number else ""
                summary_parts.append(f"  {idx}. [{it.rule_id}]{loc}: {it.description}")
                summary_parts.append(f"     Action: {it.remediation_action}")

    summary_parts.append(
        "\nNext Steps: Address the remediation steps detailed above for each finding in your codebase, "
        "and submit a new version for intake once resolved."
    )

    overall_summary = "\n".join(summary_parts)

    if forced_summary_for_test:
        overall_summary = forced_summary_for_test

    # Code-enforced guardrails check
    scan_data = {
        "scan_status": version.scan_status,
        "severity_counts": computed_counts,
    }
    bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing, scan_data=scan_data)
    enforce_guardrails(overall_summary, bundle, skip_price_check=True)


    return ExplainFindingsResponse(
        version_id=version.id,
        listing_id=listing.id,
        version_label=version.version_label,
        scan_status=version.scan_status,
        total_findings=total_findings,
        severity_counts=computed_counts,
        overall_summary=overall_summary,
        grouped_findings=grouped,
        has_issues=True,
    )
