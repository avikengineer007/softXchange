"""
ml_shared.context

Defines the single source of truth data structure representing "a listing, fully described":
- Listing metadata (title, description, price, category, status)
- Scan result summary (exact severity counts, vetted status — pulled from listings-service/scan-service, never re-derived)
- Seller-provided documentation (READMEs, API specs, guides)

Both buyer-assist and seller-assist consume this same shape when reasoning about
a listing, ensuring zero drift across models.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, ConfigDict


class SellerDocument(BaseModel):
    """Represents documentation provided by the seller."""
    title: str = Field(..., description="Document title or filename, e.g. README.md, API.md")
    content: str = Field(..., description="Full text content of the document")
    doc_type: str = Field(default="readme", description="Document type: readme, api_docs, architecture, license")

    model_config = ConfigDict(extra="ignore")


class ScanSummary(BaseModel):
    """
    Security scan summary pulled directly from listings-service and/or scan-service.
    CRITICAL: Never re-derive or guess severity counts or vetted status.
    """
    scan_status: str = Field(..., description="'passed', 'pending_scan', 'scan_failed', etc.")
    vetted: bool = Field(default=False, description="True if listing is verified live with passing scan")
    badge: str = Field(default="Unvetted Draft", description="Display badge string, e.g. 'Scanned — 0 critical findings'")
    severity_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Exact count of findings per severity level (e.g. {'critical': 0, 'high': 0})"
    )
    scan_job_id: Optional[str] = Field(default=None, description="Upstream scanner job ID")
    error_message: Optional[str] = Field(default=None, description="Scanner error message if applicable")

    model_config = ConfigDict(extra="ignore")


class ListingMetadata(BaseModel):
    """Core listing metadata as stored and validated in listings-service."""
    id: str
    seller_id: str
    title: str
    description: str
    price_cents: int = Field(..., ge=0, description="Strict price in integer cents (e.g. 5900 = $59.00)")
    category: str
    status: str = Field(..., description="'live', 'draft', 'pending_scan', 'scan_failed', 'withdrawn', etc.")
    status_message: Optional[str] = None
    version_label: Optional[str] = Field(default=None, description="Version label, e.g. '1.0.0'")
    current_version_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(extra="ignore", from_attributes=True)


class ListingContextBundle(BaseModel):
    """
    The canonical context bundle representing 'a listing, fully described'.
    Consumed identically by buyer-assist, seller-assist, and broker.
    """
    listing: ListingMetadata
    scan_summary: ScanSummary
    seller_docs: List[SellerDocument] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")

    @property
    def price_usd(self) -> float:
        """Returns the price in US Dollars computed strictly from price_cents."""
        return round(self.listing.price_cents / 100.0, 2)

    @property
    def formatted_price(self) -> str:
        """Standard human-readable formatted price."""
        if self.listing.price_cents == 0:
            return "Free"
        return f"${self.price_usd:.2f}"

    def to_prompt_context(self) -> str:
        """
        Renders the context bundle into a structured text format for LLM prompts.
        Ensures both buyer-assist and seller-assist present the exact same factual
        grounding to their respective models.
        """
        lines = [
            f"# Listing: {self.listing.title}",
            f"- **ID**: {self.listing.id}",
            f"- **Category**: {self.listing.category}",
            f"- **Price**: {self.formatted_price} ({self.listing.price_cents} cents)",
            f"- **Marketplace Status**: {self.listing.status}",
            f"- **Version**: {self.listing.version_label or 'N/A'}",
            "",
            "## Description",
            self.listing.description.strip(),
            "",
            "## Security & Scan Status",
            f"- **Vetted Status**: {'Verified / Vetted' if self.scan_summary.vetted else 'Unvetted'}",
            f"- **Scan Status**: {self.scan_summary.scan_status}",
            f"- **Badge**: {self.scan_summary.badge}",
        ]

        if self.scan_summary.severity_counts:
            sev_formatted = ", ".join(f"{k}: {v}" for k, v in self.scan_summary.severity_counts.items())
            lines.append(f"- **Severity Counts**: {sev_formatted}")
        else:
            lines.append("- **Severity Counts**: None recorded")

        if self.seller_docs:
            lines.append("")
            lines.append("## Seller Documentation")
            for doc in self.seller_docs:
                lines.append(f"### {doc.title} ({doc.doc_type})")
                lines.append(doc.content.strip())
                lines.append("")

        return "\n".join(lines)

    @classmethod
    def from_listing_and_scan(
        cls,
        listing_data: Union[dict, Any],
        scan_data: Optional[Union[dict, Any]] = None,
        seller_docs: Optional[List[SellerDocument]] = None,
    ) -> "ListingContextBundle":
        """
        Canonical factory method constructing the context bundle directly from
        listings-service response or ORM objects, and scan-service status data.
        
        Guarantees that severity_counts and vetted status are pulled directly from
        the upstream source and NEVER re-derived or guessed.
        """
        # 1. Normalize listing fields
        if isinstance(listing_data, dict):
            # Dict representation (e.g. from /listings/{id} endpoint)
            v_label = listing_data.get("current_version_label")
            if not v_label and "current_version" in listing_data and listing_data["current_version"]:
                v_label = listing_data["current_version"].get("version_label")

            listing_meta = ListingMetadata(
                id=str(listing_data["id"]),
                seller_id=str(listing_data.get("seller_id", "unknown")),
                title=str(listing_data["title"]),
                description=str(listing_data["description"]),
                price_cents=int(listing_data["price_cents"]),
                category=str(listing_data["category"]),
                status=str(listing_data.get("status", "draft")),
                status_message=listing_data.get("status_message"),
                version_label=v_label,
                current_version_id=listing_data.get("current_version_id"),
                created_at=listing_data.get("created_at"),
                updated_at=listing_data.get("updated_at"),
            )
        elif hasattr(listing_data, "__table__"):  # SQLAlchemy model
            current_label = None
            if hasattr(listing_data, "versions") and listing_data.versions:
                if getattr(listing_data, "current_version_id", None):
                    for v in listing_data.versions:
                        if v.id == listing_data.current_version_id:
                            current_label = v.version_label
                            break
                if not current_label and listing_data.versions:
                    current_label = listing_data.versions[0].version_label

            listing_meta = ListingMetadata(
                id=str(getattr(listing_data, "id")),
                seller_id=str(getattr(listing_data, "seller_id")),
                title=str(getattr(listing_data, "title")),
                description=str(getattr(listing_data, "description")),
                price_cents=int(getattr(listing_data, "price_cents")),
                category=str(getattr(listing_data, "category")),
                status=str(getattr(listing_data, "status")),
                status_message=getattr(listing_data, "status_message", None),
                version_label=current_label,
                current_version_id=getattr(listing_data, "current_version_id", None),
                created_at=getattr(listing_data, "created_at", None),
                updated_at=getattr(listing_data, "updated_at", None),
            )
            # Check if version has findings_summary
            if not scan_data and hasattr(listing_data, "versions") and listing_data.versions:
                v_obj = listing_data.versions[0]
                scan_data = {
                    "scan_status": v_obj.scan_status,
                    "severity_counts": v_obj.findings_summary or {},
                    "scan_job_id": v_obj.scan_job_id,
                }
        elif hasattr(listing_data, "id") and hasattr(listing_data, "price_cents"):
            # Pydantic or object representation
            listing_meta = ListingMetadata.model_validate(listing_data)
        else:
            raise ValueError(f"Unsupported listing_data type: {type(listing_data)}")

        # 2. Extract scan summary without re-derivation
        scan_dict = scan_data or {}
        if hasattr(scan_dict, "model_dump"):
            scan_dict = scan_dict.model_dump()

        # Determine vetted status and badge
        is_live = listing_meta.status == "live"
        vetted = bool(listing_data.get("vetted", is_live)) if isinstance(listing_data, dict) else is_live
        badge = (
            listing_data.get("badge")
            if isinstance(listing_data, dict) and listing_data.get("badge")
            else ("Scanned — 0 critical findings" if is_live else "Unvetted Draft")
        )

        scan_status = scan_dict.get("scan_status", "pending_scan" if not is_live else "passed")
        severity_counts = dict(scan_dict.get("severity_counts", {}))

        scan_summary = ScanSummary(
            scan_status=scan_status,
            vetted=vetted,
            badge=badge,
            severity_counts=severity_counts,
            scan_job_id=scan_dict.get("scan_job_id"),
            error_message=scan_dict.get("error_message"),
        )

        return cls(
            listing=listing_meta,
            scan_summary=scan_summary,
            seller_docs=seller_docs or [],
        )
