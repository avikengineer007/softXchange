"""
apps/seller-assist/seller_assist/suggest.py

Listing copy & pricing suggestions engine for seller-assist.
Grounded in real comparable live listings using the shared embedding vector space.

Strict guarantees:
1. Advisory only: zero writes/modifications to Listing records.
2. Shared embeddings: uses BAAI/bge-small-en-v1.5 and listing_embeddings.
3. Single canonical INR pricing guidance (₹). All `_cents` fields represent minor units (paise: 1 INR = 100 paise).
4. Graceful degradation when inventory is sparse (0, 1-2, >=3 comparables).
5. Code-enforced guardrails on generated copy (skip_price_check=True for pre-publish drafts).
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

from ml_shared.embeddings import (
    default_embedder,
    BaseEmbedder,
    compute_cosine_similarity,
)
from ml_shared.currency import (
    resolve_currency,
    format_money,
    convert_cents_to_currency,
    calculate_price_guidance,
    LocalizedPriceGuidance,
)
from ml_shared.guardrails import (
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
)
from ml_shared.context import ListingContextBundle, ListingMetadata, ScanSummary

from src.models.listing import Listing, ListingStatus  # type: ignore # pyrefly: ignore
from src.models.embedding import ListingEmbedding  # type: ignore # pyrefly: ignore
from seller_assist.config import settings


class ComparableListingItem(BaseModel):
    listing_id: str
    title: str
    category: str
    price_cents: int
    price_formatted: str
    similarity_score: float

    model_config = ConfigDict(from_attributes=True)


class CopySuggestionRequest(BaseModel):
    title: Optional[str] = Field(None, description="Optional draft title override")
    description: Optional[str] = Field(None, description="Optional draft description override")
    category: Optional[str] = Field(None, description="Optional category override")
    rough_price_cents: Optional[int] = Field(None, ge=0, description="Optional rough price in minor units (paise: 1 INR = 100 paise)")
    currency: Optional[str] = Field("INR", description="Target currency code (standardized to INR)")
    region: Optional[str] = Field("IN", description="Target region code (standardized to IN)")
    k: Optional[int] = Field(settings.DEFAULT_K_COMPARABLES, ge=1, le=10)


class CopySuggestionResponse(BaseModel):
    listing_id: str
    suggested_title: str
    suggested_description: str
    currency: str
    currency_symbol: str
    price_guidance: Optional[LocalizedPriceGuidance] = None
    confidence_note: str
    comparable_listings: List[ComparableListingItem]
    advisory_notice: str = (
        "These suggestions are strictly advisory and grounded in comparable marketplace listings. "
        "No changes have been saved to your listing. Review and apply them through your listing dashboard."
    )


def synthesize_suggested_copy(
    current_title: str,
    current_desc: str,
    category: str,
    comparables: List[ComparableListingItem],
) -> tuple[str, str]:
    """
    Synthesizes professional, technical, and grounded title & description copy
    informed by top comparable live listings.
    """
    title_clean = current_title.strip()
    desc_clean = current_desc.strip()

    # Formulate refined title
    if title_clean:
        if not any(cat_word in title_clean.lower() for cat_word in category.replace("-", " ").split()):
            suggested_title = f"{title_clean} — Verified {category.replace('-', ' ').title()} Package"
        else:
            suggested_title = title_clean
    else:
        suggested_title = f"High-Performance {category.replace('-', ' ').title()} Module"

    # Formulate structured, professional description
    comparable_context = ""
    if comparables:
        top_cats = ", ".join(list(dict.fromkeys(c.category for c in comparables)))
        comparable_context = f" Modeled for compatibility with top {top_cats} standards."

    base_desc = desc_clean if desc_clean else f"Production-grade {category} software package."
    suggested_desc = (
        f"{base_desc}\n\n"
        f"Key Features & Highlights:\n"
        f"- Clean, modular architecture with verified dependency manifests.\n"
        f"- Full developer documentation and automated scan vetting.\n"
        f"- Built for enterprise {category.replace('-', ' ')} environments.{comparable_context}"
    )

    return suggested_title, suggested_desc


def generate_listing_suggestions(
    listing_id: str,
    request: CopySuggestionRequest,
    db: Session,
    embedder: Optional[BaseEmbedder] = None,
) -> CopySuggestionResponse:
    """
    Core engine generating copy & pricing suggestions.
    Guaranteed strictly read-only: does not write or mutate any database record.
    """
    # 1. Fetch listing draft
    listing = db.query(Listing).filter(Listing.id == listing_id).first()
    if not listing:
        raise ValueError(f"Listing '{listing_id}' not found")

    title = request.title if request.title is not None else listing.title
    description = request.description if request.description is not None else listing.description
    category = request.category if request.category is not None else listing.category
    rough_price_cents = (
        request.rough_price_cents
        if request.rough_price_cents is not None
        else listing.price_cents
    )

    # 2. Resolve target regional currency
    curr_code = resolve_currency(currency=request.currency, region=request.region)

    # 3. Discover comparable live listings via vector embedding
    active_embedder = embedder or default_embedder
    text_to_embed = f"{title}\n{description}\ncategory: {category}".strip()
    query_vector = active_embedder.embed_document(text_to_embed)

    # Query all live listings except the current listing
    rows = (
        db.query(Listing, ListingEmbedding)
        .join(ListingEmbedding, Listing.id == ListingEmbedding.listing_id)
        .filter(Listing.status == ListingStatus.LIVE.value)
        .filter(Listing.id != listing_id)
        .all()
    )

    scored_comparables: List[tuple[float, Listing]] = []
    for comp_listing, emb_row in rows:
        sim = compute_cosine_similarity(query_vector, emb_row.embedding)
        # Small category match boost to favor same category when similarity is close
        if comp_listing.category == category:
            sim += 0.05
        scored_comparables.append((sim, comp_listing))

    scored_comparables.sort(key=lambda x: x[0], reverse=True)
    k = request.k or settings.DEFAULT_K_COMPARABLES
    top_k = scored_comparables[:k]

    comparable_items: List[ComparableListingItem] = []
    prices_cents: List[int] = []
    for sim_score, comp in top_k:
        prices_cents.append(comp.price_cents)
        comparable_items.append(
            ComparableListingItem(
                listing_id=comp.id,
                title=comp.title,
                category=comp.category,
                price_cents=comp.price_cents,
                price_formatted=format_money(comp.price_cents, curr_code, is_cents=True),
                similarity_score=round(float(sim_score), 4),
            )
        )

    # 4. Compute pricing guidance with graceful degradation on sparse data
    n_comparables = len(comparable_items)
    if n_comparables == 0:
        price_guidance = None
        confidence_note = (
            "Insufficient market data: 0 comparable live listings found. "
            "Pricing guidance is unavailable; please set an initial price based on your requirements."
        )
    elif n_comparables < 3:
        price_guidance = calculate_price_guidance(prices_cents, currency=curr_code, region=request.region)
        confidence_note = (
            f"Limited market data: calculated from only {n_comparables} comparable listing(s). "
            f"Treat this pricing range as preliminary guidance."
        )
    else:
        price_guidance = calculate_price_guidance(prices_cents, currency=curr_code, region=request.region)
        confidence_note = (
            f"Robust market data based on {n_comparables} comparable live listings in the marketplace."
        )

    # 5. Synthesize suggested copy
    suggested_title, suggested_desc = synthesize_suggested_copy(
        current_title=title,
        current_desc=description,
        category=category,
        comparables=comparable_items,
    )

    # 6. Guardrail validation on generated copy
    # Pre-publish draft copy passes skip_price_check=True because price is not yet finalized
    bundle = ListingContextBundle.from_listing_and_scan(listing_data=listing)
    enforce_guardrails(suggested_desc, bundle, skip_price_check=True)
    enforce_guardrails(suggested_title, bundle, skip_price_check=True)

    curr_symbol = price_guidance.currency_symbol if price_guidance else "₹"

    return CopySuggestionResponse(
        listing_id=listing_id,
        suggested_title=suggested_title,
        suggested_description=suggested_desc,
        currency=curr_code,
        currency_symbol=curr_symbol,
        price_guidance=price_guidance,
        confidence_note=confidence_note,
        comparable_listings=comparable_items,
    )
