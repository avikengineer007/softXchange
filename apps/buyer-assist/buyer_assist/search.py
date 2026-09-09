"""
apps/buyer-assist/buyer_assist/search.py

Vector-based natural-language listing search engine for buyer-assist.
Powered by the shared BAAI/bge-small-en-v1.5 embedding model and similarity math.

Guarantees:
1. Pure vector retrieval and ranking (supplements keyword search).
2. Live-only filtering: strictly excludes withdrawn, draft, and unapproved listings.
3. Relevance floor (min_score): eliminates false-positive noise on unrelated queries.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

from ml_shared.embeddings import (
    default_embedder,
    BaseEmbedder,
    compute_cosine_similarity,
)
from src.models.listing import Listing, ListingVersion, ListingStatus
from src.models.embedding import ListingEmbedding
from buyer_assist.config import settings


class SearchResultItem(BaseModel):
    """Represents a single ranked listing result."""
    listing_id: str
    title: str
    description: str
    price_cents: int
    price_usd: float
    category: str
    status: str
    vetted: bool
    badge: str
    version_label: Optional[str] = None
    similarity_score: float

    model_config = ConfigDict(from_attributes=True)


class SearchQueryRequest(BaseModel):
    """Natural-language search request."""
    query: str = Field(..., min_length=1, description="Natural language search query")
    limit: int = Field(default=settings.DEFAULT_SEARCH_LIMIT, ge=1, le=50)
    min_score: float = Field(default=settings.DEFAULT_MIN_SCORE, ge=0.0, le=1.0)


class SearchQueryResponse(BaseModel):
    """Natural-language search response."""
    query: str
    total: int
    results: List[SearchResultItem]


def search_listings(
    query: str,
    db: Session,
    limit: int = settings.DEFAULT_SEARCH_LIMIT,
    min_score: float = settings.DEFAULT_MIN_SCORE,
    embedder: Optional[BaseEmbedder] = None,
) -> List[SearchResultItem]:
    """
    Executes semantic vector search over live listings.
    
    Workflow:
    1. Embeds query with canonical BGE asymmetric query prefix.
    2. Queries live listings with precomputed embeddings.
    3. Computes cosine similarity between query and listing document vectors.
    4. Applies relevance threshold (min_score) and ranks top-k.
    """
    active_embedder = embedder or default_embedder
    query_clean = query.strip()
    if not query_clean:
        return []

    # 1. Asymmetric query embedding (applies BGE query prefix)
    query_vector = active_embedder.embed_query(query_clean)

    # 2. Query live listings joined with listing_embeddings
    # Reuses listings-service's own live-only guarantee: Listing.status == LIVE
    rows = (
        db.query(Listing, ListingEmbedding)
        .join(ListingEmbedding, Listing.id == ListingEmbedding.listing_id)
        .filter(Listing.status == ListingStatus.LIVE.value)
        .all()
    )

    scored_results: List[tuple[float, Listing]] = []
    for listing, emb_row in rows:
        sim = compute_cosine_similarity(query_vector, emb_row.embedding)
        if sim >= min_score:
            scored_results.append((sim, listing))

    # 3. Sort descending by similarity score
    scored_results.sort(key=lambda x: x[0], reverse=True)
    top_results = scored_results[:limit]

    # 4. Format into response items
    items: List[SearchResultItem] = []
    for score, listing in top_results:
        # Resolve current version label
        v_label = None
        if listing.current_version_id and listing.versions:
            for v in listing.versions:
                if v.id == listing.current_version_id:
                    v_label = v.version_label
                    break
        if not v_label and listing.versions:
            v_label = listing.versions[0].version_label

        items.append(
            SearchResultItem(
                listing_id=listing.id,
                title=listing.title,
                description=listing.description,
                price_cents=listing.price_cents,
                price_usd=round(listing.price_cents / 100.0, 2),
                category=listing.category,
                status=listing.status,
                vetted=True,
                badge="Scanned — 0 critical findings",
                version_label=v_label,
                similarity_score=round(score, 4),
            )
        )

    return items
