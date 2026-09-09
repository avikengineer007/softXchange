"""
apps/listings-service/src/models/embedding.py

Defines the ListingEmbedding model storing 384-dimensional vector representations
of live listings directly alongside listings-service's data in SQLite.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ListingEmbedding(Base):
    """
    Stores the canonical BAAI/bge-small-en-v1.5 embedding for an active live listing.
    
    Invariants:
    - Only live listings have active embeddings.
    - version_id explicitly tracks the live version that produced the embedding.
    - content_hash prevents duplicate re-embedding of identical text.
    """
    __tablename__ = "listing_embeddings"

    listing_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("listings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    version_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("listing_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Stored as a 384-dimensional float array (JSON serialized)
    embedding: Mapped[List[float]] = mapped_column(JSON, nullable=False)
    # SHA-256 hash of title + description + category to detect content changes
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
