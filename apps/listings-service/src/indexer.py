"""
apps/listings-service/src/indexer.py

Synchronizes 384-dimensional vector embeddings for live marketplace listings
using the unified BAAI/bge-small-en-v1.5 model from ml_shared.

Guarantees:
1. Only approved, verified live listings are indexed.
2. Embeddings are updated whenever a newly approved version goes live.
3. Content hashing avoids re-embedding unchanged listings.
4. Withdrawn listings are immediately purged from the vector index.
"""

import hashlib
import logging
from typing import Optional
from sqlalchemy.orm import Session

from ml_shared.embeddings import default_embedder, BaseEmbedder
from src.models.listing import Listing, ListingVersion, ListingStatus
from src.models.embedding import ListingEmbedding, utc_now

logger = logging.getLogger("listings-service.indexer")


def compute_listing_content_hash(title: str, description: str, category: str) -> str:
    """Computes deterministic SHA-256 hash of searchable listing text."""
    payload = f"{title.strip()}\n{description.strip()}\n{category.strip().lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sync_live_listing_embedding(
    listing: Listing,
    version: Optional[ListingVersion],
    db: Session,
    embedder: Optional[BaseEmbedder] = None,
) -> Optional[ListingEmbedding]:
    """
    Synchronizes vector embedding for a live listing.
    
    Triggered when:
    - evaluate_publish_gate promotes a listing/version to 'live'
    - sync_seller_kyc promotes an awaiting listing to 'live'
    """
    if listing.status != ListingStatus.LIVE.value:
        logger.debug(f"Skipping embedding for non-live listing {listing.id} (status={listing.status})")
        return None

    active_embedder = embedder or default_embedder
    content_hash = compute_listing_content_hash(
        title=listing.title,
        description=listing.description,
        category=listing.category,
    )
    version_id = version.id if version else listing.current_version_id

    # Check if up-to-date embedding already exists
    existing = db.query(ListingEmbedding).filter(ListingEmbedding.listing_id == listing.id).first()
    if existing and existing.content_hash == content_hash and existing.version_id == version_id:
        logger.debug(f"Listing {listing.id} embedding is already fresh (hash={content_hash[:8]})")
        return existing

    # Embed document using canonical asymmetric passage rules (no prefix)
    embed_text = f"{listing.title}\n{listing.description}\nCategory: {listing.category}"
    vector = active_embedder.embed_document(embed_text)

    if existing:
        existing.embedding = vector
        existing.content_hash = content_hash
        existing.version_id = version_id
        existing.updated_at = utc_now()
        target_obj = existing
    else:
        target_obj = ListingEmbedding(
            listing_id=listing.id,
            version_id=version_id,
            embedding=vector,
            content_hash=content_hash,
            updated_at=utc_now(),
        )
        db.add(target_obj)

    db.commit()
    db.refresh(target_obj)
    logger.info(f"Synchronized embedding for live listing {listing.id} (version={version_id})")
    return target_obj


def remove_listing_embedding(listing_id: str, db: Session) -> bool:
    """Purges the embedding when a listing is withdrawn or soft-deleted."""
    deleted_count = db.query(ListingEmbedding).filter(ListingEmbedding.listing_id == listing_id).delete()
    if deleted_count > 0:
        db.commit()
        logger.info(f"Removed embedding for withdrawn listing {listing_id}")
        return True
    return False


def reindex_all_live_listings(db: Session, embedder: Optional[BaseEmbedder] = None) -> int:
    """Scans all live listings in the database and ensures they are indexed."""
    live_listings = db.query(Listing).filter(Listing.status == ListingStatus.LIVE.value).all()
    count = 0
    for l in live_listings:
        # Find active version
        active_ver = None
        if l.current_version_id:
            active_ver = db.query(ListingVersion).filter(ListingVersion.id == l.current_version_id).first()
        elif l.versions:
            active_ver = l.versions[0]
        sync_live_listing_embedding(listing=l, version=active_ver, db=db, embedder=embedder)
        count += 1
    return count
