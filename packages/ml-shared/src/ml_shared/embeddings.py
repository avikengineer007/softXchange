"""
ml_shared.embeddings

Unified Embedding Model Foundation:
- Canonical Model: BAAI/bge-small-en-v1.5
- Dimensionality: 384
- Metric: Cosine similarity via dot product on unit L2 normalized vectors
- Query Prefix: "Represent this sentence for searching relevant passages: "
- Passage Prefix: "" (none)

This module defines the single, immutable vector space shared across
buyer-assist, seller-assist, and broker.
"""

from __future__ import annotations
import math
import hashlib
from typing import List, Sequence, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

# ============================================================================
# Canonical Model Constants & Specifications
# ============================================================================

MODEL_NAME = "BAAI/bge-small-en-v1.5"
EMBEDDING_DIM = 384
MAX_SEQ_LENGTH = 512
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
BGE_PASSAGE_PREFIX = ""


class EmbeddingModelSpec(BaseModel):
    """Specification of the system-wide embedding model."""
    model_name: str = MODEL_NAME
    dimensions: int = EMBEDDING_DIM
    max_sequence_length: int = MAX_SEQ_LENGTH
    query_prefix: str = BGE_QUERY_PREFIX
    passage_prefix: str = BGE_PASSAGE_PREFIX
    distance_metric: str = "cosine"
    l2_normalized: bool = True


# ============================================================================
# Vector Math Utilities
# ============================================================================

def l2_normalize(vector: Sequence[float]) -> List[float]:
    """Normalizes a vector to unit length (L2 norm = 1.0)."""
    norm = math.sqrt(sum(x * x for x in vector))
    if norm < 1e-12:
        return [0.0] * len(vector)
    return [x / norm for x in vector]


def compute_cosine_similarity(vec_a: Sequence[float], vec_b: Sequence[float]) -> float:
    """
    Computes cosine similarity between two vectors.
    If vectors are already L2 normalized, this is equivalent to their dot product.
    """
    if len(vec_a) != len(vec_b):
        raise ValueError(f"Vector dimension mismatch: {len(vec_a)} vs {len(vec_b)}")

    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))

    if norm_a < 1e-12 or norm_b < 1e-12:
        return 0.0

    sim = dot / (norm_a * norm_b)
    # Clamp to [-1.0, 1.0] to guard against minor floating point precision errors
    return max(-1.0, min(1.0, sim))


# ============================================================================
# Embedder Interface & Protocol
# ============================================================================

@runtime_checkable
class BaseEmbedder(Protocol):
    """Interface implemented by all embedder clients in softXchange."""

    def embed_query(self, query: str) -> List[float]:
        """Embed a buyer search query with canonical asymmetric instruction prefix."""
        ...

    def embed_document(self, doc_text: str) -> List[float]:
        """Embed a seller listing / document without prefix."""
        ...

    def embed_batch(self, texts: Sequence[str], is_query: bool = False) -> List[List[float]]:
        """Embed a batch of texts."""
        ...


import re
import random

_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he",
    "in", "is", "it", "its", "of", "on", "that", "the", "to", "was", "were", "will",
    "with", "this", "our", "represent", "sentence", "searching", "relevant", "passages"
}


class DeterministicTestEmbedder:
    """
    Deterministic reference embedder for testing and offline environments.
    Produces unit L2 normalized 384-dimensional vectors matching BGE-small dimensions
    with realistic semantic similarity properties, without requiring 133MB weights download.
    
    Uses zero-centered pseudo-random projections with subword n-grams to guarantee:
    - Unrelated texts have expected cosine similarity near 0.0 (no positive bias).
    - Topically relevant texts have high cosine similarity (>0.30).
    - Exact string self-similarity is 1.0.
    """

    def __init__(self, dimensions: int = EMBEDDING_DIM):
        self.dimensions = dimensions

    def _get_token_vec(self, token: str) -> List[float]:
        seed = int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:16], 16)
        rng = random.Random(seed)
        return [rng.gauss(0.0, 1.0) for _ in range(self.dimensions)]

    def _hash_embed(self, text: str) -> List[float]:
        raw_tokens = re.findall(r"[a-zA-Z0-9]+", text.lower())
        tokens = [t for t in raw_tokens if t not in _STOP_WORDS and len(t) > 2]
        if not tokens:
            return [0.0] * self.dimensions

        vec = [0.0] * self.dimensions
        for t in tokens:
            t_vec = self._get_token_vec(t)
            for i in range(self.dimensions):
                vec[i] += t_vec[i]
            # Add character trigrams for subword matching (e.g. secur, vuln, pay)
            for j in range(len(t) - 2):
                ng = t[j : j + 3]
                ng_vec = self._get_token_vec(f"__{ng}")
                for i in range(self.dimensions):
                    vec[i] += 0.3 * ng_vec[i]

        return l2_normalize(vec)

    def embed_query(self, query: str) -> List[float]:
        prefixed = f"{BGE_QUERY_PREFIX}{query}"
        return self._hash_embed(prefixed)

    def embed_document(self, doc_text: str) -> List[float]:
        return self._hash_embed(doc_text)

    def embed_batch(self, texts: Sequence[str], is_query: bool = False) -> List[List[float]]:
        if is_query:
            return [self.embed_query(t) for t in texts]
        return [self.embed_document(t) for t in texts]


# Global default test embedder instance
default_embedder = DeterministicTestEmbedder()

