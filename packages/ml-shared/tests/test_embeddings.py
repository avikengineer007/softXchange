"""
Unit tests for ml_shared.embeddings.
Verifies the unified BAAI/bge-small-en-v1.5 specification:
- Exact 384 dimensions
- L2 normalization
- Asymmetric query instruction prefixing
- Direct cosine similarity computation between buyer queries and seller listings
"""

import math
import pytest
from ml_shared.embeddings import (
    MODEL_NAME,
    EMBEDDING_DIM,
    MAX_SEQ_LENGTH,
    BGE_QUERY_PREFIX,
    EmbeddingModelSpec,
    DeterministicTestEmbedder,
    compute_cosine_similarity,
    l2_normalize,
    default_embedder,
)


def test_embedding_model_specification():
    """Verifies that the canonical model constants adhere strictly to the BGE specification."""
    spec = EmbeddingModelSpec()
    assert spec.model_name == "BAAI/bge-small-en-v1.5"
    assert spec.dimensions == 384
    assert spec.max_sequence_length == 512
    assert spec.query_prefix == "Represent this sentence for searching relevant passages: "
    assert spec.distance_metric == "cosine"
    assert spec.l2_normalized is True


def test_vector_dimensions_and_normalization():
    """Verifies that generated embeddings have exactly 384 dimensions and unit L2 norm."""
    embedder = DeterministicTestEmbedder()

    query_vec = embedder.embed_query("automated cloud vulnerability scanner")
    doc_vec = embedder.embed_document("Cloud Sentry CLI scans AWS and GCP infrastructure for secrets.")

    # Dimensions check
    assert len(query_vec) == 384
    assert len(doc_vec) == 384

    # Unit L2 normalization check (||v||_2 == 1.0)
    norm_query = math.sqrt(sum(x * x for x in query_vec))
    norm_doc = math.sqrt(sum(x * x for x in doc_vec))
    assert pytest.approx(norm_query, rel=1e-5) == 1.0
    assert pytest.approx(norm_doc, rel=1e-5) == 1.0


def test_direct_cosine_similarity_comparability():
    """
    Verifies that embeddings produced for a buyer query and seller listing
    can be directly compared by the broker model without translation.
    """
    embedder = DeterministicTestEmbedder()

    # Buyer query
    query = "looking for a tool to audit cloud infrastructure for vulnerabilities"
    query_vec = embedder.embed_query(query)

    # Matching seller document
    relevant_doc = "Cloud Sentry CLI audits cloud infrastructure and scans repositories for vulnerabilities"
    relevant_vec = embedder.embed_document(relevant_doc)

    # Irrelevant seller document
    irrelevant_doc = "Cute cat sticker pack graphics for messenger apps"
    irrelevant_vec = embedder.embed_document(irrelevant_doc)

    sim_relevant = compute_cosine_similarity(query_vec, relevant_vec)
    sim_irrelevant = compute_cosine_similarity(query_vec, irrelevant_vec)

    # Identical document self-similarity is 1.0
    assert pytest.approx(compute_cosine_similarity(relevant_vec, relevant_vec), rel=1e-5) == 1.0

    # Relevant document scores significantly higher than irrelevant document
    assert sim_relevant > sim_irrelevant
    assert -1.0 <= sim_relevant <= 1.0
    assert -1.0 <= sim_irrelevant <= 1.0


def test_batch_embedding():
    """Verifies batch embedding helper functionality."""
    texts = [
        "First software package",
        "Second security tool",
        "Third cloud service",
    ]
    batch_vecs = default_embedder.embed_batch(texts, is_query=False)
    assert len(batch_vecs) == 3
    for vec in batch_vecs:
        assert len(vec) == 384
        assert pytest.approx(math.sqrt(sum(x * x for x in vec)), rel=1e-5) == 1.0
