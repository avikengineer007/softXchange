"""
ml_shared — softXchange ML Shared Foundation
"""

from ml_shared.context import (
    ListingContextBundle,
    ListingMetadata,
    ScanSummary,
    SellerDocument,
)

from ml_shared.guardrails import (
    check_guardrails,
    enforce_guardrails,
    format_guardrail_refusal,
    GuardrailViolationError,
    GuardrailResult,
    RuleViolation,
    GuardrailRefusal,
)

from ml_shared.embeddings import (
    MODEL_NAME,
    EMBEDDING_DIM,
    MAX_SEQ_LENGTH,
    BGE_QUERY_PREFIX,
    BGE_PASSAGE_PREFIX,
    EmbeddingModelSpec,
    BaseEmbedder,
    DeterministicTestEmbedder,
    default_embedder,
    compute_cosine_similarity,
    l2_normalize,
)

from ml_shared.client import (
    ContextBundleClient,
    build_context_bundle,
)

from ml_shared.currency import (
    CURRENCIES,
    REGION_TO_CURRENCY,
    CurrencyInfo,
    LocalizedPriceGuidance,
    resolve_currency,
    convert_cents_to_currency,
    format_money,
    calculate_price_guidance,
)

__all__ = [
    # Context
    "ListingContextBundle",
    "ListingMetadata",
    "ScanSummary",
    "SellerDocument",
    # Guardrails
    "check_guardrails",
    "enforce_guardrails",
    "format_guardrail_refusal",
    "GuardrailViolationError",
    "GuardrailResult",
    "RuleViolation",
    "GuardrailRefusal",
    # Embeddings
    "MODEL_NAME",
    "EMBEDDING_DIM",
    "MAX_SEQ_LENGTH",
    "BGE_QUERY_PREFIX",
    "BGE_PASSAGE_PREFIX",
    "EmbeddingModelSpec",
    "BaseEmbedder",
    "DeterministicTestEmbedder",
    "default_embedder",
    "compute_cosine_similarity",
    "l2_normalize",
    # Client
    "ContextBundleClient",
    "build_context_bundle",
    # Currency
    "CURRENCIES",
    "REGION_TO_CURRENCY",
    "CurrencyInfo",
    "LocalizedPriceGuidance",
    "resolve_currency",
    "convert_cents_to_currency",
    "format_money",
    "calculate_price_guidance",
]

