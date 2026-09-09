# Architectural Decision Record: Unified Embedding Model

**Status**: Accepted  
**Date**: September 2026  
**Deciders**: softXchange AI Engineering Team  
**Model Selected**: `BAAI/bge-small-en-v1.5`  
**Vector Dimensionality**: 384  
**Distance Metric**: Cosine Similarity (Dot Product on Unit L2 Normalized Vectors)  
**Query Instruction Prefix**: `"Represent this sentence for searching relevant passages: "`  

---

## 1. Context & Problem Statement

softXchange relies on three distinct ML models across the marketplace lifecycle:
1. **`buyer-assist`**: Understands buyer natural language search intent, technical requirements, and queries.
2. **`seller-assist`**: Understands seller software assets, generates listings, and structures technical capabilities.
3. **`broker`**: Matches buyer queries with seller listings by directly comparing embeddings produced by buyer-assist and seller-assist.

Because the **broker model directly computes mathematical similarity** between embeddings originating from buyer-assist and seller-assist, **all three models must share the exact same embedding model and latent vector space**.

Changing an embedding model post-launch is catastrophic: it invalidates every stored vector in the database, breaking historical similarity scores and requiring a complete re-embedding of the entire product catalog and cached vector indices.

---

## 2. Decision: `BAAI/bge-small-en-v1.5`

We have deliberately selected **`BAAI/bge-small-en-v1.5`** as the sole embedding model across all three services.

### Core Specifications
- **Model ID**: `BAAI/bge-small-en-v1.5`
- **Architecture**: Small Transformer BERT-derived dense bi-encoder
- **Embedding Dimensions**: `384`
- **Max Sequence Length**: `512 tokens`
- **Output Representation**: Unit L2 Normalized Dense Vector (`||v||_2 = 1.0`)
- **Similarity Computation**: Dot product (equivalent to Cosine Similarity for normalized vectors):
  $$\text{sim}(\vec{u}, \vec{v}) = \vec{u} \cdot \vec{v}$$
- **Asymmetric Retrieval Rule**:
  - **Buyer Query / Search Intent**: Must be prepended with `"Represent this sentence for searching relevant passages: "`
  - **Seller Listing / Passage / Document**: Embedded directly without prefix.

---

## 3. Deliberate Rationale: Why BGE-Small Over Claude / Hosted SaaS APIs

Hosted SaaS embedding APIs (e.g., Claude embeddings pipeline, OpenAI `text-embedding-3`, or Cohere) were evaluated and deliberately rejected in favor of self-hosted BGE-small:

| Criterion | `BAAI/bge-small-en-v1.5` | Hosted SaaS APIs (Claude / OpenAI) |
|---|---|---|
| **Deprecation & Drift Risk** | **Zero**. Model weights are immutable and frozen locally. Vectors created today are mathematically comparable to vectors created 5 years from now. | **High**. Cloud providers deprecate model versions, update backend checkpoints, or change tokenizer rules, forcing full catalog re-embeddings. |
| **Operational SaaS Cost** | **$0.00**. Unlimited local inference with zero per-token or per-query billing. | Variable recurring cost scaling with catalog size and query volume. |
| **Latency & Reliability** | **Sub-10ms CPU inference**. In-process or local HTTP sidecar eliminates network round-trips and external rate-limits. | 50–250ms network round-trip; subject to external API outages and 429 rate limit throttling. |
| **Hardware Footprint** | **Minimal (~133MB weights)**. Runs smoothly on standard microservice CPU instances without dedicated GPU hardware. | N/A (runs on vendor cloud). |
| **Retrieval Quality (MTEB)** | **Top-tier MTEB Benchmark**. Consistently ranks at the top of the Massive Text Embedding Benchmark for retrieval and semantic similarity. | High, but not significantly better for retrieval given latency/cost penalties. |

---

## 4. Consequences & Invariants

1. **Strict Invariant**: No service (`buyer-assist`, `seller-assist`, or `broker`) may introduce an alternative embedding model, change dimensions, or skip L2 normalization.
2. **Query Asymmetry**: All query-side vector generation must apply the official BGE query prefix. All document-side indexing must omit it.
3. **Broker Direct Match Guarantee**: The broker can compute $\cos(\theta) = \vec{q}_{\text{buyer}} \cdot \vec{d}_{\text{seller}}$ directly without vector translation or multi-space projection.
