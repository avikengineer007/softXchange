# `ml-shared` — softXchange ML Shared Foundation

`packages/ml-shared/` provides the shared data structures, embedding standards, and hard-block guardrails required across all three marketplace AI models:
- **`buyer-assist`**: Buyer requirements assistant and semantic discovery.
- **`seller-assist`**: Seller onboarding and package documentation generation.
- **`broker`**: Semantic matching engine connecting buyer requests with seller listings.

---

## Key Modules

### 1. `ml_shared.context` — Canonical Context Bundle
Provides `ListingContextBundle`, the single source of truth data structure representing "a listing, fully described":
- **`ListingMetadata`**: Verified listing attributes (`id`, `title`, `description`, `price_cents`, `category`, `status`, `version_label`).
- **`ScanSummary`**: Real scan status and findings (`severity_counts`, `vetted`, `badge`, `scan_status`) pulled directly from upstream services, never re-derived.
- **`SellerDocument`**: Seller-provided documentation (READMEs, API references, architecture guides).

### 2. `ml_shared.guardrails` — Hard-Block Safety Engine
A single, shared set of hard-block rules enforced in code before any model output reaches a user:
- **Rule 1 (`RULE_SECURITY_CLAIMS`)**: Never assert security/safety claims unsupported by the scan (e.g. prohibits claims like "malware-free" or claiming zero findings when issues exist).
- **Rule 2 (`RULE_TRANSACTION_PRICE_LEGAL`)**:
  - Never finalize a sale or claim a transaction was completed.
  - Never quote a different price than the listing's actual `price_cents`.
  - Never make warranty or legal claims (e.g. guarantees, liability promises).
- **Rule 3 (`RULE_PLATFORM_BYPASS`)**: Never draft content that suggests bypassing softXchange (e.g. external payment via PayPal/crypto or off-platform communication).

#### Caller Refusal Contract (No 500s)
When `enforce_guardrails` blocks a response, it raises `GuardrailViolationError`. API callers (`/assist/search`, `/assist/listings/{id}/ask`) must catch this error and use `format_guardrail_refusal()` or return a clean refusal response, rather than allowing an unhandled 500 error to reach the user.

#### Honest Labeling Note on Rule 3
Rule 3 uses textual pattern and keyword filtering as a defense-in-depth barrier. It is **not** an airtight semantic guarantee against sophisticated adversarial evasion. In production, edge-case matches should be logged for human moderation review.

### 3. `ml_shared.embeddings` — Unified Embedding Specification
Defines the canonical embedding model: **`BAAI/bge-small-en-v1.5`** (384 dimensions, L2 normalized, cosine similarity). See [EMBEDDING_DECISION.md](./EMBEDDING_DECISION.md) for full architectural rationale.

---

## Installation

Within the repository `.venv`:
```bash
pip install -e packages/ml-shared
```
