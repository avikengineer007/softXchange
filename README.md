# softXchange

> Manifest's Marketplace Application — A secure microservices-based software exchange marketplace powered by AI-driven buyer/seller assistance, automated security scanning, and seamless entitlements.

---

## 🏗️ Architecture & Microservices

softXchange is organized as a modular monorepo containing microservices under `apps/` and shared packages under `packages/`:

### Applications (`apps/`)

- **`auth-service`**: Handles authentication, user management, and JWT session handling.
- **`listings-service`**: Manages software package listings, versions, metadata, and catalog searches.
- **`payments-service`**: Manages payments, transactions, and software access entitlements.
- **`scan-service`**: Multi-scanner security engine intake gateway and orchestrator, gating packages before publication.
- **`buyer-assist`**: AI-powered assistant for buyer requirement parsing, question answering, and semantic search.
- **`seller-assist`**: AI-powered seller onboarding assistant and documentation generator.

### Shared Packages (`packages/`)

- **`packages/ml-shared`**: Canonical listing context bundle, embedding specifications (`BAAI/bge-small-en-v1.5`), and hard-block guardrails.
- **`packages/db`**: Shared database abstractions and models.
- **`packages/types`**: Shared types, event contracts, and interfaces.

### Security Engine (`Secret Scanner engine_Manifest/`)

- Contains the core secrets scanner, static code analyzer, and dependency manifest inspection rules.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js (for monorepo script tooling)

### Installation

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install shared packages in editable mode
pip install -e packages/ml-shared
pip install -e packages/types
pip install -e packages/db
```

### Running Tests

```bash
pytest packages/ml-shared/tests
pytest apps/buyer-assist/tests
pytest apps/seller-assist/tests
```

---

## 🔒 Security & Guardrails

softXchange enforces zero-translation fail-closed security gating across all published packages. Hard-block safety guardrails in `ml-shared` ensure AI assistants never make unverified security claims, guarantee legal terms, or permit off-platform transactions.
