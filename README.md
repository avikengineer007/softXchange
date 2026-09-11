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

### Security Engine (`Secret Scanner engine/`)

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

### 3D Asset Pipeline

> **Note**: Node.js (v18+) is required for the 3D build pipeline. This is in addition to Python — the backend services are still Python-only, but the 3D asset generator and budget enforcer run in Node.

```powershell
# Generate the bowtie/hourglass glTF models (logo-hi.glb, logo-lo.glb)
npm run 3d:generate

# Copy 3D assets + vendored Three.js into each service's static directory
# Use this instead of symlinks (Windows requires admin for symlinks)
npm run 3d:copy

# Or both steps at once:
npm run 3d:build

# Verify all 3D assets are within the byte-size budget (CI gate, exits 1 on failure):
npm run check:assets
```

The 3D models live in `packages/3d-assets/` (source of truth).
Three.js is vendored at `packages/vendor/` (self-hosted — no CDN dependency).
After running `npm run 3d:copy`, distributed copies appear in:
- `apps/listings-service/static/js/` — glb models + tier-detection.js
- `apps/listings-service/static/js/vendor/` — three.module.min.js + GLTFLoader.js


---

## 🔒 Security & Guardrails

softXchange enforces zero-translation fail-closed security gating across all published packages. Hard-block safety guardrails in `ml-shared` ensure AI assistants never make unverified security claims, guarantee legal terms, or permit off-platform transactions.
