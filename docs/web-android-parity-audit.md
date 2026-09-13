# softXchange Cross-Platform Parity Matrix: Web Unified vs. Android Native

This document provides a comprehensive functional and architectural capability ledger between the **softXchange Unified Web Frontend** (`apps/web-unified`) and the **Android Native Application** (`apps/android`).

---

## Architectural Guarantee: Single Backend Source of Truth

Both client frontends operate against the exact same backend microservice endpoints:
- **Auth Service** (`:8001`): `http://localhost:8001/auth/...`
- **Scan Service** (`:8002`): `http://localhost:8002/...`
- **Listings Service** (`:8003`): `http://localhost:8003/listings/...`
- **Payments Service** (`:8004`): `http://localhost:8004/orders/...` and `/connect/...`
- **Buyer Assist** (`:8005`): `http://localhost:8005/assist/...`
- **Seller Assist** (`:8006`): `http://localhost:8006/assist/...`
- **Broker Service** (`:8007`): `http://localhost:8007/broker/...`

**Core Invariants Guaranteed Across Both Clients:**
1. Zero Local Storage as source of truth: all business data hydrates live from PostgreSQL.
2. Identical RS256 JWT access tokens and cryptographically hashed refresh tokens.
3. Fail-closed KYC gates, fraud holds (`HOLD_NEW_SELLER_HIGH_AMOUNT`), scan gating (`gate.py`), and entitlement verifications.

---

## Functional Parity Ledger Matrix

| # | Domain | Feature / Workflow | Web Unified (`apps/web-unified`) | Android Native (`apps/android`) | Parity Status | Technical Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1** | **Auth & Identity** | Multi-role registration (Customer/Seller) | `/signup-customer.html`, `/signup-seller.html` | `RegisterScreen.kt` | `PARITY CONFIRMED` | Shared POST `/auth/signup` |
| **1.2** | | Password authentication with timing defense | `/login-customer.html`, `/login-seller.html` | `LoginScreen.kt` | `PARITY CONFIRMED` | Identical constant-time verification & unified error copy |
| **1.3** | | In-memory token management | `SoftXchangeAuth` closure (`auth.js`) | `AuthRepository.kt` StateFlow | `PARITY CONFIRMED` | Zero local storage / SharedPreferences token caching |
| **1.4** | | Refresh token rotation & session recovery | Automatic silent refresh on 401 via cookie | `TokenAuthenticator.kt` OkHttp interceptor | `PARITY CONFIRMED` | SHA-256 server-hashed refresh tokens |
| **1.5** | | Session termination & revocation | `SoftXchangeAuth.logout()` | `AuthViewModel.logout()` | `PARITY CONFIRMED` | POST `/auth/logout` revokes session in DB |
| **1.6** | | WebAuthn / Biometrics | FIDO2 / WebAuthn browser credentials API | Android BiometricPrompt & Credential Manager | `INTENTIONAL DIVERGENCE: PLATFORM_NATIVE_CREDENTIALS` | Native Android uses BiometricPrompt; Web uses navigator.credentials |
| **2.1** | **Seller KYC** | KYC status retrieval & gating | `seller-payouts.html`, `dashboard-seller.html` | `SellerKycScreen.kt` | `PARITY CONFIRMED` | GET `/auth/seller/kyc/status` |
| **2.2** | | KYC verification submission | `seller-payouts.html` | `SellerKycScreen.kt` | `PARITY CONFIRMED` | POST `/auth/seller/kyc/submit` with masked tax ID |
| **2.3** | | Fail-closed payout lock badge | Dynamic vetted/KYC pills in payout workbench | `KycBadge.kt` | `PARITY CONFIRMED` | Server-enforced gating |
| **3.1** | **Listings Management** | Draft listing creation | `seller-listings.html` | `CreateListingScreen.kt` | `PARITY CONFIRMED` | POST `/listings` |
| **3.2** | | Version intake & archive upload | Drag-and-drop ZIP / Git intake | System File Picker / Git intake | `PARITY CONFIRMED` | POST `/listings/{id}/versions` |
| **3.3** | | Version history & status tracking | `seller-listings.html` | `ListingDetailScreen.kt` | `PARITY CONFIRMED` | GET `/listings/{id}` |
| **4.1** | **Security Scanning** | Background scan status polling | 2-second adaptive poller | Kotlin Coroutines Flow polling | `PARITY CONFIRMED` | GET `/listings/{id}/versions/{v}/status` |
| **4.2** | | Multi-analyzer report (SAST/SBOM/Secrets) | `listing-detail.html` | `SecurityReportCard.kt` | `PARITY CONFIRMED` | Full breakdown of scan severities |
| **4.3** | | Redacted report for non-owners | Public summary card (owner sees line findings) | Public card vs Owner view | `PARITY CONFIRMED` | Backend gateway enforces redaction rules |
| **5.1** | **Catalog Search & Facets** | Keyword & semantic search | `browse-listings.html` | `BrowseScreen.kt` | `PARITY CONFIRMED` | Query params `q`, category filtering |
| **5.2** | | Price sorting & filters | Ascending, descending, recency | Sort dropdown & category chips | `PARITY CONFIRMED` | Server-driven parameters |
| **5.3** | | Verified-only live catalog filter | Live listing constraint + Vetted badge | Live listing constraint + Vetted badge | `PARITY CONFIRMED` | Pending/failed packages omitted from public feed |
| **6.1** | **Stripe Checkout & Orders**| Marketplace fee split (92/8) | `checkout.html` | `CheckoutScreen.kt` | `PARITY CONFIRMED` | 8% platform fee calculation |
| **6.2** | | Stripe Connect / Payment confirmation | `checkout.html` | `CheckoutScreen.kt` | `PARITY CONFIRMED` | Stripe Hosted / Dev test-confirm endpoint |
| **6.3** | | Instant cryptographic entitlement | `order-confirmation.html` | `OrderSuccessScreen.kt` | `PARITY CONFIRMED` | Order write generates signed entitlement |
| **7.1** | **Downloads & Delivery** | Package binary delivery | `dashboard-customer.html` | `CustomerLibraryScreen.kt` | `PARITY CONFIRMED` | GET `/orders/download/{id}` |
| **7.2** | | Unentitled access defense | 403 Forbidden intercept with purchase modal | 403 Forbidden intercept with snackbar | `PARITY CONFIRMED` | Validated by backend entitlement check |
| **8.1** | **Seller AI Insights** | AI Pricing suggestions | `seller-listings.html` | `PricingSuggestionsCard.kt` | `PARITY CONFIRMED` | POST `/assist/pricing-suggestions` via seller-assist |
| **8.2** | | AI Draft reply generation | `seller-listings.html` | `DraftReplyBottomSheet.kt` | `PARITY CONFIRMED` | POST `/assist/draft-reply` via seller-assist |
| **8.3** | | AI Security scan explanation | `listing-detail.html`, `seller-listings.html` | `ScanExplainerDialog.kt` | `PARITY CONFIRMED` | GET `/assist/explain/{scan_id}` |
| **9.1** | **Buyer Q&A & Broker** | Natural language listing Q&A | `listing-detail.html` | `ListingQaSection.kt` | `PARITY CONFIRMED` | POST `/assist/listings/{id}/ask` via buyer-assist |
| **9.2** | | Deterministic Question Routing | Seamless routing to instant answer vs seller | Seamless routing | `PARITY CONFIRMED` | POST `/broker/listings/{id}/route-question` |
| **9.3** | | Aggregate demand signal surfacing | `seller-listings.html` | `DemandSignalsCard.kt` | `PARITY CONFIRMED` | GET `/broker/sellers/{id}/demand-signals` |
| **10.1**| **Admin Operations** | Full Compliance & Fraud Control Suite | `admin-dashboard.html` | Not exposed in mobile client | `INTENTIONAL DIVERGENCE: DESKTOP_ONLY_ADMIN` | Heavy administrative, audit log, and financial release tools are strictly scoped to desktop web |
| **10.2**| | Held order SLA monitor & release | `admin-dashboard.html` | Not exposed in mobile client | `INTENTIONAL DIVERGENCE: DESKTOP_ONLY_ADMIN` | Restricted compliance workbench |
| **10.3**| | Platform-wide user moderation | `admin-dashboard.html` | Not exposed in mobile client | `INTENTIONAL DIVERGENCE: DESKTOP_ONLY_ADMIN` | Scoped to authorized desktop web operators |

---

## Verification Summary

- **Total Assessed Capabilities**: 28 line items
- **Parity Confirmed**: 24 items (100% core buyer & seller flows)
- **Intentional Divergences**: 4 items
  - `PLATFORM_NATIVE_CREDENTIALS`: Native Android BiometricPrompt vs. Web W3C WebAuthn credentials.
  - `DESKTOP_ONLY_ADMIN` (3 items): Scoping the comprehensive compliance, held-order release, and user moderation suites exclusively to desktop web.
