# softXchange Functional Parity Audit: Web vs. Android

This document provides a comprehensive functional and architectural capability audit between the **softXchange Unified Web Frontend** (`apps/web-unified`) and the **Android Native Application** (`apps/android`).

---

## Architectural Guarantee: Single Backend Source of Truth

Both the unified web application and the native Android application are client frontends operating against the exact same backend microservice endpoints:
- **Auth Service** (`:8001`): `http://localhost:8001/auth/...`
- **Scan Service** (`:8002`): `http://localhost:8002/...`
- **Listings Service** (`:8003`): `http://localhost:8003/listings/...`
- **Payments Service** (`:8004`): `http://localhost:8004/orders/...` and `/connect/...`

Both frontends share:
1. Identical RS256 JWT access tokens and cryptographically hashed refresh tokens.
2. Identical database state (SQLite/PostgreSQL tables).
3. Identical security publish gates (`gate.py`), fraud hold rules (`HOLD_NEW_SELLER_HIGH_AMOUNT`), and entitlement verification.

---

## 8-Domain Capability Matrix

| Domain | Feature / Workflow | Web Unified (`apps/web-unified`) | Android App (`apps/android`) | Parity Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Auth & Identity** | Multi-role registration (Customer/Seller) | Supported (`/signup-customer.html`, `/signup-seller.html`) | Supported (`RegisterScreen.kt`) | **Full Parity** | Shared `/auth/signup` endpoint |
| | Password login with timing-attack defense | Supported (`/login-customer.html`, `/login-seller.html`) | Supported (`LoginScreen.kt`) | **Full Parity** | Unified error messages; memory-safe token handling |
| | In-memory token management | Supported (`SoftXchangeAuth` in `auth.js`) | Supported (`AuthRepository.kt` StateFlow) | **Full Parity** | Zero local storage / SharedPreferences for raw access tokens |
| | Server-side refresh token rotation | Supported (`/auth/refresh` on 401 intercept) | Supported (`TokenAuthenticator.kt`) | **Full Parity** | SHA-256 server-hashed refresh tokens |
| | Logout & token revocation | Supported (`SoftXchangeAuth.logout()`) | Supported (`AuthViewModel.logout()`) | **Full Parity** | Active revocation on auth-service |
| **2. Seller KYC** | KYC status retrieval | Supported (`seller-payouts.html`, `dashboard-seller.html`) | Supported (`SellerKycScreen.kt`) | **Full Parity** | Reads `/auth/seller/kyc/status` |
| | KYC submission with masked tax ID | Supported (`seller-payouts.html`) | Supported (`SellerKycScreen.kt`) | **Full Parity** | Submits to `/auth/seller/kyc/submit` |
| | Real-time payout gating badge | Supported (Badges in header & payout workbench) | Supported (`KycBadge.kt`) | **Full Parity** | Fail-closed payout lock |
| **3. Listings Mgmt** | Draft package creation | Supported (`seller-listings.html`) | Supported (`CreateListingScreen.kt`) | **Full Parity** | POST `/listings` |
| | Version upload / Git intake | Supported (ZIP file or Git repository URL) | Supported (File picker / Git URL) | **Full Parity** | POST `/listings/{id}/versions` |
| | Package version list & history | Supported (`seller-listings.html`) | Supported (`ListingDetailScreen.kt`) | **Full Parity** | GET `/listings/{id}` |
| **4. Security Scanning** | Background scan status polling | Supported (2s interval poller) | Supported (Coroutines polling) | **Full Parity** | GET `/listings/{id}/versions/{v}/status` |
| | Multi-analyzer breakdown (SAST/SBOM) | Supported (`listing-detail.html`) | Supported (`SecurityReportCard.kt`) | **Full Parity** | SAST, Dependency, Container, License |
| | Redacted findings report for non-owners | Supported (Owner sees details, public sees summary) | Supported (Owner-only detail view) | **Full Parity** | Redaction enforced at backend gateway |
| **5. Browse & Discovery**| Category & keyword search | Supported (`browse-listings.html`) | Supported (`BrowseScreen.kt`) | **Full Parity** | Query params `category`, `q` |
| | Price sorting (Asc / Desc / Recency) | Supported (`browse-listings.html`) | Supported (`BrowseScreen.kt`) | **Full Parity** | Parameter `sort_by` |
| | Live-only public catalog filter | Supported (Server-filtered + UI vetted badge) | Supported (`BrowseScreen.kt`) | **Full Parity** | Drafts/Pending never returned publicly |
| **6. Checkout & Orders** | Fee split calculation (92/8) | Supported (`checkout.html`) | Supported (`CheckoutScreen.kt`) | **Full Parity** | 8% flat marketplace fee calculated |
| | Stripe Connect / Test-confirm flow | Supported (`checkout.html`) | Supported (`CheckoutScreen.kt`) | **Full Parity** | Dev/Test confirm + Stripe Hosted checkout |
| | Instant entitlement creation | Supported (`order-confirmation.html`) | Supported (`OrderSuccessScreen.kt`) | **Full Parity** | Backend entitlement write on payment |
| **7. Downloads** | Customer package download delivery | Supported (`dashboard-customer.html`) | Supported (`CustomerLibraryScreen.kt`) | **Full Parity** | GET `/orders/download/{id}` |
| | Cryptographic entitlement check | Supported (403 if unentitled / unpaid) | Supported (403 handled with alert) | **Full Parity** | Direct backend token validation |
| **8. Admin & Ops** | Held orders SLA monitor & release | Supported (`admin-dashboard.html`) | Supported (`AdminDashboardScreen.kt`) | **Full Parity** | POST `/orders/admin/orders/{id}/release` |
| | Listing moderation & suspension | Supported (`admin-dashboard.html`) | Supported (`AdminListingsScreen.kt`) | **Full Parity** | POST `/listings/admin/{id}/suspend` |
| | Audit log inspection | Supported (`admin-dashboard.html`) | Supported (`AdminAuditScreen.kt`) | **Full Parity** | GET `/auth/admin/audit-log` |

---

## Verification Summary

All 8 functional domains maintain 100% API and semantic parity. Any update or mutation performed on the web interface is instantly visible on Android and vice-versa.
