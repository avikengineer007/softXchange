# softXchange Production Go-Live Checklist & Sign-Off Runbook

Complete each verification gate sequentially before announcing softXchange production availability.

---

## Pre-Launch Verification Matrix

| Section | Gate Description | Verification Command / Target | Status | Operator Sign-Off |
| :--- | :--- | :--- | :---: | :--- |
| **1. Secrets & Auth** | `ADMIN_PROVISIONING_CODE` rotated from dev default (`sx_admin_sec_9f7a28e4c19d4b8e8f2a1b3c4d5e6f7a`). Min 32 chars. | `python scripts/rotate-secrets.py` | [ ] | |
| | RS256 RSA keypairs generated and mounted (`jwt_private.pem`, `jwt_public.pem`). Ephemeral keys disabled. | `pytest tests/test_production_fail_closed.py -k rs256` | [ ] | |
| | Inter-service HMAC secret generated (`INTERNAL_SERVICE_SECRET`). | Check `.env.production` | [ ] | |
| | Strong PostgreSQL database password generated. | Check `.env.production` | [ ] | |
| **2. Database** | Managed PostgreSQL instance active with 4 isolated logical databases (`softxchange_auth`, `softxchange_listings`, `softxchange_payments`, `softxchange_scan`). | `psql -l` | [ ] | |
| | Alembic migrations applied forward to `head` across all 4 databases. | `pytest tests/test_database_migrations.py` | [ ] | |
| | Connection pooling enabled (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`). | Inspect `src/database.py` | [ ] | |
| | Disaster recovery: automated backup script tested and test restore executed into staging. | `scripts/backup-db.sh && scripts/restore-db.sh` | [ ] | |
| **3. Payments** | Stripe Connect platform verified in live mode with Express onboarding active. | Stripe Dashboard > Connect | [ ] | |
| | Restricted live API key (`sk_live_...`) configured in `payments-service`. | `.env.production` | [ ] | |
| | Production webhook URL (`https://<domain>/payments/webhooks/stripe`) registered with live signing secret (`whsec_...`). | Stripe Dashboard > Webhooks | [ ] | |
| | Fail-closed gate: `/orders/{id}/test-confirm` confirmed completely unregistered (404). | `pytest tests/test_production_fail_closed.py -k test_confirm` | [ ] | |
| | Safe live transaction verified: small $1.00 charge completed, entitlement verified, and immediately refunded. | End-to-end checkout walkthrough | [ ] | |
| **4. Domain & TLS** | Reverse proxy (Caddy) listening on port 80 & 443 with Let's Encrypt automated TLS. | `curl -I https://<domain>` (HTTP 200) | [ ] | |
| | Plain HTTP redirects to HTTPS automatically (308 / 301). | `curl -I http://<domain>` (Redirects) | [ ] | |
| | Security headers active: HSTS (`Strict-Transport-Security`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`. | `curl -I https://<domain>` | [ ] | |
| | Single-domain reverse proxy routing verified: `/auth`, `/listings`, `/orders`, `/payments`, `/scan`, `/assist`, `/broker`. | API endpoints respond over HTTPS | [ ] | |
| **5. Security & CVE** | `SCAN_OSV_FAIL_OPEN` policy deliberately configured (`false` recommended for fail-closed marketplace integrity). | Check scan-service config | [ ] | |
| | 3D `.glb` assets comply with byte-size budget. | `npm run check:assets` | [ ] | |
| | Zero-Storage-Rule: frontend verified free of `localStorage`, `sessionStorage`, and unauthorized cookies. | `pytest tests/test_storage_rule.py` | [ ] | |
| **6. Observability** | Correlation IDs (`X-Correlation-ID`) propagating across microservice requests. | Inspect request logs | [ ] | |
| | Alert hooks active for Stripe webhook rejections, scan job dead states, and repeated admin elevation failures. | Trigger test alert | [ ] | |
| **7. CI/CD** | Automated pipeline configured in `.github/workflows/ci-cd.yml` with manual approval gate for production. | GitHub Actions repository settings | [ ] | |

---

## Final Manual Walkthrough Protocol (On Production Domain)

Execute this exact sequence through the public HTTPS domain before declaring general availability:

1. **Customer Registration**: Sign up a new customer account at `https://<domain>/signup-customer.html`. Confirm redirect to `dashboard-customer.html`.
2. **Seller Onboarding**: Sign up a seller at `https://<domain>/signup-seller.html`. Complete Stripe Connect Express bank onboarding. Confirm KYC verified status in seller dashboard.
3. **Software Package Upload & Scan**: Upload a software package archive via `https://<domain>/seller-listings.html`. Verify background scan job transitions from `pending_scan` to `passed`.
4. **Natural Language Discovery & Q&A**: Search for the listing on `https://<domain>/browse-listings.html`. Open `listing-detail.html`, submit a natural-language question, and verify broker route handling.
5. **Purchase & Entitlement**: Proceed to `checkout.html`, pay via Stripe Checkout, confirm redirect to `order-confirmation.html`. Verify entitlement token and download link active.
6. **Package Download**: Click download and confirm cryptographic artifact is served securely.
7. **Admin Elevation**: Execute one-time admin code provisioning at `https://<domain>/admin-dashboard.html`. Verify admin audit logs display single-use consumption and subsequent reuse is blocked.
