# softXchange Production Secrets Inventory & Management

This inventory catalogues every secret, key, and credential across the softXchange marketplace architecture.

---

## 1. Secrets Inventory Matrix

| Secret Name | Consuming Service(s) | Format & Algorithm | Purpose | Rotation Cadence | Fail-Closed Policy in Production |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`JWT_PRIVATE_KEY`** | `auth-service` | 2048-bit RSA PEM (`-----BEGIN PRIVATE KEY-----`) | Signs RS256 JWT access and identity tokens. | 90 days (or immediate on compromise) | **Fatal startup error**: Refuses to start with auto-generated/ephemeral keys when `ENVIRONMENT=production`. |
| **`JWT_PUBLIC_KEY`** | `auth-service`, `listings-service`, `payments-service` | 2048-bit RSA PEM (`-----BEGIN PUBLIC KEY-----`) | Verifies RS256 JWT tokens downstream without signing authority. | Paired with private key | Downstream requests fail with 401 Unauthorized if verification key is missing or mismatched. |
| **`INTERNAL_SERVICE_SECRET`** | `payments-service`, `auth-service` | 64-char Hex (HMAC-SHA256) | Authenticates inter-service KYC callbacks (`payments -> auth`) with 5-min replay protection. | 180 days | Webhook callback rejected with 401/403 if signature is invalid or timestamp > 300s old. |
| **`ADMIN_PROVISIONING_CODE`** | `auth-service` | High-entropy string (`sx_admin_` + 64 hex chars) | Single-use elevation token for initial system administrator setup. | Single-use / Rotated per elevation | **Fatal startup error**: Refuses startup if matching known dev default (`sx_admin_sec_9f7a28e4c19d4b8e8f2a1b3c4d5e6f7a`) or < 32 chars. |
| **`STRIPE_SECRET_KEY`** | `payments-service` | Restricted Live Key (`sk_live_...`) | Communicates with Stripe API for PaymentIntents, Connect onboarding, and transfers. | Per Stripe security policy | Stripe calls fail closed; checkout disabled. |
| **`STRIPE_WEBHOOK_SECRET`** | `payments-service` | Live Signing Secret (`whsec_...`) | Cryptographically verifies raw HTTP payload of inbound Stripe webhooks. | Rotated if endpoint updated | **Fatal rejection**: Inbound webhooks without valid signature return 400 Bad Request; orders remain unfulfilled. |
| **`DATABASE_URL` (Auth)** | `auth-service` | PostgreSQL URI with credentials | Connection string for `softxchange_auth` logical database. | 180 days | Service cannot boot if database authentication fails. |
| **`DATABASE_URL` (Listings)** | `listings-service`, `buyer-assist`, `broker` | PostgreSQL URI with credentials | Connection string for `softxchange_listings` logical database. | 180 days | Service cannot boot if database authentication fails. |
| **`DATABASE_URL` (Payments)** | `payments-service` | PostgreSQL URI with credentials | Connection string for `softxchange_payments` logical database. | 180 days | Service cannot boot if database authentication fails. |
| **`DATABASE_URL` (Scan)** | `scan-service` | PostgreSQL URI with credentials | Connection string for `softxchange_scan` logical database. | 180 days | Service cannot boot if database authentication fails. |
| **`MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD`** | `minio`, `scan-service`, `listings-service` | Alphanumeric credentials | Administrative and client access to local/staging S3 object storage. | 180 days | Storage operations fail closed. |
| **`EMAIL_PROVIDER_API_KEY`** | `auth-service` | Resend API Key (`re_...`) | Authenticates outbound transactional email delivery (password reset, email verification). | 90 days (or on compromise) | **Operational Alert**: When missing or failing, transactions fail-safe with generic user response and trigger CRITICAL operational alerts to ops/support. |

---

## 2. Secrets Management & Injection Guidelines

1. **Never Commit Secrets**: Secrets must never be committed to Git or baked into Docker container images.
2. **Environment Variable Injection**: In production, inject secrets via the container runtime environment (`environment:` or `.env.production` loaded outside version control) or native cloud secret manager (AWS Secrets Manager, GCP Secret Manager, Vault).
3. **Restricted Stripe Keys**: In production Stripe live mode, create a **Restricted API Key** with only the permissions required (`Charges: Write`, `PaymentIntents: Write`, `Connect: Write`, `Refunds: Write`), rather than the root account secret key.
4. **Automated Rotation**: Use `scripts/rotate-secrets.py` to generate cryptographically random keys and hashes for rotation.
