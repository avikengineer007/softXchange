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
| **`RAZORPAY_KEY_ID`** | `payments-service` | Live API Key ID (`rzp_live_...`) | Public identifier for Razorpay Checkout and API requests. | 180 days | Razorpay calls fail closed; checkout disabled. |
| **`RAZORPAY_KEY_SECRET`** | `payments-service` | High-entropy Secret Key | Authenticates API requests for Orders, Route linked accounts, and refunds. | 180 days | **Fatal startup error**: Refuses to start with mock/dev keys in production. API calls fail closed. |
| **`RAZORPAY_WEBHOOK_SECRET`** | `payments-service` | Webhook Secret | Cryptographically verifies raw HTTP payload of inbound Razorpay webhooks (X-Razorpay-Signature). | Rotated if webhook secret updated | **Fatal rejection**: Inbound webhooks without valid signature return 400 Bad Request; orders remain unfulfilled. |
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
3. **Razorpay API Keys**: In production Razorpay live mode, generate dedicated live keys (`rzp_live_...`) with secret key stored securely in environment variables.
4. **Automated Rotation**: Use `scripts/rotate-secrets.py` to generate cryptographically random keys and hashes for rotation.
