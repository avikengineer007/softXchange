# softXchange Razorpay Live Mode Activation & Webhook Guide

This operational guide details the exact steps for switching payments-service from Razorpay test mode to live production mode.

---

## 1. Razorpay Live Mode Checklist

1. **Complete Platform Business Verification & Activation**:
   - Navigate to the [Razorpay Dashboard](https://dashboard.razorpay.com/).
   - Complete legal entity identity verification, business details, bank account linkage for platform fee settlements, and public support details.
2. **Enable Razorpay Route (Linked Accounts)**:
   - In Settings > Route, confirm Route / Linked Accounts product is active.
   - Configure split settlements and transfer parameters for seller marketplace payouts.
3. **Generate Production API Key**:
   - Navigate to Settings > API Keys.
   - Switch to **Live Mode** in the dashboard toggle.
   - Click **Generate Key**:
     - Save Key ID (`rzp_live_...`).
     - Save Key Secret securely (never log or commit to version control).
   - Configure `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` in `.env.production`.
4. **Register Live Webhook Endpoint**:
   - In Settings > Webhooks, click **Add New Webhook**:
     - Webhook URL: `https://<YOUR_DOMAIN>/payments/webhooks/razorpay`
     - Secret: Generate a high-entropy secret string and save as `RAZORPAY_WEBHOOK_SECRET` in `.env.production`.
     - Alert Email: ops@softxchange.io
     - Active Events:
       - `order.paid` (synchronizes order fulfillment & entitlement creation)
       - `payment.captured` (handles payment captures with cross-event idempotency)
       - `account.activated` (bridges Route linked account verification to auth-service KYC state machine)
       - `account.under_review` (maintains fail-closed KYC gate)
       - `account.suspended` (fails closed on suspended seller accounts)
       - `refund.processed` (tracks refund reconciliation)
   - Save and test the webhook endpoint ping.

---

## 2. Production Testing with Live Mode (Refundable Small Charge)

To verify end-to-end live payment flow safely:
1. Create a test listing on the production marketplace priced at $1.00 (100 cents / minor units).
2. Complete purchase through Razorpay Checkout.
3. Verify:
   - Synchronous verification via `POST /orders/{id}/verify` succeeds with valid signature.
   - Asynchronous webhook receives `order.paid` / `payment.captured` and handles duplicate delivery idempotently.
   - Order transitions to status `paid`.
   - Entitlement is created and cryptographically signed download link becomes active.
   - Platform fee (8%) is retained and net seller balance is recorded.
4. Immediately issue an admin refund via `POST /payments/orders/{id}/refund` to confirm payment reversal and entitlement revocation work cleanly.
