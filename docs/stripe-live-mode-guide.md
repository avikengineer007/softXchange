# softXchange Stripe Live Mode Activation & Webhook Guide

This operational guide details the exact steps for switching payments-service from Stripe test mode to live production mode.

---

## 1. Stripe Live Mode Checklist

1. **Complete Platform Business Verification**:
   - Navigate to [Stripe Dashboard](https://dashboard.stripe.com/).
   - Complete legal entity identity verification, bank account linkage for platform fee payouts, and public support information.
2. **Enable Stripe Connect Express**:
   - In Settings > Connect, confirm Connect Express accounts are active for sellers.
   - Configure branding (logo, marketplace name `softXchange`, brand color `#10b981`).
   - Confirm capabilities requested: `card_payments` and `transfers`.
3. **Generate Restricted Live API Key**:
   - Navigate to Developers > API Keys.
   - Click **Create restricted key** (never use the root secret key in production):
     - Name: `softxchange-payments-live`
     - Permissions:
       - `Charges`: Write
       - `PaymentIntents`: Write
       - `Connect`: Write
       - `Customers`: Write
       - `Refunds`: Write
       - `Webhook Endpoints`: Read
   - Save the key starting with `sk_live_...`.
4. **Register Live Webhook Endpoint**:
   - In Developers > Webhooks, click **Add destination**:
     - Endpoint URL: `https://<YOUR_DOMAIN>/payments/webhooks/stripe`
     - Listen to: **Events on your account** AND **Events on Connected accounts**.
     - Select events:
       - `account.updated` (bridges Connect onboarding verification to auth-service KYC)
       - `payment_intent.succeeded` (fulfills orders and generates entitlements)
       - `payment_intent.payment_failed` (marks orders failed)
       - `charge.refunded` (revokes entitlements on refund)
   - Copy the Signing Secret: starting with `whsec_...`.
   - Configure `STRIPE_WEBHOOK_SECRET=whsec_...` in `.env.production`.

---

## 2. Production Testing with Live Mode (Refundable Small Charge)

To verify end-to-end live payment flow safely:
1. Create a test listing on the production marketplace priced at $1.00 (100 cents).
2. Use a real credit card to purchase the package through Stripe Checkout.
3. Verify:
   - Webhook receives `payment_intent.succeeded`.
   - Order transitions to status `paid`.
   - Entitlement is created and download link becomes active.
   - Platform fee is retained and seller payout balance is recorded.
4. Immediately issue a refund from the Admin or Seller dashboard (or Stripe dashboard) to confirm refund reversal logic works cleanly.
