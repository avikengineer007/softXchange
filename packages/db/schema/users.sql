-- ============================================================================
-- softXchange / Manifest Marketplace - Users & Identity Schema
-- ============================================================================

-- Ensure UUID generation extension is available
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- User roles: customer, seller, admin
-- KYC statuses: unverified, pending, verified, rejected
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'seller', 'admin')),
    kyc_status VARCHAR(32) NOT NULL DEFAULT 'unverified' CHECK (kyc_status IN ('unverified', 'pending', 'verified', 'rejected')),
    display_name VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Payout Account (e.g., Stripe Connect Account ID; touched exclusively by payments-service)
    payout_account_id VARCHAR(255),
    
    -- KYC submission metadata (optional JSON for document references or business details)
    kyc_metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_kyc_status ON users(kyc_status);
CREATE INDEX IF NOT EXISTS idx_users_payout_account_id ON users(payout_account_id) WHERE payout_account_id IS NOT NULL;
