export type UserRole = 'customer' | 'seller' | 'admin';

export type KYCStatus = 'unverified' | 'pending' | 'verified' | 'rejected';

export interface User {
  id: string;
  email: string;
  role: UserRole;
  kyc_status: KYCStatus;
  display_name?: string | null;
  is_active: boolean;
  payout_account_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: User;
}

export interface KYCStatusResponse {
  user_id: string;
  email: string;
  role: UserRole;
  kyc_status: KYCStatus;
  can_sell: boolean;
  can_receive_payout: boolean;
  details?: Record<string, unknown> | null;
}

export interface KYCSubmitRequest {
  legal_name: string;
  business_type: 'individual' | 'company';
  registration_number?: string;
  country: string;
  documents?: Record<string, unknown>;
}
