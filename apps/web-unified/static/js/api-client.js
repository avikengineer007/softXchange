/**
 * softXchange — Unified API Client
 * Centralized HTTP client configuration for all platform microservices.
 *
 * Enforces:
 *   - Config-driven service URLs with sensible localhost defaults
 *   - Automatic JWT Authorization header injection
 *   - Standardized error handling & response parsing
 *   - ZERO local application data caching (pure API client)
 */

// ── Service Endpoints Configuration ──────────────────────────────────────────
// When served over HTTPS or via standard reverse proxy (port 80/443), route to
// relative paths on the same origin. When running bare-metal dev, use port defaults.
const isReverseProxy = typeof window !== 'undefined' && 
  (window.location.protocol === 'https:' || window.location.port === '' || window.location.port === '80' || window.location.port === '443');

const DEFAULT_CONFIG = isReverseProxy ? {
  authServiceUrl:     '',
  scanServiceUrl:     '',
  listingsServiceUrl: '',
  paymentsServiceUrl: '',
  buyerAssistUrl:     '',
  sellerAssistUrl:    '',
  brokerUrl:          '',
} : {
  authServiceUrl:     'http://localhost:8001',
  scanServiceUrl:     'http://localhost:8002',
  listingsServiceUrl: 'http://localhost:8003',
  paymentsServiceUrl: 'http://localhost:8004',
  buyerAssistUrl:     'http://localhost:8005',
  sellerAssistUrl:    'http://localhost:8006',
  brokerUrl:          'http://localhost:8007',
};

// Allow runtime override via window.__CONFIG__ or meta tags
export const API_CONFIG = {
  ...DEFAULT_CONFIG,
  ...(typeof window !== 'undefined' && window.__CONFIG__ ? window.__CONFIG__ : {}),
};

// ── Base Fetch Wrapper ────────────────────────────────────────────────────────
async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});

  // If body is JSON object, stringify and set Content-Type
  let body = options.body;
  if (body && typeof body === 'object' && !(body instanceof FormData) && !(body instanceof Blob)) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(body);
  }

  // Inject Authorization Bearer token if available and not explicitly provided
  if (!headers.has('Authorization')) {
    const token = getActiveToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  }

  const response = await fetch(url, {
    ...options,
    headers,
    body,
  });

  // Parse JSON response if available
  const contentType = response.headers.get('content-type') || '';
  let data = null;
  if (contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch (_) {
      data = null;
    }
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const errorMsg = (data && typeof data === 'object' && (data.detail || data.message || data.error)) || response.statusText;
    const error = new Error(typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg));
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

// Helper to get active access token from the in-memory SoftXchangeAuth singleton.
// ZERO browser storage APIs (localStorage/sessionStorage/indexedDB) are touched here.
// auth.js is the sole token authority — it stores the token in a JS closure variable.
function getActiveToken() {
  if (typeof window === 'undefined') return null;
  // Delegate to auth.js in-memory singleton (set by auth.js IIFE on window)
  if (typeof window.SoftXchangeAuth !== 'undefined' && window.SoftXchangeAuth.getAccessToken) {
    return window.SoftXchangeAuth.getAccessToken();
  }
  return null;
}

// ── Service API Namespaces ────────────────────────────────────────────────────

export const AuthAPI = {
  // Unified login — both customer and seller hit the same endpoint.
  // The legacy /auth/customer/login and /auth/seller/login aliases also work.
  loginCustomer: (email, password) =>
    request(`${API_CONFIG.authServiceUrl}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      body: { email, password },
    }),

  loginSeller: (email, password) =>
    request(`${API_CONFIG.authServiceUrl}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      body: { email, password },
    }),

  // Signup routes: /auth/customer/signup and /auth/seller/signup
  signupCustomer: (email, password, displayName) =>
    request(`${API_CONFIG.authServiceUrl}/auth/customer/signup`, {
      method: 'POST',
      body: { email, password, display_name: displayName },
    }),

  signupSeller: (email, password, displayName) =>
    request(`${API_CONFIG.authServiceUrl}/auth/seller/signup`, {
      method: 'POST',
      body: { email, password, display_name: displayName },
    }),

  silentRefresh: () =>
    request(`${API_CONFIG.authServiceUrl}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      body: {},
    }),

  logout: () =>
    request(`${API_CONFIG.authServiceUrl}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      body: {},
    }),

  getProfile: () =>
    request(`${API_CONFIG.authServiceUrl}/auth/me`),

  getKycStatus: () =>
    request(`${API_CONFIG.authServiceUrl}/kyc/status`),

  submitKyc: (payload) =>
    request(`${API_CONFIG.authServiceUrl}/kyc/submit`, {
      method: 'POST',
      body: payload,
    }),

  adminListUsers: (role) =>
    request(`${API_CONFIG.authServiceUrl}/admin/users${role ? `?role=${role}` : ''}`),

  adminSetUserBan: (userId, banned) =>
    request(`${API_CONFIG.authServiceUrl}/admin/users/${userId}/ban`, {
      method: 'POST',
      body: { banned },
    }),
};

export const ListingsAPI = {
  getListings: (query = '', category = '', price = '') => {
    const params = new URLSearchParams();
    if (query) params.append('q', query);
    if (category) params.append('category', category);
    if (price) params.append('price', price);
    const qs = params.toString();
    return request(`${API_CONFIG.listingsServiceUrl}/listings${qs ? `?${qs}` : ''}`);
  },

  getListing: (id) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}`),

  createListing: (formData) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings`, {
      method: 'POST',
      body: formData,
    }),

  getSellerListings: () =>
    request(`${API_CONFIG.listingsServiceUrl}/seller/listings`),

  adminModerateListing: (id, approved) =>
    request(`${API_CONFIG.listingsServiceUrl}/admin/listings/${id}/moderate`, {
      method: 'POST',
      body: { approved },
    }),
};

export const ScanAPI = {
  getScanReport: (scanId) =>
    request(`${API_CONFIG.scanServiceUrl}/scans/${scanId}`),

  submitScan: (formData) =>
    request(`${API_CONFIG.scanServiceUrl}/scan`, {
      method: 'POST',
      body: formData,
    }),
};

export const PaymentsAPI = {
  createOrder: (listingId) =>
    request(`${API_CONFIG.paymentsServiceUrl}/orders`, {
      method: 'POST',
      body: { listing_id: listingId },
    }),

  getOrder: (orderId) =>
    request(`${API_CONFIG.paymentsServiceUrl}/orders/${orderId}`),

  confirmTestPayment: (orderId) =>
    request(`${API_CONFIG.paymentsServiceUrl}/orders/${orderId}/test-confirm`, {
      method: 'POST',
    }),

  getSellerPayouts: () =>
    request(`${API_CONFIG.paymentsServiceUrl}/seller/payouts`),

  getConnectStatus: () =>
    request(`${API_CONFIG.paymentsServiceUrl}/seller/connect/status`),

  startConnectOnboarding: () =>
    request(`${API_CONFIG.paymentsServiceUrl}/seller/connect/onboard`, {
      method: 'POST',
    }),

  adminGetHeldOrders: () =>
    request(`${API_CONFIG.paymentsServiceUrl}/admin/held-orders`),

  adminReleaseOrder: (orderId) =>
    request(`${API_CONFIG.paymentsServiceUrl}/admin/orders/${orderId}/release`, {
      method: 'POST',
    }),

  adminRefundOrder: (orderId, reason = 'fraud_prevention') =>
    request(`${API_CONFIG.paymentsServiceUrl}/admin/orders/${orderId}/refund`, {
      method: 'POST',
      body: { reason },
    }),
};

export const BuyerAssistAPI = {
  searchRelevant: (query, limit = 5) =>
    request(`${API_CONFIG.buyerAssistUrl}/assist/query`, {
      method: 'POST',
      body: { query, limit },
    }),

  draftQuestion: (listingId, topic) =>
    request(`${API_CONFIG.buyerAssistUrl}/assist/draft-question`, {
      method: 'POST',
      body: { listing_id: listingId, topic },
    }),
};

export const SellerAssistAPI = {
  suggestPricing: (category, features) =>
    request(`${API_CONFIG.sellerAssistUrl}/assist/pricing-suggestions`, {
      method: 'POST',
      body: { category, features },
    }),

  draftReply: (questionId, context) =>
    request(`${API_CONFIG.sellerAssistUrl}/assist/draft-reply`, {
      method: 'POST',
      body: { question_id: questionId, context },
    }),
};
