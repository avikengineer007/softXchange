/**
 * softXchange — Unified API Client
 * Centralized HTTP client singleton for all platform microservices.
 *
 * Enforces:
 *   - Config-driven service URLs with sensible localhost defaults
 *   - Automated JWKS-backed token validation
 *   - Unified exponential backoff retry policies (transient 5xx/network errors)
 *   - Structured error boundaries and ApiError class
 *   - ZERO local application data caching (pure API client)
 */

// ── Service Endpoints Configuration ──────────────────────────────────────────
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

// ── Structured API Error Class ───────────────────────────────────────────────
export class ApiError extends Error {
  constructor(status, code, message, details = null, raw = null) {
    super(message || `Request failed with status ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || `HTTP_${status}`;
    this.details = details;
    this.raw = raw;
  }
}

// ── JWKS Cache & Client Token Validation ──────────────────────────────────────
let _cachedJwks = null;
let _jwksFetchPromise = null;

export async function fetchJwks() {
  if (_cachedJwks) return _cachedJwks;
  if (_jwksFetchPromise) return _jwksFetchPromise;

  _jwksFetchPromise = (async () => {
    try {
      const res = await fetch(`${API_CONFIG.authServiceUrl}/auth/.well-known/jwks.json`);
      if (res.ok) {
        _cachedJwks = await res.json();
        return _cachedJwks;
      }
    } catch (_) {
      // Fail soft if offline or auth-service not responding
    } finally {
      _jwksFetchPromise = null;
    }
    return null;
  })();

  return _jwksFetchPromise;
}

/**
 * Validates JWT token structure and expiration against current time.
 * Verifies matching 'kid' if JWKS is cached.
 */
export async function validateTokenWithJwks(token) {
  if (!token || typeof token !== 'string') return { valid: false, reason: 'missing_token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, reason: 'malformed_jwt' };

  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    // Check expiration with 5-second leeway
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now - 5) {
      return { valid: false, reason: 'expired', payload };
    }

    // Optional JWKS kid check
    const jwks = await fetchJwks();
    if (jwks && Array.isArray(jwks.keys) && header.kid) {
      const match = jwks.keys.some(k => k.kid === header.kid);
      if (!match) {
        return { valid: false, reason: 'unrecognized_key_id', header };
      }
    }

    return { valid: true, payload, header };
  } catch (err) {
    return { valid: false, reason: 'parse_error', error: err.message };
  }
}

// ── In-Memory Token Resolver ──────────────────────────────────────────────────
function getActiveToken() {
  if (typeof window === 'undefined') return null;
  if (typeof window.SoftXchangeAuth !== 'undefined' && window.SoftXchangeAuth.getAccessToken) {
    return window.SoftXchangeAuth.getAccessToken();
  }
  return null;
}

// ── Exponential Backoff Fetch ─────────────────────────────────────────────────
async function fetchWithRetry(url, options = {}, maxRetries = 2, baseDelayMs = 250) {
  let attempt = 0;
  while (true) {
    try {
      const response = await fetch(url, options);

      // Retry on transient gateway / server errors: 502, 503, 504
      if ([502, 503, 504].includes(response.status) && attempt < maxRetries) {
        attempt++;
        const jitter = Math.random() * 80;
        const delay = (baseDelayMs * Math.pow(2, attempt - 1)) + jitter;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }

      return response;
    } catch (networkErr) {
      // Retry on connection drop / DNS blip
      if (attempt < maxRetries) {
        attempt++;
        const jitter = Math.random() * 80;
        const delay = (baseDelayMs * Math.pow(2, attempt - 1)) + jitter;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw new ApiError(0, 'NETWORK_ERROR', `Network connection failed: ${networkErr.message}`, null, networkErr);
    }
  }
}

// ── Base Request Wrapper ──────────────────────────────────────────────────────
export async function request(url, options = {}) {
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

  const response = await fetchWithRetry(url, {
    ...options,
    headers,
    body,
  });

  // Parse response
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
    let errorCode = `HTTP_${response.status}`;
    let errorMsg = response.statusText;
    let errorDetails = null;

    if (data && typeof data === 'object') {
      errorMsg = data.detail || data.message || data.error || errorMsg;
      errorCode = data.code || errorCode;
      errorDetails = data.details || data;
    }

    throw new ApiError(response.status, errorCode, typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg), errorDetails, data);
  }

  return data;
}

// ── UI Error Boundary Renderer ────────────────────────────────────────────────
export function renderErrorBoundary(container, error, retryFn = null) {
  if (!container) return;
  const target = typeof container === 'string' ? document.querySelector(container) : container;
  if (!target) return;

  const isNetwork = error.status === 0 || error.code === 'NETWORK_ERROR';
  const title = isNetwork ? 'Connection Lost' : (error.status === 403 ? 'Action Restricted' : 'Request Failed');
  const message = error.message || 'An unexpected error occurred while communicating with the service.';

  target.innerHTML = `
    <div class="glass-surface" style="padding: 1.5rem; border-radius: 12px; border-left: 4px solid var(--color-danger, #F87171); margin: 1rem 0;">
      <div style="display: flex; align-items: flex-start; gap: 0.875rem;">
        <div style="color: var(--color-danger, #F87171); font-size: 1.25rem;">⚠️</div>
        <div style="flex: 1;">
          <h4 style="margin: 0 0 0.25rem 0; color: var(--text-primary); font-size: 1rem;">${title}</h4>
          <p style="margin: 0 0 0.75rem 0; color: var(--text-secondary); font-size: 0.875rem;">${message}</p>
          ${retryFn ? `<button type="button" class="action-btn retry-action-btn" style="padding: 0.375rem 0.75rem; font-size: 0.8125rem;">Retry Request</button>` : ''}
        </div>
      </div>
    </div>
  `;

  if (retryFn) {
    const btn = target.querySelector('.retry-action-btn');
    if (btn) btn.addEventListener('click', () => retryFn(), { once: true });
  }
}

// ── Service API Namespaces ────────────────────────────────────────────────────

export const AuthAPI = {
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

  // Reviews & Ratings
  getListingReviews: (id, limit = 50, offset = 0) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/reviews?limit=${limit}&offset=${offset}`),

  submitReview: (id, rating, reviewText = '') =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/reviews`, {
      method: 'POST',
      body: { rating, review_text: reviewText },
    }),

  // Wishlist / Saved Listings
  getSavedListings: () =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/saved`),

  saveListing: (id) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/save`, {
      method: 'POST',
    }),

  unsaveListing: (id) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/save`, {
      method: 'DELETE',
    }),

  toggleSaveListing: (id) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/toggle-save`, {
      method: 'POST',
    }),

  getSavedStatus: (id) =>
    request(`${API_CONFIG.listingsServiceUrl}/listings/${id}/saved-status`),
};

export const NotificationsAPI = {
  getNotifications: (limit = 50, offset = 0, unreadOnly = false) =>
    request(`${API_CONFIG.authServiceUrl}/notifications?limit=${limit}&offset=${offset}&unread_only=${unreadOnly}`),

  getUnreadCount: () =>
    request(`${API_CONFIG.authServiceUrl}/notifications/unread-count`),

  markRead: (id) =>
    request(`${API_CONFIG.authServiceUrl}/notifications/${id}/read`, {
      method: 'POST',
    }),

  markAllRead: () =>
    request(`${API_CONFIG.authServiceUrl}/notifications/read-all`, {
      method: 'POST',
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

  askQuestion: (listingId, question) =>
    request(`${API_CONFIG.buyerAssistUrl}/assist/listings/${listingId}/ask`, {
      method: 'POST',
      body: { question },
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

  explainScan: (scanId) =>
    request(`${API_CONFIG.sellerAssistUrl}/assist/explain/${scanId}`),
};

export const BrokerAPI = {
  routeQuestion: (listingId, questionText, buyerId = null) =>
    request(`${API_CONFIG.brokerUrl}/broker/listings/${listingId}/route-question`, {
      method: 'POST',
      body: { question_text: questionText, buyer_id: buyerId },
    }),

  getDemandSignals: (sellerId) =>
    request(`${API_CONFIG.brokerUrl}/broker/sellers/${sellerId}/demand-signals`),

  recordSearchEvent: (queryText, matchedCategory = null) =>
    request(`${API_CONFIG.brokerUrl}/broker/events/search`, {
      method: 'POST',
      body: { query_text: queryText, matched_category: matchedCategory },
    }),
};

// Global attach for non-module script tag usage
if (typeof window !== 'undefined') {
  window.SoftXchangeAPI = {
    API_CONFIG,
    ApiError,
    fetchJwks,
    validateTokenWithJwks,
    request,
    renderErrorBoundary,
    AuthAPI,
    ListingsAPI,
    ScanAPI,
    PaymentsAPI,
    BuyerAssistAPI,
    SellerAssistAPI,
    BrokerAPI,
    NotificationsAPI,
  };
}
