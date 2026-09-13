/**
 * softXchange Auth Client — Unified Frontend
 *
 * SECURITY ARCHITECTURE:
 * - Access Token: Stored STRICTLY in an in-memory closure variable.
 *   Never persisted to localStorage, sessionStorage, or indexedDB.
 *   This is an absolute architectural boundary enforced by test_storage_rule.py.
 * - Refresh Token: Stored in an httpOnly, Secure, SameSite=Lax cookie managed
 *   exclusively by the browser and the /auth backend.
 * - Silent Re-authentication: On page load/refresh, calls /auth/refresh using
 *   the httpOnly cookie to re-populate the in-memory access token.
 *
 * ROUTING: All redirects use root-relative canonical paths (/page.html).
 *   The /static/page.html alias is supported by run.py for backward compatibility
 *   but is NOT the canonical form. New code should always use root-relative.
 */

(function (window) {
  // In-memory access token storage — never touches any browser storage API
  let _inMemoryAccessToken = null;
  let _currentUser = null;

  // Resolve auth service base URL from runtime config or default
  const AUTH_BASE = (
    (typeof window !== 'undefined' && window.__CONFIG__ && window.__CONFIG__.authServiceUrl) ||
    'http://localhost:8001'
  );

  const AuthClient = {
    getAccessToken() {
      return _inMemoryAccessToken;
    },

    getUser() {
      return _currentUser;
    },

    setSession(tokenResponse) {
      if (tokenResponse && tokenResponse.access_token) {
        _inMemoryAccessToken = tokenResponse.access_token;
        _currentUser = tokenResponse.user;
        if (_currentUser) {
          initNotificationBell(_currentUser);
        }
      }
    },

    clearSession() {
      _inMemoryAccessToken = null;
      _currentUser = null;
      stopNotificationBell();
    },

    /**
     * Submit login credentials.
     * Refresh token is automatically set as httpOnly cookie by the server.
     */
    async login(email, password) {
      const response = await fetch(`${AUTH_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Required to receive and send httpOnly refresh cookie
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.detail || 'Invalid email or password.';
        throw new Error(errorMsg);
      }

      this.setSession(data);
      return data;
    },

    /**
     * Register a new user with specific role(s).
     * Signup creates user with email_verified=False.
     */
    async signup(email, password, roles, displayName = null) {
      const payload = {
        email,
        password,
        roles: Array.isArray(roles) ? roles : [roles],
        display_name: displayName,
      };

      const response = await fetch(`${AUTH_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.detail || 'Failed to create account.';
        throw new Error(errorMsg);
      }

      return data;
    },

    /**
     * Re-fetch access token into memory using the httpOnly refresh cookie.
     */
    async silentRefresh() {
      try {
        const response = await fetch(`${AUTH_BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({}),
        });

        if (!response.ok) {
          this.clearSession();
          return null;
        }

        const data = await response.json();
        this.setSession(data);
        return data;
      } catch (err) {
        this.clearSession();
        return null;
      }
    },

    /**
     * Terminate session, revoking refresh token on server and clearing cookie.
     */
    async logout() {
      try {
        await fetch(`${AUTH_BASE}/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({}),
        });
      } finally {
        this.clearSession();
      }
    },

    /**
     * Authenticated fetch helper for downstream services.
     * Reads token from in-memory closure — no storage APIs touched.
     */
    async fetchWithAuth(url, options = {}) {
      if (!_inMemoryAccessToken) {
        await this.silentRefresh();
      }

      const headers = Object.assign({}, options.headers || {});
      if (_inMemoryAccessToken) {
        headers['Authorization'] = `Bearer ${_inMemoryAccessToken}`;
      }

      let response = await fetch(url, { ...options, headers, credentials: 'include' });

      // If token expired (401), try one silent refresh and retry
      if (response.status === 401) {
        const refreshed = await this.silentRefresh();
        if (refreshed && refreshed.access_token) {
          headers['Authorization'] = `Bearer ${refreshed.access_token}`;
          response = await fetch(url, { ...options, headers, credentials: 'include' });
        }
      }

      return response;
    },

    /**
     * Role-aware post-login routing.
     * CANONICAL PATHS: root-relative (/page.html), not /static/page.html.
     * The /static/ alias is supported by run.py for backward compatibility only.
     *
     * - Seller lands on seller dashboard (even if also admin/customer)
     * - Customer lands on browse listings
     * - Admin-only account lands on catalog with persistent admin bar
     */
    routeUserAfterLogin(user) {
      if (!user) return;
      const roles = Array.isArray(user.roles) ? user.roles : (user.role ? [user.role] : []);

      if (roles.includes('seller')) {
        window.location.href = '/dashboard-seller.html';
        return;
      }

      if (roles.includes('customer')) {
        window.location.href = '/browse-listings.html';
        return;
      }

      // Default fallback (e.g. admin-only account) lands on catalog with admin bar
      window.location.href = '/browse-listings.html';
    },

    /**
     * Initializes persistent admin bar across pages if authenticated user is admin.
     * Admin bar link uses canonical root-relative path.
     */
    initPersistentAdminUI(user) {
      if (!user) return;
      const roles = Array.isArray(user.roles) ? user.roles : (user.role ? [user.role] : []);
      if (!roles.includes('admin')) return;

      if (document.getElementById('admin-persistent-bar')) return;

      const bar = document.createElement('div');
      bar.id = 'admin-persistent-bar';
      bar.className = 'admin-top-banner';
      bar.innerHTML = `
        <div style="display: flex; align-items: center; gap: var(--space-xs);">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: var(--badge-green);"></span>
          <span>Administrator Session Active</span>
        </div>
        <a href="/admin-dashboard.html" class="admin-banner-link">Admin Console &rarr;</a>
      `;
      document.body.prepend(bar);
    },
  };

  // ── Notification Bell Component & Poller ──────────────────────────────────
  let _notifPollTimer = null;

  async function updateNotificationBadge() {
    if (!AuthClient.getAccessToken()) return;
    try {
      const resp = await AuthClient.fetchWithAuth(`${AUTH_BASE}/notifications/unread-count`);
      if (resp.ok) {
        const data = await resp.json();
        const badge = document.getElementById('nav-notif-badge');
        if (badge) {
          if (data.unread_count > 0) {
            badge.textContent = data.unread_count > 99 ? '99+' : data.unread_count;
            badge.style.display = 'inline-flex';
          } else {
            badge.style.display = 'none';
          }
        }
      }
    } catch (_) {}
  }

  async function openNotificationDropdown() {
    const dropdown = document.getElementById('nav-notif-dropdown');
    if (!dropdown) return;
    const isVisible = dropdown.style.display === 'block';
    if (isVisible) {
      dropdown.style.display = 'none';
      return;
    }
    dropdown.style.display = 'block';
    dropdown.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted, #94a3b8); font-size: 0.85rem;">Loading notifications...</div>';

    try {
      const resp = await AuthClient.fetchWithAuth(`${AUTH_BASE}/notifications?limit=10`);
      if (resp.ok) {
        const data = await resp.json();
        renderNotificationList(data.notifications, data.unread_count);
      } else {
        dropdown.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted, #94a3b8); font-size: 0.85rem;">Failed to load notifications</div>';
      }
    } catch (_) {
      dropdown.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted, #94a3b8); font-size: 0.85rem;">Error loading notifications</div>';
    }
  }

  function renderNotificationList(items, unreadCount) {
    const dropdown = document.getElementById('nav-notif-dropdown');
    if (!dropdown) return;

    if (!items || items.length === 0) {
      dropdown.innerHTML = `
        <div style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); font-weight: 600; font-size: 0.85rem; color: var(--text-main, #f8fafc);">Notifications</div>
        <div style="padding: 24px; text-align: center; color: var(--text-muted, #94a3b8); font-size: 0.825rem;">No notifications yet</div>
      `;
      return;
    }

    let headerHtml = `
      <div style="padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; justify-content: space-between; align-items: center;">
        <span style="font-weight: 600; font-size: 0.85rem; color: var(--text-main, #f8fafc);">Notifications (${items.length})</span>
        ${unreadCount > 0 ? '<button id="btn-mark-all-read" style="background: none; border: none; color: #818cf8; cursor: pointer; font-size: 0.75rem; text-decoration: underline;">Mark all read</button>' : ''}
      </div>
      <div style="max-height: 340px; overflow-y: auto;">
    `;

    let itemsHtml = items.map(n => {
      const isUnread = !n.read_at;
      const typeLabel = (n.type || '').replace(/_/g, ' ').toUpperCase();
      let summary = '';
      if (n.payload) {
        summary = n.payload.message || n.payload.listing_title || (n.payload.amount_cents ? `$${(n.payload.amount_cents/100).toFixed(2)}` : '') || '';
      }
      const timeStr = new Date(n.created_at).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

      return `
        <div class="notif-item" data-id="${n.id}" style="padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.05); cursor: pointer; background: ${isUnread ? 'rgba(99,102,241,0.08)' : 'transparent'}; transition: background 0.15s ease;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <span style="font-size: 0.7rem; font-weight: 700; letter-spacing: 0.03em; color: ${isUnread ? '#818cf8' : 'var(--text-muted, #94a3b8)'};">${typeLabel}</span>
            <span style="font-size: 0.7rem; color: var(--text-muted, #64748b);">${timeStr}</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-main, #f1f5f9); line-height: 1.35;">${summary || typeLabel}</div>
        </div>
      `;
    }).join('');

    dropdown.innerHTML = headerHtml + itemsHtml + '</div>';

    const markAllBtn = document.getElementById('btn-mark-all-read');
    if (markAllBtn) {
      markAllBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await AuthClient.fetchWithAuth(`${AUTH_BASE}/notifications/read-all`, { method: 'POST' });
        updateNotificationBadge();
        openNotificationDropdown();
      });
    }

    dropdown.querySelectorAll('.notif-item').forEach(el => {
      el.addEventListener('click', async () => {
        const id = el.getAttribute('data-id');
        await AuthClient.fetchWithAuth(`${AUTH_BASE}/notifications/${id}/read`, { method: 'POST' });
        el.style.background = 'transparent';
        updateNotificationBadge();
      });
    });
  }

  function initNotificationBell(user) {
    if (!user) return;
    if (document.getElementById('nav-notif-container')) return;

    const nav = document.querySelector('.nav-links') || document.querySelector('nav') || document.querySelector('.navbar');
    if (!nav) return;

    const container = document.createElement('div');
    container.id = 'nav-notif-container';
    container.style.position = 'relative';
    container.style.display = 'inline-flex';
    container.style.alignItems = 'center';
    container.style.margin = '0 8px';

    container.innerHTML = `
      <button id="nav-notif-btn" aria-label="Notifications" style="position: relative; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); color: var(--text-main, #f8fafc); border-radius: 8px; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s ease;">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        <span id="nav-notif-badge" style="display: none; position: absolute; top: -4px; right: -4px; background: #ef4444; color: white; border-radius: 10px; font-size: 0.65rem; font-weight: 700; min-width: 16px; height: 16px; padding: 0 4px; align-items: center; justify-content: center; border: 2px solid #0f172a;"></span>
      </button>
      <div id="nav-notif-dropdown" style="display: none; position: absolute; top: calc(100% + 8px); right: 0; width: 320px; background: #1e293b; border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5); z-index: 9999;"></div>
    `;

    nav.appendChild(container);

    const btn = container.querySelector('#nav-notif-btn');
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openNotificationDropdown();
    });

    document.addEventListener('click', (e) => {
      const dropdown = document.getElementById('nav-notif-dropdown');
      if (dropdown && dropdown.style.display === 'block' && !container.contains(e.target)) {
        dropdown.style.display = 'none';
      }
    });

    updateNotificationBadge();
    if (_notifPollTimer) clearInterval(_notifPollTimer);
    _notifPollTimer = setInterval(updateNotificationBadge, 35000);
  }

  function stopNotificationBell() {
    if (_notifPollTimer) {
      clearInterval(_notifPollTimer);
      _notifPollTimer = null;
    }
    const el = document.getElementById('nav-notif-container');
    if (el) el.remove();
  }

  // Automatically check and show admin banner & notification bell if logged in
  window.addEventListener('DOMContentLoaded', async () => {
    try {
      const session = await AuthClient.silentRefresh();
      if (session && session.user) {
        AuthClient.initPersistentAdminUI(session.user);
        initNotificationBell(session.user);
      }
    } catch (e) {
      // Unauthenticated visitor — normal, no action needed
    }
  });

  window.SoftXchangeAuth = AuthClient;
})(window);
