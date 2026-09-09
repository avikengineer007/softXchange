/**
 * softXchange Auth Client
 * 
 * SECURITY ARCHITECTURE:
 * - Access Token: Stored STRICTLY in an in-memory closure variable.
 *   Never persisted to localStorage or sessionStorage, mitigating XSS exfiltration.
 * - Refresh Token: Stored in an httpOnly, Secure, SameSite=Lax cookie managed
 *   exclusively by the browser and the /auth backend.
 * - Silent Re-authentication: On page load/refresh, calls /auth/refresh using
 *   the httpOnly cookie to re-populate the in-memory access token.
 */

(function (window) {
  // In-memory access token storage
  let _inMemoryAccessToken = null;
  let _currentUser = null;

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
      }
    },

    clearSession() {
      _inMemoryAccessToken = null;
      _currentUser = null;
    },

    /**
     * Submit login credentials.
     * Refresh token is automatically set as httpOnly cookie by the server.
     */
    async login(email, password) {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // Required to receive and send httpOnly refresh cookie
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.detail || "Invalid email or password.";
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

      const response = await fetch("/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.detail || "Failed to create account.";
        throw new Error(errorMsg);
      }

      return data;
    },

    /**
     * Re-fetch access token into memory using the httpOnly refresh cookie.
     */
    async silentRefresh() {
      try {
        const response = await fetch("/auth/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
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
        await fetch("/auth/logout", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({}),
        });
      } finally {
        this.clearSession();
      }
    },

    /**
     * Authenticated fetch helper for downstream services.
     */
    async fetchWithAuth(url, options = {}) {
      if (!_inMemoryAccessToken) {
        await this.silentRefresh();
      }

      const headers = Object.assign({}, options.headers || {});
      if (_inMemoryAccessToken) {
        headers["Authorization"] = `Bearer ${_inMemoryAccessToken}`;
      }

      let response = await fetch(url, { ...options, headers, credentials: "include" });

      // If token expired (401), try one silent refresh and retry
      if (response.status === 401) {
        const refreshed = await this.silentRefresh();
        if (refreshed && refreshed.access_token) {
          headers["Authorization"] = `Bearer ${refreshed.access_token}`;
          response = await fetch(url, { ...options, headers, credentials: "include" });
        }
      }

      return response;
    },
  };

  window.SoftXchangeAuth = AuthClient;
})(window);
