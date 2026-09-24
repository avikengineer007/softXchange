/**
 * softXchange Global Runtime API Configuration
 * Automatically detects production / Cloudflare Pages / reverse proxy environments
 * and points service URLs to the live backend rather than hardcoded localhost ports.
 */
(function () {
  const isBrowser = typeof window !== 'undefined';
  if (!isBrowser) return;

  const hostname = window.location.hostname;
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
  const RAILWAY_BACKEND = 'https://softxchange-production.up.railway.app';
  const isRailway = hostname.endsWith('railway.app') || window.location.origin === RAILWAY_BACKEND;

  /**
   * Returns the correct base URL for a given service.
   *
   * Priority:
   *   1. Railway (Caddy handles internal routing) → relative path ''
   *   2. Local dev                               → explicit localhost port
   *   3. Cloudflare Pages / any other static CDN → absolute Railway backend URL
   *
   * NOTE: Do NOT use the pattern `prodBase || fallback` here.
   * When running on Railway, prodBase is intentionally '' (empty string),
   * which is falsy in JS and would silently fall through to the wrong branch.
   */
  function getBase(localPort) {
    if (isRailway)    return '';
    if (isLocalhost)  return `http://localhost:${localPort}`;
    return RAILWAY_BACKEND;
  }

  window.__CONFIG__ = Object.assign({
    authServiceUrl:     getBase(8001),
    scanServiceUrl:     getBase(8002),
    listingsServiceUrl: getBase(8003),
    paymentsServiceUrl: getBase(8004),
    buyerAssistUrl:     getBase(8005),
    sellerAssistUrl:    getBase(8006),
    brokerUrl:          getBase(8007),
  }, window.__CONFIG__ || {});
})();
