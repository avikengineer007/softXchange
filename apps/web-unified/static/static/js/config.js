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

  // In production:
  // - If directly on Railway (Caddy reverse proxies all services under same host): use relative paths ''
  // - If on Cloudflare Pages, Vercel, Netlify, custom domain, or any static host: point to live Railway backend
  let prodBase = '';
  if (isRailway) {
    prodBase = '';
  } else if (!isLocalhost) {
    prodBase = RAILWAY_BACKEND;
  }

  window.__CONFIG__ = Object.assign({
    authServiceUrl:     prodBase || (isLocalhost ? 'http://localhost:8001' : RAILWAY_BACKEND),
    scanServiceUrl:     prodBase || (isLocalhost ? 'http://localhost:8002' : RAILWAY_BACKEND),
    listingsServiceUrl: prodBase || (isLocalhost ? 'http://localhost:8003' : RAILWAY_BACKEND),
    paymentsServiceUrl: prodBase || (isLocalhost ? 'http://localhost:8004' : RAILWAY_BACKEND),
    buyerAssistUrl:     prodBase || (isLocalhost ? 'http://localhost:8005' : RAILWAY_BACKEND),
    sellerAssistUrl:    prodBase || (isLocalhost ? 'http://localhost:8006' : RAILWAY_BACKEND),
    brokerUrl:          prodBase || (isLocalhost ? 'http://localhost:8007' : RAILWAY_BACKEND),
  }, window.__CONFIG__ || {});
})();
