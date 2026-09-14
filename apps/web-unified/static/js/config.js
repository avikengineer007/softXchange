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
  const isCloudflare = hostname.endsWith('pages.dev');
  const RAILWAY_BACKEND = 'https://softxchange-production.up.railway.app';

  // In production (Railway or Cloudflare Pages), point to the Railway backend
  let prodBase = '';
  if (isCloudflare) {
    prodBase = RAILWAY_BACKEND;
  } else if (!isLocalhost) {
    prodBase = window.location.origin;
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
