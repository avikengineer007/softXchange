/**
 * softXchange — Device Capability Tier Detection
 * Shared ES module consumed by hero-3d.js and card-tilt.js.
 *
 * Tiers:
 *   A — High: WebGL2 + capable GPU + sufficient memory + no reduced-motion preference
 *   B — Mid:  WebGL2 present but mid-range GPU, or WebGL1 only
 *   C — Low:  No WebGL2, low-end GPU, reduced-motion preference, or data-saver mode
 *
 * Results are cached to window.__sxTier and written to <html data-tier="A|B|C">
 * so CSS can also key off tier (e.g. [data-tier="A"] .listing-card { … }).
 *
 * Critical: prefers-reduced-motion and saveData ALWAYS force Tier C regardless
 * of hardware — accessibility and bandwidth preferences trump capability.
 */

/** @typedef {{ tier: 'A' | 'B' | 'C', reason: string }} TierResult */

/** Known low-end GPU substrings → Tier C */
const GPU_TIER_C = [
  'intel hd', 'intel(r) hd', 'intel uhd',
  'mesa', 'swiftshader', 'llvmpipe', 'softpipe',
  'microsoft basic', 'vmware',
  'mali-4', 'mali-t',        // very old Mali
  'adreno (tm) 3',           // Adreno 3xx
  'powervr sgx',
];

/** Known mid-range GPU substrings → Tier B */
const GPU_TIER_B = [
  'intel iris',
  'radeon rx 5', 'radeon rx 4',   // AMD mid-gen
  'adreno (tm) 5', 'adreno (tm) 4',
  'mali-g5', 'mali-g6',
  'apple a9', 'apple a10',
];

/**
 * Classify a GPU renderer string into a tier.
 * @param {string} renderer
 * @returns {'A' | 'B' | 'C' | null}  null = unrecognized
 */
function classifyGPUString(renderer) {
  const r = renderer.toLowerCase();
  if (GPU_TIER_C.some(s => r.includes(s))) return 'C';
  if (GPU_TIER_B.some(s => r.includes(s))) return 'B';

  // Positively-known high-end patterns → Tier A
  const highEnd = [
    'nvidia', 'geforce', 'rtx', 'gtx',
    'radeon rx 6', 'radeon rx 7', 'radeon pro',
    'apple m', 'apple a1', 'apple a11', 'apple a12', 'apple a13', 'apple a14', 'apple a15', 'apple a16', 'apple a17',
    'adreno (tm) 6', 'adreno (tm) 7', 'adreno (tm) 8',
    'mali-g7', 'mali-g8', 'mali-g9',
    'arc a',   // Intel Arc
  ];
  if (highEnd.some(s => r.includes(s))) return 'A';

  // Unrecognized (ANGLE generic string, restricted API, unknown GPU) → Tier B
  // Safe middle assumption: don't assume high-end capability we can't verify.
  return null;
}

/**
 * Run tier detection synchronously at call time.
 * @returns {TierResult}
 */
export function detectTier() {
  // Support explicit query param override for verification/testing (e.g. ?tier=A)
  try {
    const override = new URLSearchParams(window.location.search).get('tier');
    if (override && ['A', 'B', 'C'].includes(override.toUpperCase())) {
      return { tier: override.toUpperCase(), reason: `query-param:${override}` };
    }
  } catch (_) {}

  // 1. Accessibility: prefers-reduced-motion always wins
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return { tier: 'C', reason: 'prefers-reduced-motion' };
  }

  // 2. Network: data-saver preference
  if (navigator.connection && navigator.connection.saveData) {
    return { tier: 'C', reason: 'saveData' };
  }

  // 3. WebGL2 availability
  const canvas = document.createElement('canvas');
  const gl2 = canvas.getContext('webgl2');
  if (!gl2) {
    // Try WebGL1 for Tier B
    const gl1 = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl1) return { tier: 'C', reason: 'no-webgl' };
    return { tier: 'B', reason: 'webgl1-only' };
  }

  // 4. GPU renderer string classification
  let gpuTier = null;
  let gpuRenderer = '(unavailable)';
  try {
    const ext = gl2.getExtension('WEBGL_debug_renderer_info');
    if (ext) {
      gpuRenderer = gl2.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
      gpuTier = classifyGPUString(gpuRenderer);
    }
  } catch (_) {
    // Extension blocked (strict privacy mode) — treat as unrecognized
  }

  // Unrecognized or unavailable → Tier B (safe middle, not Tier A)
  if (gpuTier === null) {
    gpuTier = 'B';
    gpuRenderer += ' [unrecognized → B]';
  }

  if (gpuTier === 'C') return { tier: 'C', reason: `gpu:${gpuRenderer}` };
  if (gpuTier === 'B') return { tier: 'B', reason: `gpu:${gpuRenderer}` };

  // 5. Memory check (deviceMemory is approximate, may be undefined)
  const mem = navigator.deviceMemory;
  if (typeof mem === 'number' && mem < 2) {
    return { tier: 'B', reason: `low-memory:${mem}GB` };
  }

  return { tier: 'A', reason: `gpu:${gpuRenderer}` };
}

/**
 * Detect tier, cache result on window, set data-tier attribute on <html>.
 * Idempotent — returns cached result on repeat calls.
 * @returns {TierResult}
 */
export function getDeviceTier() {
  if (window.__sxTier) return window.__sxTier;

  const result = detectTier();
  window.__sxTier = result;
  document.documentElement.setAttribute('data-tier', result.tier);

  if (typeof console !== 'undefined') {
    console.debug(`[softXchange] Device tier: ${result.tier} (${result.reason})`);
  }

  return result;
}

export default getDeviceTier;
