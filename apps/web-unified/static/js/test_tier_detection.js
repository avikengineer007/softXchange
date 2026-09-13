/**
 * test_tier_detection.js
 * Regression tests for tier-detection.js:
 * 1. prefers-reduced-motion -> Tier C
 * 2. saveData -> Tier C
 * 3. No WebGL -> Tier C
 * 4. WebGL1 only -> Tier B
 * 5. Low-end GPU -> Tier C
 * 6. Mid-range GPU -> Tier B
 * 7. Unrecognized GPU (undefined memory) -> Tier B (NOT Tier C)
 * 8. High-end GPU with undefined deviceMemory -> Tier A (NOT Tier C)
 * 9. High-end GPU with low memory (< 2GB) -> Tier B
 */

import assert from 'node:assert';
import { detectTier } from './tier-detection.js';

function setupEnvironment({
  reducedMotion = false,
  saveData = false,
  webgl2 = true,
  webgl1 = true,
  gpuRenderer = 'NVIDIA GeForce RTX 4080',
  deviceMemory = undefined,
}) {
  globalThis.window = {
    matchMedia: (query) => ({
      matches: query.includes('prefers-reduced-motion: reduce') ? reducedMotion : false,
    }),
  };

  const navMock = {
    connection: { saveData },
    deviceMemory,
  };

  try {
    Object.defineProperty(globalThis, 'navigator', {
      value: navMock,
      configurable: true,
      writable: true,
    });
  } catch (_) {
    globalThis.navigator.connection = navMock.connection;
    globalThis.navigator.deviceMemory = navMock.deviceMemory;
  }

  globalThis.document = {
    createElement: (tag) => {
      if (tag === 'canvas') {
        return {
          getContext: (type) => {
            if (type === 'webgl2') {
              if (!webgl2) return null;
              return {
                getExtension: (name) => (name === 'WEBGL_debug_renderer_info' ? {} : null),
                getParameter: () => gpuRenderer,
              };
            }
            if (type === 'webgl' || type === 'experimental-webgl') {
              if (!webgl1) return null;
              return {
                getExtension: (name) => (name === 'WEBGL_debug_renderer_info' ? {} : null),
                getParameter: () => gpuRenderer,
              };
            }
            return null;
          },
        };
      }
      return {};
    },
  };
}

console.log('Running tier-detection regression test suite...');

// Test 1: prefers-reduced-motion overrides hardware -> Tier C
setupEnvironment({ reducedMotion: true });
let res = detectTier();
assert.strictEqual(res.tier, 'C');
assert.strictEqual(res.reason, 'prefers-reduced-motion');
console.log('✔ Test 1: prefers-reduced-motion -> Tier C passed');

// Test 2: saveData -> Tier C
setupEnvironment({ saveData: true });
res = detectTier();
assert.strictEqual(res.tier, 'C');
assert.strictEqual(res.reason, 'saveData');
console.log('✔ Test 2: saveData -> Tier C passed');

// Test 3: No WebGL -> Tier C
setupEnvironment({ webgl2: false, webgl1: false });
res = detectTier();
assert.strictEqual(res.tier, 'C');
assert.strictEqual(res.reason, 'no-webgl');
console.log('✔ Test 3: No WebGL -> Tier C passed');

// Test 4: WebGL1 only -> Tier B
setupEnvironment({ webgl2: false, webgl1: true });
res = detectTier();
assert.strictEqual(res.tier, 'B');
assert.strictEqual(res.reason, 'webgl1-only');
console.log('✔ Test 4: WebGL1 only -> Tier B passed');

// Test 5: Low-end GPU -> Tier C
setupEnvironment({ gpuRenderer: 'llvmpipe (LLVM 12.0.0, 256 bits)' });
res = detectTier();
assert.strictEqual(res.tier, 'C');
console.log('✔ Test 5: Low-end GPU -> Tier C passed');

// Test 6: Mid-range GPU -> Tier B
setupEnvironment({ gpuRenderer: 'Intel(R) UHD Graphics 620' });
res = detectTier();
assert.strictEqual(res.tier, 'B');
console.log('✔ Test 6: Mid-range GPU -> Tier B passed');

// Test 7: REGRESSION TEST — Unrecognized GPU with undefined deviceMemory -> Tier B (NOT Tier C)
setupEnvironment({ gpuRenderer: 'Some Unknown Proprietary GPU 9000', deviceMemory: undefined });
res = detectTier();
assert.strictEqual(res.tier, 'B', `Expected Tier B for unrecognized GPU with undefined memory, got ${res.tier}`);
console.log('✔ Test 7 (Regression): Unrecognized GPU + undefined deviceMemory -> Tier B passed');

// Test 8: REGRESSION TEST — Capable GPU with undefined deviceMemory -> Tier A (NOT Tier C)
setupEnvironment({ gpuRenderer: 'NVIDIA GeForce RTX 3080', deviceMemory: undefined });
res = detectTier();
assert.strictEqual(res.tier, 'A', `Expected Tier A for capable GPU with undefined memory, got ${res.tier}`);
console.log('✔ Test 8 (Regression): Capable GPU + undefined deviceMemory -> Tier A passed');

// Test 9: Capable GPU with low memory (< 2GB) -> Tier B
setupEnvironment({ gpuRenderer: 'NVIDIA GeForce RTX 3080', deviceMemory: 1 });
res = detectTier();
assert.strictEqual(res.tier, 'B');
assert.strictEqual(res.reason, 'low-memory:1GB');
console.log('✔ Test 9: Capable GPU + low memory (<2GB) -> Tier B passed');

console.log('\nAll 9 tier-detection regression tests PASSED successfully!');
