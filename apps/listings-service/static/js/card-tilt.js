/**
 * softXchange — Browse Card 3D Tilt + Sheen (Prompt 3)
 *
 * Adds subtle CSS 3D perspective tilt to listing cards on Tier A.
 * IMPORTANT: implemented entirely with CSS transforms driven by pointer events —
 * no additional WebGL context. WebGL is reserved for the hero scene only.
 * Many simultaneous WebGL contexts is a real performance trap; we avoid it here.
 *
 * Tier A: pointer/gyroscope-driven tilt (±8°) + moving gradient-sheen highlight.
 * Tier B/C: does nothing — existing flat hover CSS from tokens.css handles it.
 *
 * The sheen highlight is a CSS ::after pseudo-element positioned via
 * --card-mx/--card-my custom properties — pure CSS rendering, zero GPU overhead.
 */

import { getDeviceTier } from './tier-detection.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_TILT_DEG    = 8;      // degrees — bounded so cards stay readable
const SMOOTH_FACTOR   = 0.12;   // lerp factor for tilt smoothing
const GYRO_SCALE      = 0.09;   // maps gyro ±90° to ±8° tilt
const RESET_DURATION  = '300ms';

// ─── Per-card State ───────────────────────────────────────────────────────────

/** @type {Map<HTMLElement, {targetX: number, targetY: number, currentX: number, currentY: number, rafId: number}>} */
const cardState = new Map();

// Shared gyro values (one listener, distributed to all cards)
let gyroX = 0, gyroY = 0;
let gyroActive = false;

// ─── Main Init ────────────────────────────────────────────────────────────────

/**
 * Initialise tilt on all `.listing-card` elements currently in the DOM,
 * and on any new ones added dynamically (browse page loads cards via fetch).
 */
export function initCardTilt() {
  const { tier } = getDeviceTier();

  // Tier B/C: flat hover CSS from tokens.css is sufficient, no tilt.
  if (tier !== 'A') return;

  injectSheenStyles();
  attachToExistingCards();
  watchForNewCards();

  // Gyroscope input (mobile — no pointer to follow on touch devices)
  setupGyroscope();
}

// ─── Card Binding ─────────────────────────────────────────────────────────────

function attachToExistingCards() {
  document.querySelectorAll('.listing-card').forEach(attachCard);
}

function watchForNewCards() {
  // The browse page populates cards via fetch; observe the container for additions
  const container = document.getElementById('listings-container');
  if (!container) return;

  const mo = new MutationObserver((mutations) => {
    mutations.forEach(m => {
      m.addedNodes.forEach(node => {
        if (node.nodeType !== 1) return;
        if (node.classList && node.classList.contains('listing-card')) {
          attachCard(node);
        }
        // Also check descendants (in case a wrapper div was added)
        node.querySelectorAll && node.querySelectorAll('.listing-card').forEach(attachCard);
      });
    });
  });
  mo.observe(container, { childList: true, subtree: true });
}

function attachCard(card) {
  if (cardState.has(card)) return;  // already attached

  const state = { targetX: 0, targetY: 0, currentX: 0, currentY: 0, rafId: null };
  cardState.set(card, state);

  // Pointer events (desktop / tablet with stylus)
  card.addEventListener('pointermove', (e) => onPointerMove(e, card), { passive: true });
  card.addEventListener('pointerenter', () => startSmoothLoop(card),  { passive: true });
  card.addEventListener('pointerleave', () => resetCard(card),        { passive: true });
}

// ─── Pointer Handler ──────────────────────────────────────────────────────────

function onPointerMove(e, card) {
  const state = cardState.get(card);
  if (!state) return;

  const rect = card.getBoundingClientRect();
  // Normalise pointer position to [-1, 1] within the card
  const nx = ((e.clientX - rect.left)  / rect.width  - 0.5) * 2;
  const ny = ((e.clientY - rect.top)   / rect.height - 0.5) * 2;

  state.targetX = -ny * MAX_TILT_DEG;   // tilt X = vertical pointer → rotation around X axis
  state.targetY =  nx * MAX_TILT_DEG;   // tilt Y = horizontal pointer → rotation around Y axis

  // Update sheen position custom properties (moves sheen highlight with pointer)
  card.style.setProperty('--card-mx', `${((nx + 1) / 2 * 100).toFixed(1)}%`);
  card.style.setProperty('--card-my', `${((ny + 1) / 2 * 100).toFixed(1)}%`);
}

// ─── Gyroscope Handler ────────────────────────────────────────────────────────

function setupGyroscope() {
  if (typeof DeviceOrientationEvent === 'undefined') return;

  const applyGyro = (e) => {
    if (e.gamma == null || e.beta == null) return;
    // gamma [-90,90] → tilt Y (left/right); beta [0,180] shifted → tilt X (forward/back)
    gyroX = Math.max(-1, Math.min(1, (e.beta - 45) / 45)) * MAX_TILT_DEG * GYRO_SCALE * 10;
    gyroY = Math.max(-1, Math.min(1, e.gamma / 45))       * MAX_TILT_DEG * GYRO_SCALE * 10;
    gyroActive = true;

    // Update all visible cards with gyro values when pointer isn't hovering
    cardState.forEach((state, card) => {
      // Only apply gyro if pointer isn't currently over this card
      if (state.targetX === 0 && state.targetY === 0) {
        state.targetX = gyroX;
        state.targetY = gyroY;
        if (!state.rafId) startSmoothLoop(card);
      }
    });
  };

  if (typeof DeviceOrientationEvent.requestPermission === 'function') {
    // iOS 13+: needs user gesture
    document.addEventListener('touchstart', async () => {
      try {
        const perm = await DeviceOrientationEvent.requestPermission();
        if (perm === 'granted') window.addEventListener('deviceorientation', applyGyro, { passive: true });
      } catch (_) {}
    }, { once: true, passive: true });
  } else {
    window.addEventListener('deviceorientation', applyGyro, { passive: true });
  }
}

// ─── Smooth RAF Loop ──────────────────────────────────────────────────────────

function startSmoothLoop(card) {
  const state = cardState.get(card);
  if (!state || state.rafId) return;

  function tick() {
    state.currentX += (state.targetX - state.currentX) * SMOOTH_FACTOR;
    state.currentY += (state.targetY - state.currentY) * SMOOTH_FACTOR;

    card.style.transform = `
      perspective(800px)
      rotateX(${state.currentX.toFixed(2)}deg)
      rotateY(${state.currentY.toFixed(2)}deg)
      translateZ(4px)
    `;

    // Keep looping until close enough to target (avoids infinite RAF)
    const settled = Math.abs(state.targetX - state.currentX) < 0.05 &&
                    Math.abs(state.targetY - state.currentY) < 0.05;
    if (!settled) {
      state.rafId = requestAnimationFrame(tick);
    } else {
      state.currentX = state.targetX;
      state.currentY = state.targetY;
      state.rafId = null;
      // If fully reset, clear transform entirely
      if (state.targetX === 0 && state.targetY === 0) {
        card.style.transform = '';
      }
    }
  }

  state.rafId = requestAnimationFrame(tick);
}

function resetCard(card) {
  const state = cardState.get(card);
  if (!state) return;

  state.targetX = 0;
  state.targetY = 0;

  // Smooth return to flat
  card.style.transition = `transform ${RESET_DURATION} var(--easing-standard)`;
  startSmoothLoop(card);

  // Remove sheen
  card.style.removeProperty('--card-mx');
  card.style.removeProperty('--card-my');

  // Clean up transition override after reset completes
  setTimeout(() => {
    if (card.style.transition) card.style.transition = '';
  }, 350);
}

// ─── Sheen Highlight Styles ───────────────────────────────────────────────────

function injectSheenStyles() {
  if (document.getElementById('sx-card-tilt-styles')) return;

  const style = document.createElement('style');
  style.id = 'sx-card-tilt-styles';
  style.textContent = `
    /* Tier A only — [data-tier="A"] rule in tokens.css enables preserve-3d */

    .listing-card {
      position: relative;
      overflow: hidden;
    }

    /* Moving gradient-sheen highlight — follows pointer via CSS custom properties */
    [data-tier="A"] .listing-card::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(
        circle at var(--card-mx, 50%) var(--card-my, 50%),
        rgba(255, 255, 255, 0.10) 0%,
        rgba(91, 141, 239, 0.06) 40%,
        transparent 70%
      );
      border-radius: inherit;
      pointer-events: none;
      transition: background 80ms ease;
    }

    /* On pointer leave, fade the sheen out */
    [data-tier="A"] .listing-card:not(:hover)::after {
      opacity: 0;
      transition: opacity 300ms ease, background 80ms ease;
    }
  `;
  document.head.appendChild(style);
}
