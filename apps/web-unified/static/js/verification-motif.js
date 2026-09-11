/**
 * softXchange — Verification/Convergence Motion Language
 *
 * Implements the "nothing reaches a buyer unverified" visual language.
 * This module defines WHERE and HOW the convergence motif appears,
 * and — critically — WHERE IT IS FORBIDDEN.
 *
 * Usage inventory:
 *   1. Browse Grid  — IntersectionObserver badge-settle on card enter (plays once per card)
 *   2. Landing Hero — Ambient particles periodically absorbed into bowtie centroid
 *   3. Admin Panel  — 480ms convergence flourish on held-order release
 *
 * Negative constraints (forbidden zones):
 *   - Checkout page:         Uses .calming-loading spinner only (plain blue, no green, no flourish)
 *   - Payment confirmation:  Uses .calming-loading spinner only
 *   - Order refund:          Uses neutralFade (200ms opacity, no color)
 *   - Any error state:       Never uses convergence green
 *
 * See docs/verification-convergence-motif.md for full specification.
 */

(function (window) {
  'use strict';

  // ── 1. Browse Grid: Badge Convergence on Card Scroll-Enter ─────────────────
  // IntersectionObserver triggers badgeConverge CSS keyframe once per card.
  // Animation timing: 360ms, spring easing (--easing-spring).
  function initBrowseBadgeConvergence() {
    const cards = document.querySelectorAll('.listing-card');
    if (!cards.length) return;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const badge = entry.target.querySelector('.vetted-badge');
        if (badge && !badge.dataset.animated) {
          badge.dataset.animated = '1';
          badge.classList.add('badge-animate');
          // Remove class after animation completes so it doesn't replay on layout shift
          badge.addEventListener('animationend', () => {
            badge.classList.remove('badge-animate');
          }, { once: true });
        }
        observer.unobserve(entry.target);
      });
    }, {
      root: null,
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.25,
    });

    cards.forEach((card) => observer.observe(card));
  }

  // ── 2. Landing Hero: Periodic Particle Absorption into Bowtie ─────────────
  // Activates the ambient-layer.js attractor toward the bowtie SVG centroid.
  // Fires every 7 seconds, active for 1.8 seconds, then releases.
  // Only activates when Tier A ambient layer is present.
  function initHeroParticleAbsorption() {
    const heroLogo = document.querySelector('.hero-bowtie-target');
    if (!heroLogo || !window.__ambientLayer) return;

    function pulse() {
      if (!window.__ambientLayer) return;

      // Get centroid of bowtie SVG in Three.js normalized device coords
      const rect = heroLogo.getBoundingClientRect();
      const cx = ((rect.left + rect.width / 2) / window.innerWidth)  * 14 - 7;
      const cy = -((rect.top  + rect.height / 2) / window.innerHeight) * 10 + 5;

      window.__ambientLayer.activateAttractor(cx, cy, 0, 0.007);

      setTimeout(() => {
        if (window.__ambientLayer) window.__ambientLayer.deactivateAttractor();
      }, 1800);
    }

    // Initial pulse after 3s, then every 7s
    setTimeout(() => {
      pulse();
      setInterval(pulse, 7000);
    }, 3000);
  }

  // ── 3. Admin: Held-Order Release Flourish ─────────────────────────────────
  // Call triggerReleaseFlourish(rowEl) after a successful /admin/orders/{id}/release call.
  // 480ms radial burst: convergence green, spring easing.
  // Contrasts with triggerRefundFade(rowEl) which uses plain opacity fade.
  function triggerReleaseFlourish(rowEl) {
    if (!rowEl) return;
    rowEl.classList.remove('refund-fade');
    rowEl.classList.add('convergence-flourish');
    rowEl.addEventListener('animationend', () => {
      rowEl.classList.remove('convergence-flourish');
    }, { once: true });
  }

  // 200ms neutral fade for refunds — plain, no color, no motif.
  function triggerRefundFade(rowEl) {
    if (!rowEl) return;
    rowEl.classList.remove('convergence-flourish');
    rowEl.classList.add('refund-fade');
    // Element typically removed from DOM after fade; no cleanup needed.
  }

  // ── 4. Listing Detail: Scan-Resolution Moment ────────────────────────────
  // Called when scan status transitions to 'passed'. Card gets scanResolvePass.
  // Called when scan status transitions to 'failed'. Card gets scanResolveFail.
  // These are defined as CSS @keyframes in tokens.css.
  function triggerScanResolution(cardEl, passed) {
    if (!cardEl) return;
    const className = passed ? 'scan-resolve-pass' : 'scan-resolve-fail';
    cardEl.classList.add(className);
    cardEl.addEventListener('animationend', () => {
      cardEl.classList.remove(className);
    }, { once: true });
  }

  // ── Auto-initialize on DOMContentLoaded ─────────────────────────────────
  window.addEventListener('DOMContentLoaded', () => {
    initBrowseBadgeConvergence();
    initHeroParticleAbsorption();
  });

  // Export public API
  window.VerificationMotif = {
    triggerReleaseFlourish,
    triggerRefundFade,
    triggerScanResolution,
    initBrowseBadgeConvergence,  // callable after dynamic card injection
  };

})(window);
