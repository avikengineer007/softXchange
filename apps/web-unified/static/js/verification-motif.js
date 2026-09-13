/**
 * softXchange — Trust Engine: Convergence Motion Language
 * Motif Ideology: "Nothing reaches a buyer unverified."
 *
 * The Convergence Primitive:
 *   Scattered unverified chaos resolving inward into verified, immutable order.
 *   4 micro-particles pull inward from orbital coordinates toward a central anchor,
 *   locking cleanly into place with a subtle radiant pulse before settling into
 *   verified emerald (#10B981).
 *
 * Contextual Touchpoints:
 *   1. Browse Catalog: IntersectionObserver triggers 4-particle inward convergence lock
 *      onto the .vetted-badge strictly once when a listing card enters viewport.
 *   2. Landing Canvas: Ambient particles periodically gather toward and absorb into
 *      the central 3D brand mark / bowtie centroid.
 *   3. Admin Operations: Approving/releasing a held order triggers a 480ms convergence
 *      flourish; refunding/cancelling executes a flat, neutral 200ms fade.
 *
 * Negative Constraints & Exclusion Rules:
 *   - Strictly PROHIBITED on checkout loops, payment spinners, and generic submit buttons.
 *   - Financial transactions must use neutral, calming indeterminate rings (.calming-loading).
 *   - See tokens/motion.md for formal architecture specification.
 */

(function (window) {
  'use strict';

  // ── Helper: Check Exclusion Zones ───────────────────────────────────────────
  function isExcludedZone(element) {
    if (typeof window === 'undefined') return true;
    const path = (window.location.pathname || '').toLowerCase();
    if (path.includes('checkout')) return true;

    if (element && element.closest) {
      if (element.closest('.checkout-form, #checkout-form, .payment-form, .financial-modal, .payment-spinner-container')) {
        return true;
      }
    }
    return false;
  }

  // ── 1. The Convergence Primitive: 4-Particle Inward Lock ────────────────────
  function triggerBadgeConvergence(badgeEl) {
    if (!badgeEl || badgeEl.dataset.animated === '1') return;
    if (isExcludedZone(badgeEl)) return;

    badgeEl.dataset.animated = '1';

    // Wrap badge in .convergence-wrapper if not already wrapped
    let wrapper = badgeEl.parentElement;
    if (!wrapper || !wrapper.classList.contains('convergence-wrapper')) {
      wrapper = document.createElement('span');
      wrapper.className = 'convergence-wrapper';
      badgeEl.parentNode.insertBefore(wrapper, badgeEl);
      wrapper.appendChild(badgeEl);
    }

    // Inject 4 orbital micro-particles if not present
    if (!wrapper.querySelector('.convergence-particle')) {
      ['p-tl', 'p-tr', 'p-bl', 'p-br'].forEach((coordClass) => {
        const p = document.createElement('span');
        p.className = `convergence-particle ${coordClass}`;
        p.setAttribute('aria-hidden', 'true');
        wrapper.appendChild(p);
      });
    }

    // Trigger inward pull and anchor pulse
    wrapper.classList.add('animating-convergence');
    badgeEl.classList.add('badge-animate');

    badgeEl.addEventListener('animationend', () => {
      wrapper.classList.remove('animating-convergence');
      // Clean up particles
      wrapper.querySelectorAll('.convergence-particle').forEach(p => p.remove());
    }, { once: true });
  }

  // ── 2. Browse Grid: IntersectionObserver Single-Fire Hook ───────────────────
  function initBrowseBadgeConvergence() {
    const cards = document.querySelectorAll('.listing-card');
    if (!cards.length) return;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const badge = entry.target.querySelector('.vetted-badge');
        if (badge && badge.dataset.animated !== '1') {
          triggerBadgeConvergence(badge);
        }
        observer.unobserve(entry.target);
      });
    }, {
      root: null,
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.25,
    });

    cards.forEach((card) => {
      const badge = card.querySelector('.vetted-badge');
      if (badge && badge.dataset.animated !== '1') {
        observer.observe(card);
      }
    });
  }

  // ── 3. Landing Hero: Ambient Particle Absorption into Brand Mark ────────────
  function initHeroParticleAbsorption() {
    const heroTarget = document.querySelector('#hero-3d-viewport, .hero-bowtie-target, .hero-brand-mark, #hero-3d-logo');
    if (!heroTarget) return;

    function absorb() {
      if (!window.__ambientLayer || typeof window.__ambientLayer.activateAttractor !== 'function') return;

      const rect = heroTarget.getBoundingClientRect();
      // Translate centroid to Three.js normalized coordinates
      const cx = ((rect.left + rect.width / 2) / window.innerWidth) * 16 - 8;
      const cy = -((rect.top + rect.height / 2) / window.innerHeight) * 12 + 6;

      window.__ambientLayer.activateAttractor(cx, cy, 0, 0.0075);

      setTimeout(() => {
        if (window.__ambientLayer && typeof window.__ambientLayer.deactivateAttractor === 'function') {
          window.__ambientLayer.deactivateAttractor();
        }
      }, 1800);
    }

    setTimeout(() => {
      absorb();
      setInterval(absorb, 7000);
    }, 2800);
  }

  // ── 4. Admin Operations: Held-Order Release vs Refund ────────────────────────
  function triggerReleaseFlourish(targetEl) {
    if (!targetEl) return;
    targetEl.classList.remove('refund-fade');
    targetEl.classList.add('convergence-flourish');
    targetEl.addEventListener('animationend', () => {
      targetEl.classList.remove('convergence-flourish');
    }, { once: true });
  }

  function triggerRefundFade(targetEl) {
    if (!targetEl) return;
    targetEl.classList.remove('convergence-flourish');
    targetEl.classList.add('refund-fade');
  }

  // ── 5. Scan Resolution Moment ────────────────────────────────────────────────
  function triggerScanResolution(cardEl, passed) {
    if (!cardEl) return;
    const className = passed ? 'scan-resolve-pass' : 'scan-resolve-fail';
    cardEl.classList.add(className);
    cardEl.addEventListener('animationend', () => {
      cardEl.classList.remove(className);
    }, { once: true });
  }

  // ── Auto-initialize on DOM ready ───────────────────────────────────────────
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        initBrowseBadgeConvergence();
        initHeroParticleAbsorption();
      });
    } else {
      initBrowseBadgeConvergence();
      initHeroParticleAbsorption();
    }
  }

  // Export public API
  window.VerificationMotif = {
    triggerBadgeConvergence,
    initBrowseBadgeConvergence,
    triggerReleaseFlourish,
    triggerRefundFade,
    triggerScanResolution,
    isExcludedZone,
  };

})(window);
