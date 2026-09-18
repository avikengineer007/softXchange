# softXchange Motion Architecture Specification: Trust Engine

> **Motif Ideology**: *"Nothing reaches a buyer unverified."*

---

## 1. The Convergence Primitive

The visual identity of softXchange is anchored by the transition from unverified chaos to verified, immutable order. The motion language expresses this through **Inward Convergence**:

1. **Orbital Micro-Particles**: 4 micro-particles instantiate at orbital offsets:
   - Top-Left: `translate(-22px, -22px)`
   - Top-Right: `translate(22px, -22px)`
   - Bottom-Left: `translate(-22px, 22px)`
   - Bottom-Right: `translate(22px, 22px)`
2. **Inward Pull**: Under the deceleration curve `cubic-bezier(0.16, 1, 0.3, 1)`, particles pull inward toward the anchor centroid over 360ms.
3. **Anchor Radiant Pulse**: Upon particle convergence, the anchor badge/mark pulses outward (`scale(1.06)` with radiant glow) and settles firmly into **Verified Emerald** (`#10B981`).

---

## 2. Timing & Easing Curves

| Motion Token | Value | Description |
| :--- | :--- | :--- |
| `--easing-convergence` | `cubic-bezier(0.16, 1, 0.3, 1)` | Swift entrance with long, stable deceleration tail |
| `--easing-spring` | `cubic-bezier(0.34, 1.56, 0.64, 1)` | Expressive overshoot for tactile badge locks |
| `--duration-badge-lock` | `360ms` | Total duration of the 4-particle convergence sequence |
| `--duration-admin-flourish` | `480ms` | Held-order release burst flourish |
| `--duration-neutral-fade` | `200ms` | Order refund or rejection neutral fade |
| `--color-emerald-verified` | `#10B981` | Immutable verified trust color (non-gradient) |

---

## 3. Contextual Touchpoints (Mandated Zones)

The convergence motif is **mandated** on the following verification milestones:

1. **Catalog Browse Grid (`browse-listings.html`)**:
   - When a listing card scrolls into the viewport, an `IntersectionObserver` triggers the 4-particle inward convergence lock onto the `.vetted-badge`.
   - **Single-Fire Guarantee**: Executed strictly once per card via `data-animated="1"`. Does not loop or replay on subsequent page scrolling.
2. **Landing Hero (`index.html`)**:
   - Ambient background particles periodically (every 7s) gather toward and absorb into the 3D bowtie brand mark, symbolizing software ingestion into the verification pipeline.
3. **Admin Operations (`admin-dashboard.html`)**:
   - Approving or releasing a held order triggers a 480ms radial convergence flourish across the order record.
4. **Security Scan Resolution (`listing-detail.html`)**:
   - Transition of package scan status to `passed` triggers the emerald convergence pulse.

---

## 4. Exclusion Rules (Barred Zones)

To preserve the sacred trust value of the verified emerald convergence, the motif is **strictly prohibited** in the following contexts:

1. **Checkout & Payment Loops (`checkout.html`)**:
   - Payment submission, card validation, and Razorpay webhooks must NEVER use convergence emerald or particle flourishes.
   - **Mandated Alternative**: Neutral, calming indeterminate spinner (`.calming-loading`, `.calming-spinner`) using muted slate-blue (`#5B8DEF`).
2. **Refund & Cancellation Flows**:
   - Order refunds, seller listing rejections, or suspensions must NEVER use green or radiant bursts.
   - **Mandated Alternative**: Flat, neutral opacity fade (`.refund-fade`, 200ms `neutralFade`).
3. **Generic Submit Buttons**:
   - Standard form submissions (e.g. login, search query submission, profile save) must use standard button press feedback (`scale(0.98)`), reserving particle convergence purely for trust milestones.

---

## 5. CSS Reference Implementation

```css
/* Glassmorphic Layering Token */
.glass-surface {
  background: rgba(15, 20, 32, 0.7);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
}

/* Convergence Easing & Emerald Anchor */
:root {
  --color-emerald-verified: #10B981;
  --easing-convergence: cubic-bezier(0.16, 1, 0.3, 1);
}

/* Inward Convergence Lock Animation */
@keyframes badgeConverge {
  0%   { transform: scale(0.85) translateY(3px); opacity: 0.6; }
  60%  { transform: scale(1.06) translateY(-1px); opacity: 1; box-shadow: 0 0 16px rgba(16, 185, 129, 0.45); }
  100% { transform: scale(1) translateY(0); opacity: 1; box-shadow: 0 0 6px rgba(16, 185, 129, 0.25); }
}
```
