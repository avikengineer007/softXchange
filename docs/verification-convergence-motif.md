# softXchange Verification & Convergence Motion Language

This document codifies the platform-wide motion design language and "Verification Convergence" motif across the softXchange unified web frontend and native client experiences.

---

## 1. Philosophical Tenets

In softXchange's threat model and market positioning, **verified security is an active achievement, not a static label**. Security vetting transforms an untrusted binary package into a verified, cryptographically signed asset.

The visual and motion language reflects this transformation through the **Convergence Motif**:
- **Dispersed / Ambient Particles** represent the raw, unverified state of software distributed across diverse nodes.
- **Inward Attraction (Convergence)** represents the rigorous multi-scanner inspection, gate evaluation, and KYC compliance bringing order and trust.
- **Stable Green Glow / Badge** represents the final, immutable state of verified software.

---

## 2. Motion Specifications & Timing Profiles

All convergence animations are constructed using CSS transforms and SVG elements without introducing additional WebGL contexts, keeping CPU/GPU footprints negligible.

| Context | Trigger | Motion Profile | Duration | Visual Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Landing Hero Bowtie** | Periodic ambient breath (every 8.4s, Tier A) | Cubic-bezier `(0.16, 1, 0.3, 1)` (ease-out quartic) | 1200ms | 12 particle nodes pull inward toward the central bowtie centroid, then settle into orbit. |
| **Browse Grid Cards** | First intersection with viewport (`IntersectionObserver`) | Cubic-bezier `(0.25, 0.8, 0.25, 1)` | 640ms | 4 micro-particles converge toward the emerald status badge dot (`--badge-green`), fading out on contact. |
| **Listing Detail Security Badge** | Initial page mount / Scan state resolution | Cubic-bezier `(0.34, 1.56, 0.64, 1)` (spring) | 480ms | RotateY 3D flourish (±8°) settling into stable perspective with shimmering green border. |
| **Admin Held-Order Release** | Action click ("Release Payout") | Cubic-bezier `(0.175, 0.885, 0.32, 1.275)` | 480ms | Radial green flourish (`#10b981`) expanding from button into row border, settling row to "Released". |
| **Admin Order Refund** | Action click ("Refund") | Linear opacity transition | 200ms | Neutral opacity fade (`0.4`) with zero color flourish or celebratory motion. |

---

## 3. Negative Constraint: Checkout & Payment Ban

> [!CAUTION]
> **Strict Prohibition on Checkout & Payment Flows:**
> The Convergence Motif and any particle effects are **strictly prohibited** during checkout, payment authentication, or Stripe Connect handshakes.

### Rationale:
1. **Cognitive Load & Calmness**: Financial transactions require maximum clarity, sobriety, and cognitive calm. Extraneous motion creates user anxiety and distrust.
2. **Deterministic UI State**: The checkout button transitions strictly between standard states:
   - Default: Solid accent button (`Pay $XX.XX`).
   - Processing: Calming circular spinner with neutral blue accent (`calming-loading`), zero particle emission.
   - Succeeded: Instant redirect to `order-confirmation.html`.
3. **No False Certainty**: Payout and order settlements are cryptographic and financial state machine transitions; visual flourishes must not precede backend HTTP confirmation.

---

## 4. Implementation Reference

The motion language is implemented across two key modules:
- `apps/web-unified/static/js/verification-motif.js`: Standalone lightweight controller for DOM badge flourishes and admin action feedback.
- `apps/web-unified/static/js/ambient-layer.js`: Background particle canvas system adhering to Device Tiering (Tier A/B/C) with automatic pause when tabs are backgrounded.
