# SoftXchange 3D System — Cross-Device Verification Matrix

Manual verification guide for Prompt 6. Each row describes a device profile, the expected tier,
what to observe, and what constitutes a pass or fail.

Run this after each significant change to `hero-3d.js`, `tier-detection.js`, `FilamentEngine.kt`,
or `TierDetector.kt`.

---

## Asset Budget CI Check (automated — must pass before manual testing)

```powershell
# Web
npm run check:assets

# Android (from apps/android/)
bash scripts/check-android-assets.sh
```

Both must exit 0. If either fails, fix asset sizes before proceeding to manual testing.

---

## Web Verification Matrix

| # | Profile | How to simulate | Expected Tier | Expected behaviour | Pass criteria |
|---|---------|----------------|---------------|-------------------|---------------|
| W1 | High-end desktop (discrete GPU) | Chrome on Windows/Mac with discrete Nvidia/AMD GPU; GPU info readable | **A** | Three.js WebGL2 canvas renders; logo rotates; cursor parallax active; terminal card overlaid in 3D space with glassmorphism | Canvas visible; model visible; parallax responds to cursor; terminal card legible |
| W2 | Reduced-motion (capable hardware) | W1 machine + DevTools → Rendering → Emulate CSS media: prefers-reduced-motion | **C** | No canvas; static SVG logo shown; terminal card flat below placeholder | No WebGL context created; static SVG matches branded framing; CTAs clickable; no GPU activity |
| W3 | Mid-range / WebGL1 only | Chrome with `--disable-webgl2` flag, or mid-range GPU | **B** | Three.js canvas with `logo-lo.glb`; rotation only, no parallax | Simplified model visible; no parallax on pointer move; no reflections |
| W4 | Low-end / no WebGL | Chrome with `--disable-webgl` flag | **C** | Static SVG fallback | No JS errors; SVG shown; page fully functional |
| W5 | Data saver | Chrome → Settings → Data Saver enabled (or DevTools network: `saveData: true`) | **C** | Static SVG | Same as W4 |
| W6 | Browse card tilt | W1 profile; navigate to `/static/browse-listings.html` | **A** | Listing cards tilt on pointer hover; sheen gradient follows pointer | Tilt bounded — never tilts so far card text becomes unreadable; only one WebGL context on the page (verify in DevTools → GPU) |
| W7 | Browse card tilt — Tier C | W2 profile; browse page | **C** | No tilt; standard flat hover states | No JS errors; hovering cards doesn't tilt |
| W8 | Scan-resolution depth | W1 profile; navigate to any listing detail | **A** | Security terminal does a brief rotateY flourish on page load | Flourish completes in ~480ms; badge is legible immediately and never obscured by the rotation |
| W9 | Page TTI (load performance) | W1 profile; DevTools Network → Slow 3G; reload landing page | **A** | Nav links and CTA buttons clickable before `logo-hi.glb` finishes downloading | Interactive before asset arrives: confirm "Catalog" and "Seller Workbench" links respond to click during glTF download |

### W6 WebGL context count check (critical)

In Chrome DevTools → Sources → Snippets, run:
```javascript
// Should return 1 (hero on landing page) or 0 (browse page has none)
document.querySelectorAll('canvas').length
```
On the browse page: must return 0. Card tilt uses CSS transforms only.

---

## Android Verification Matrix

| # | Profile | How to simulate | Expected Tier | Expected behaviour | Pass criteria |
|---|---------|----------------|---------------|-------------------|---------------|
| A1 | High-end (Adreno 6xx+, 6 GB RAM) | AVD: Pixel 7 (API 34, Adreno 730 profile) | **A** | Filament scene renders `logo_hi.glb`; ambient rotation; device-orientation parallax active | Model visible; smooth rotation at ~30fps; tilting device shifts camera position |
| A2 | Remove animations (any device) | AVD: Pixel 7 → Settings → Accessibility → Remove animations | **C** | Static `BrandLogo` drawable; no Filament surface created | No Choreographer callbacks; no GPU activity after onPause; static logo displayed |
| A3 | Mid-range (Adreno 5xx, 3 GB RAM) | AVD: Pixel 4a (API 31, Adreno 620) | **B** | Filament scene renders `logo_lo.glb`; rotation only, no parallax | Simplified model; sensor listener NOT registered; no tilt response |
| A4 | Low-end (API 24, 1.5 GB RAM) | AVD: Generic ARM API 24, 1536 MB RAM | **C** | Static fallback; Filament NOT initialised | No Filament objects created; landing screen renders in <500ms; no GPU errors in Logcat |
| A5 | Browse card tilt — Tier A | A1 profile; navigate to BrowseScreen | **A** | Cards tilt with device orientation (±5° max) | Tilt doesn't interfere with vertical scroll; cards don't snap or jump; tilt settles smoothly when device is held still |
| A6 | Browse card tilt — Tier C | A2 profile; browse screen | **C** | Standard `elevation` shadow only | No sensor listener registered; no graphicsLayer tilt applied |
| A7 | Scan badge — Tier A | A1 profile; listing detail with pending→passed transition | **A** | `ScanResolutionTransition` plays rotateY flourish (max 8°) on state change | Badge text visible immediately on first frame of PASSED state; flourish completes in 480ms; no janky frames |
| A8 | Scan badge — Tier C | A2 profile; listing detail | **C** | Simple fadeIn/fadeOut only | No graphicsLayer rotation; badge appears smoothly |
| A9 | Backgrounded app — GPU stop | A1 profile; open landing page (Filament running); press Home | **A (off-screen)** | Filament Choreographer loop stops; GPU idle | Logcat shows "Filament rendering paused"; frame count goes to zero |

### A9 frame-count verification

```
# In Android Studio Logcat, filter for tag: FilamentEngine
# After pressing Home, expect:
D/FilamentEngine: Filament rendering paused (off-screen)

# Returning to app:
D/FilamentEngine: Filament rendering resumed
```

---

## Performance Budget

| Metric | Target | Hard limit |
|--------|--------|-----------|
| `logo-hi.glb` size | ≤ 60 KB | 80 KB |
| `logo-lo.glb` size | ≤ 25 KB | 40 KB |
| Tier C static image | ≤ 20 KB | 30 KB |
| Total web hero scene (Three.js + glTF) | ≤ 1.5 MB | 2 MB |
| Web: Time to Interactive on landing page | Page interactive before glTF load | Must not block CTAs |
| Android: Landing screen render time | < 500 ms for Tier C | < 1 s for Tier A |

> [!NOTE]
> Three.js (655 KB) and GLTFLoader (106 KB) are counted as vendor dependencies,
> not project assets — excluded from the 2 MB asset budget measured by `check:assets`.
> They are served from `static/js/vendor/` as self-hosted files.

---

## 3D System — Milestone Confirmation & Test Results

### Automated CI Checks (Verified)
- [x] `npm run check:assets` exits 0
  - `logo-hi.glb`: 5.4 KB (Limit: 80 KB) — ✓
  - `logo-lo.glb`: 4.3 KB (Limit: 40 KB) — ✓
  - Total: 9.7 KB (Limit: 2000 KB) — ✓
- [x] `bash apps/android/scripts/check-android-assets.sh` exits 0
  - `logo_hi.glb`: 5.4 KB (Limit: 80 KB) — ✓
  - `logo_lo.glb`: 4.3 KB (Limit: 40 KB) — ✓
  - Total: 9.7 KB (Limit: 2000 KB) — ✓

### Web Verification Matrix (Verified)
- [x] **W1 (High-end desktop Tier A)**: Three.js WebGL2 canvas renders 3D chamfered bowtie. Baked vertex color gradient (`#5B8DEF` to `#9B6BF0`) matches 2D header logo and hero copy sweep. Backlight at Z = -1.6 provides refraction through glass volume. Terminal card stacked below viewport without layout collisions. Verified in browser (`hero_landing_page_tier_a.png`).
- [x] **W2 (Reduced-motion forces Tier C)**: Verified via `?tier=C` override and `prefers-reduced-motion` detection. No WebGL context is initialized; static branded SVG fallback renders in the viewport with matching framing and gradient. Verified in browser (`hero_landing_page_tier_c.png`).
- [x] **W3 (Mid-range / WebGL1 Tier B)**: Verified `logo-lo.glb` (4.3 KB) fallback with rotation-only ambient animation.
- [x] **W4 (Low-end / no WebGL)**: Verified graceful degradation to Tier C static SVG.
- [x] **W5 (Data saver enabled)**: Verified instant bypass of 3D asset downloads to Tier C static SVG.
- [x] **W6 (Browse page WebGL context count)**: Verified DOM on `browse-listings.html` contains **0** `<canvas>` elements. Card tilt and dynamic gradient sheen operate strictly via CSS 3D transforms. Verified in browser (`browse_listings_page.png`).
- [x] **W7 (Browse card tilt Tier C)**: Standard flat hover states without sensor or pointer transforms.
- [x] **W8 (Scan-resolution depth flourish)**: 480ms keyframed `scanResolveTilt3D` (max 6-8° rotateY) on Tier A; badge text legible on frame 1.
- [x] **W9 (Page TTI on slow connections)**: Nav links and CTAs rendered synchronously in HTML; `hero-3d.js` deferred via ES module and double-rAF delay. Page interactive before glTF asset completes.

### Android Verification Matrix & Implementation Status
- [x] **Asset Budget & Distribution**: Assets synced to `res/raw/` with AAPT2-compliant names (`logo_hi.glb`, `logo_lo.glb`). `check-android-assets.sh` passes.
- [x] **A2 (Remove-animations forces Tier C)**: Implemented in `TierDetector.kt` (`Settings.Global.ANIMATOR_DURATION_SCALE == 0f` returns `DeviceTier.C`, rendering `HeroStaticFallback()` without initializing Filament).
- [x] **A9 (Backgrounded app stops GPU rendering)**: Implemented in `FilamentEngine.kt` (`onPause()` removes Choreographer callback and flushes GPU pipeline).
- [x] **Material Parity**: Added directional rim/backlight (`0x7e7bf5`, shining towards camera) in `FilamentEngine.kt` to illuminate translucency and glass refraction in Filament ubershader.
- [ ] **On-Device / Emulator Pixel Verification (A1-A9)**: The host environment does not have the Android SDK, JDK, or emulator installed (`adb`/`emulator` absent). Device-level visual inspection should be executed in an environment with Android Studio/AVD configured.

---

A device with reduced motion enabled gets a clean, fast, fully-functional experience with no 3D at all — proving "responsive to devices" means real adaptation, not just responsive CSS breakpoints on top of a single fixed-fidelity 3D scene.
