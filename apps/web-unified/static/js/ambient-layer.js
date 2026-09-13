/**
 * softXchange — Ambient 3D Depth Layer (<AmbientLayer />)
 *
 * Multi-tier progressive enhancement (Prompt 2 Specification):
 *   Tier A — Instanced Three.js particle canvas (N=450, muted luminance, soft radial falloff, strict 30 FPS cap via requestIdleCallback)
 *   Tier B — Hardware-accelerated CSS mesh gradient with subtle multi-axis drift (transform: translate3d)
 *   Tier C — Static, non-animated deep obsidian radial gradient (--bg-depth-gradient)
 *
 * Invariants & Constraints:
 *   - Targeted Deployment: Active on catalog browse grid and dashboards; strictly suppressed on checkout forms and terminal views.
 *   - Respects prefers-reduced-motion (forces Tier C).
 *   - Zero Total Blocking Time (TBT < 50ms) via deferred requestIdleCallback mounting.
 *   - Pauses on document hidden / tab switch.
 *   - ZERO browser storage APIs used.
 */

(function () {
  'use strict';

  // ── Targeted Deployment Negative Constraint ───────────────────────────────────
  // Suppress on high-density task flows (checkout forms, terminal views)
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  const path = (window.location.pathname || '').toLowerCase();
  const isExcludedFlow = (
    path.includes('checkout') ||
    document.body.dataset.suppressAmbient === 'true' ||
    document.querySelector('.terminal-view, .checkout-container, #checkout-form') !== null
  );

  if (isExcludedFlow) {
    // Completely suppress ambient 3D rendering on checkout/transaction task surfaces
    return;
  }

  // ── Device Tier Classification ──────────────────────────────────────────────
  function getDeviceTier() {
    if (window.__sxTier) {
      return typeof window.__sxTier === 'string' ? window.__sxTier : (window.__sxTier.tier || 'B');
    }
    if (document.documentElement.dataset.tier) {
      return document.documentElement.dataset.tier;
    }
    // Hard-downgrade: respect prefers-reduced-motion (WCAG 2.1 §2.3.3)
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return 'C';
    }
    if (navigator.connection && navigator.connection.saveData) {
      return 'C';
    }

    const cores = navigator.hardwareConcurrency || 4;
    // deviceMemory is approximate and often undefined in browsers; default to 8GB on dev machines
    const memGB = (typeof navigator.deviceMemory === 'number') ? navigator.deviceMemory : 8;

    if (cores >= 4 && memGB >= 4) return 'A';
    if (cores >= 2 && memGB >= 2) return 'B';
    return 'B'; // Fallback to Tier B on any hardware with WebGL
  }

  const TIER = getDeviceTier();
  window.__sxTier = typeof window.__sxTier === 'object' && window.__sxTier !== null
    ? window.__sxTier
    : { tier: TIER, reason: 'ambient-detected' };
  document.documentElement.dataset.tier = TIER;

  // ── Tier C: Static Obsidian Depth Gradient — nothing dynamic to mount ────────
  if (TIER === 'C') {
    document.body.classList.add('tier-c-bg');
    return;
  }

  // ── Tier B: Hardware-Accelerated CSS Mesh Gradient ───────────────────────────
  if (TIER === 'B') {
    const bg = document.createElement('div');
    bg.className = 'ambient-bg-tier-b';
    bg.setAttribute('aria-hidden', 'true');
    document.body.prepend(bg);
    return;
  }

  // ── Tier A: High-Performance WebGL Particle Canvas (N=450) ───────────────────
  // Deferred mount via requestIdleCallback so Total Blocking Time (TBT) stays < 50ms
  const mount = typeof requestIdleCallback === 'function'
    ? (fn) => requestIdleCallback(fn, { timeout: 1200 })
    : (fn) => setTimeout(fn, 120);

  mount(async function () {
    if (typeof THREE !== 'undefined') {
      initParticleField(THREE);
    } else {
      try {
        // Load local vendored Three.js module (offline-capable, zero CDN latency)
        const threeMod = await import('/static/js/vendor/three.module.min.js');
        initParticleField(threeMod);
      } catch (err) {
        console.warn('[softXchange Ambient] Local Three.js import failed, trying fallback:', err);
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/three@0.161.0/build/three.min.js';
        script.onload = () => initParticleField(window.THREE);
        script.onerror = function () {
          // Fallback to Tier B if CDN fails
          const bg = document.createElement('div');
          bg.className = 'ambient-bg-tier-b';
          bg.setAttribute('aria-hidden', 'true');
          document.body.prepend(bg);
        };
        document.head.appendChild(script);
      }
    }
  });

  // ── Particle Field Implementation ────────────────────────────────────────────
  function initParticleField(threeInstance) {
    const THREE = threeInstance || (typeof window !== 'undefined' ? window.THREE : null);
    if (!THREE) return;

    const PARTICLE_COUNT = 450; // Mandated N=450
    const TARGET_FPS = 30;      // Mandated strict 30 FPS cap
    const FRAME_INTERVAL = 1000 / TARGET_FPS;

    // Canvas setup
    const canvas = document.createElement('canvas');
    canvas.id = 'ambient-particle-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    canvas.style.cssText = `
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 0;
      opacity: 0;
      transition: opacity 0.8s ease;
    `;
    document.body.prepend(canvas);

    // Three.js scene & renderer
    const renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: false,
      powerPreference: 'low-power',
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 5;

    // Procedural soft radial falloff texture (avoids harsh pixel corners)
    function createRadialParticleTexture() {
      const texCanvas = document.createElement('canvas');
      texCanvas.width = 64;
      texCanvas.height = 64;
      const ctx = texCanvas.getContext('2d');
      const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
      grad.addColorStop(0, 'rgba(255, 255, 255, 1)');
      grad.addColorStop(0.3, 'rgba(255, 255, 255, 0.7)');
      grad.addColorStop(0.7, 'rgba(255, 255, 255, 0.15)');
      grad.addColorStop(1, 'rgba(255, 255, 255, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 64, 64);
      const texture = new THREE.CanvasTexture(texCanvas);
      texture.needsUpdate = true;
      return texture;
    }

    // Instanced particle coordinates & slow drift vectors
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const velocities = [];
    const phases = new Float32Array(PARTICLE_COUNT);

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      positions[i * 3]     = (Math.random() - 0.5) * 16; // x
      positions[i * 3 + 1] = (Math.random() - 0.5) * 12; // y
      positions[i * 3 + 2] = (Math.random() - 0.5) * 7;  // z
      phases[i] = Math.random() * Math.PI * 2;
      velocities.push({
        x: (Math.random() - 0.5) * 0.0025, // slow drift vector
        y: (Math.random() - 0.5) * 0.0018,
      });
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.PointsMaterial({
      color: 0x5B8DEF,
      size: 0.05,
      map: createRadialParticleTexture(),
      sizeAttenuation: true,
      transparent: true,
      opacity: 0.38, // Muted luminance
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    // Fade canvas in cleanly
    requestAnimationFrame(() => {
      canvas.style.opacity = '1';
    });

    // Bowtie Attractor for verification-motif.js landing brand mark absorption
    let _attractorActive = false;
    let _attractorTarget = { x: 0, y: 0, z: 0 };
    let _attractorStrength = 0.006;

    window.__ambientLayer = {
      activateAttractor(x = 0, y = 0, z = 0, strength = 0.006) {
        _attractorActive = true;
        _attractorTarget = { x, y, z };
        _attractorStrength = strength;
      },
      deactivateAttractor() {
        _attractorActive = false;
      },
      getParticleCount() {
        return PARTICLE_COUNT;
      },
      getTier() {
        return TIER;
      },
    };

    // Responsive resize handler (debounced)
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
      }, 150);
    });

    // Visibility-aware pause to conserve resources
    let _isPageVisible = !document.hidden;
    document.addEventListener('visibilitychange', () => {
      _isPageVisible = !document.hidden;
      if (_isPageVisible) {
        lastFrameTime = performance.now();
      }
    });

    // ── Strict 30 FPS Render Loop via requestIdleCallback ──────────────────────
    let lastFrameTime = performance.now();

    function updateParticles() {
      const pos = geometry.attributes.position.array;

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const i3 = i * 3;

        if (_attractorActive) {
          // Pull gently toward attractor centroid
          pos[i3]     += (_attractorTarget.x - pos[i3])     * _attractorStrength;
          pos[i3 + 1] += (_attractorTarget.y - pos[i3 + 1]) * _attractorStrength;
          pos[i3 + 2] += (_attractorTarget.z - pos[i3 + 2]) * _attractorStrength;
        } else {
          // Standard slow drift
          pos[i3]     += velocities[i].x;
          pos[i3 + 1] += velocities[i].y;

          // Soft boundary wrap
          if (pos[i3] > 8)   pos[i3] = -8;
          if (pos[i3] < -8)  pos[i3] = 8;
          if (pos[i3 + 1] > 6)  pos[i3 + 1] = -6;
          if (pos[i3 + 1] < -6) pos[i3 + 1] = 6;
        }
      }
      geometry.attributes.position.needsUpdate = true;
    }

    function loop(now) {
      if (!_isPageVisible) {
        requestAnimationFrame(loop);
        return;
      }

      const elapsed = now - lastFrameTime;

      if (elapsed >= FRAME_INTERVAL) {
        lastFrameTime = now - (elapsed % FRAME_INTERVAL);
        updateParticles();
        renderer.render(scene, camera);
      }

      requestAnimationFrame(loop);
    }

    requestAnimationFrame(loop);
  }
})();
