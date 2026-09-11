/**
 * softXchange — Ambient 3D Background Layer
 *
 * Three-tier progressive enhancement:
 *   Tier A — Three.js particle field (~180 soft drifting light points, 30fps capped)
 *   Tier B — CSS radial gradient drift (@keyframes ambientDrift, zero WebGL)
 *   Tier C — Static CSS gradient only
 *
 * Rules:
 *  - Respects prefers-reduced-motion (forces Tier C)
 *  - Canvas mounts after critical DOM paints (deferred via requestIdleCallback)
 *  - Pauses via IntersectionObserver when page is hidden
 *  - Sets document.documentElement.dataset.tier = 'A'|'B'|'C' for CSS token activation
 *  - This module never touches any browser storage API
 */

(function () {
  'use strict';

  // ── Device Tier Classification ──────────────────────────────────────────────
  function getDeviceTier() {
    // Hard-downgrade: respect prefers-reduced-motion (WCAG 2.1 §2.3.3)
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return 'C';
    }

    const cores = navigator.hardwareConcurrency || 2;
    const memGB = navigator.deviceMemory || 1; // Only available on Chrome-family

    if (cores >= 4 && memGB >= 4) return 'A';
    if (cores >= 2 && memGB >= 2) return 'B';
    return 'C';
  }

  const TIER = getDeviceTier();
  document.documentElement.dataset.tier = TIER;

  // ── Tier C: Static gradient — nothing to mount ──────────────────────────────
  if (TIER === 'C') return;

  // ── Tier B: CSS ambient drift only ──────────────────────────────────────────
  if (TIER === 'B') {
    const bg = document.createElement('div');
    bg.className = 'ambient-bg-tier-b';
    bg.setAttribute('aria-hidden', 'true');
    document.body.prepend(bg);
    return;
  }

  // ── Tier A: Three.js Particle Field ─────────────────────────────────────────
  // Deferred mount — waits for idle time so TTI is not impacted
  const mount = typeof requestIdleCallback === 'function'
    ? (fn) => requestIdleCallback(fn, { timeout: 1200 })
    : (fn) => setTimeout(fn, 120);

  mount(function () {
    // Dynamic load Three.js from CDN if not already present
    if (typeof THREE !== 'undefined') {
      initParticleField();
    } else {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/three@0.161.0/build/three.module.min.js';
      script.type = 'module';
      script.onload = initParticleField;
      script.onerror = function () {
        // Graceful fallback to Tier B if Three.js fails to load
        const bg = document.createElement('div');
        bg.className = 'ambient-bg-tier-b';
        bg.setAttribute('aria-hidden', 'true');
        document.body.prepend(bg);
      };
      document.head.appendChild(script);
    }
  });

  // ── Particle Field Implementation ────────────────────────────────────────────
  function initParticleField() {
    // Use inline Three.js via import if loaded as module
    // Fallback: use global THREE if available
    if (typeof THREE === 'undefined') return;

    const PARTICLE_COUNT = 180;
    const TARGET_FPS = 30;
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
      z-index: -1;
      opacity: 0;
      transition: opacity 0.8s ease;
    `;
    document.body.prepend(canvas);

    // Three.js scene
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 5;

    // Particle geometry
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const velocities = [];
    const phases = new Float32Array(PARTICLE_COUNT);

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      positions[i * 3]     = (Math.random() - 0.5) * 14;  // x
      positions[i * 3 + 1] = (Math.random() - 0.5) * 10;  // y
      positions[i * 3 + 2] = (Math.random() - 0.5) * 6;   // z
      phases[i] = Math.random() * Math.PI * 2;
      velocities.push({
        x: (Math.random() - 0.5) * 0.003,
        y: (Math.random() - 0.5) * 0.002,
      });
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.PointsMaterial({
      color: 0x5B8DEF,
      size: 0.04,
      sizeAttenuation: true,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    // Fade canvas in after mount
    requestAnimationFrame(() => {
      canvas.style.opacity = '1';
    });

    // Bowtie attractor — particles can be pulled toward a point (used by verification-motif.js)
    let _attractorActive = false;
    let _attractorTarget = { x: 0, y: 0, z: 0 };
    let _attractorStrength = 0;

    window.__ambientLayer = {
      activateAttractor(x, y, z, strength = 0.006) {
        _attractorTarget = { x, y, z };
        _attractorStrength = strength;
        _attractorActive = true;
      },
      deactivateAttractor() {
        _attractorActive = false;
        _attractorStrength = 0;
      },
      getScene: () => scene,
    };

    // Resize handler
    function onResize() {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    }
    window.addEventListener('resize', onResize, { passive: true });

    // Pause when page hidden (battery/perf)
    let _paused = false;
    document.addEventListener('visibilitychange', () => {
      _paused = document.hidden;
    });

    // Animation loop with 30fps cap
    let _lastFrame = 0;
    let _time = 0;

    function animate(now) {
      if (_paused) {
        requestAnimationFrame(animate);
        return;
      }

      const delta = now - _lastFrame;
      if (delta < FRAME_INTERVAL) {
        requestAnimationFrame(animate);
        return;
      }
      _lastFrame = now - (delta % FRAME_INTERVAL);
      _time += 0.016;

      const pos = geometry.attributes.position.array;

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const ix = i * 3;
        const iy = ix + 1;
        const iz = ix + 2;

        // Sinusoidal calm wave movement
        pos[ix]     += velocities[i].x + Math.sin(_time * 0.3 + phases[i]) * 0.0008;
        pos[iy]     += velocities[i].y + Math.cos(_time * 0.25 + phases[i] * 1.3) * 0.0006;

        // Wrap around bounds
        if (pos[ix] > 7)  pos[ix] = -7;
        if (pos[ix] < -7) pos[ix] = 7;
        if (pos[iy] > 5)  pos[iy] = -5;
        if (pos[iy] < -5) pos[iy] = 5;

        // Attractor pull (for hero bowtie absorption)
        if (_attractorActive) {
          const dx = _attractorTarget.x - pos[ix];
          const dy = _attractorTarget.y - pos[iy];
          const dz = _attractorTarget.z - pos[iz];
          const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
          if (dist < 3.5) {
            pos[ix] += dx * _attractorStrength;
            pos[iy] += dy * _attractorStrength;
            pos[iz] += dz * _attractorStrength;
          }
        }
      }

      geometry.attributes.position.needsUpdate = true;
      renderer.render(scene, camera);
      requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
  }
})();
