/**
 * softXchange — 3D Hero Scene (Prompt 2)
 * Renders the bowtie/hourglass logo in a Three.js WebGL canvas on the landing page.
 *
 * Tier A: Full glTF model (logo-hi.glb), PBR glass material, ambient rotation,
 *         cursor/orientation parallax, environment reflections, scan-card in 3D space.
 * Tier B: Simplified model (logo-lo.glb), opaque gradient material, rotation only.
 * Tier C: Static SVG fallback — no canvas, no asset load, no layout shift.
 *
 * Loading strategy (Prompt 2 requirement):
 *   1. Page renders nav + text + CTAs immediately (no blocking).
 *   2. hero-3d.js itself is <script type="module" defer> so it never blocks parsing.
 *   3. Placeholder gradient div is visible instantly.
 *   4. GLB fetch begins only after DOMContentLoaded.
 *   5. Canvas reveals on first render frame (no flash of empty canvas).
 *
 * Frame-rate cap: ambient idle animation is capped at 30 fps via timestamp delta.
 * IntersectionObserver: RAF loop pauses when hero is scrolled off-screen.
 */

import * as THREE from './vendor/three.module.min.js';
import { GLTFLoader } from './vendor/GLTFLoader.js';
import { getDeviceTier } from './tier-detection.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const FRAME_INTERVAL_MS = 1000 / 30;   // 30 fps cap
const ROTATION_SPEED    = 0.004;        // radians per frame at 30fps
const PARALLAX_SCALE    = 0.08;         // how far parallax displaces the camera (Tier A)
const PARALLAX_SMOOTH   = 0.05;         // lerp factor for smooth parallax response

// Brand gradient colours (same as tokens.css)
const BRAND_BLUE   = new THREE.Color(0x5B8DEF);
const BRAND_VIOLET = new THREE.Color(0x9B6BF0);

// ─── Hero scene bootstrap ─────────────────────────────────────────────────────

let renderer, scene, camera, model, rafId;
let targetRotY = 0, currentRotY = 0;
let targetParallaxX = 0, targetParallaxY = 0;
let currentParallaxX = 0, currentParallaxY = 0;
let lastFrameTime = 0;
let heroVisible = true;

/**
 * Entry point — called on DOMContentLoaded.
 * @param {HTMLElement} viewport  The hero viewport container element
 */
export async function initHeroScene(viewport) {
  const { tier } = getDeviceTier();

  // Tier C: replace placeholder with static SVG, done.
  if (tier === 'C') {
    renderStaticFallback(viewport);
    return;
  }

  // Tier A/B: set up renderer + scene, then load glTF asynchronously
  setupRenderer(viewport);
  setupScene(tier);
  setupCamera(viewport);
  setupLights(tier);

  // Start RAF immediately so the placeholder → canvas swap is smooth
  startLoop();

  // Load glTF in parallel (deferred — critical content is already interactive)
  const glbPath = tier === 'A' ? 'logo-hi.glb' : 'logo-lo.glb';
  // Use the script's directory as the base path
  const scriptBase = new URL(import.meta.url).pathname.replace(/[^/]+$/, '');
  const glbUrl = scriptBase + glbPath;

  try {
    await loadModel(glbUrl, tier);
    // Model loaded — hide placeholder, show canvas
    viewport.classList.remove('hero-3d-placeholder');
    const placeholder = viewport.querySelector('.hero-3d-placeholder');
    if (placeholder) {
      placeholder.remove();
    }
    renderer.domElement.style.opacity = '1';
  } catch (err) {
    // GLB load failed — degrade to static fallback without breaking the page
    console.warn('[softXchange 3D] glTF load failed, falling back to Tier C:', err.message);
    cleanupRenderer();
    renderStaticFallback(viewport);
    return;
  }

  // Set up input handlers for parallax (Tier A only)
  if (tier === 'A') {
    setupParallax(viewport);
  }

  // Pause RAF when hero is off-screen (save GPU/battery)
  const io = new IntersectionObserver(([entry]) => {
    heroVisible = entry.isIntersecting;
    if (heroVisible && !rafId) startLoop();
  }, { threshold: 0.05 });
  io.observe(viewport);

  // Responsive canvas resize
  const ro = new ResizeObserver(() => resizeRenderer(viewport));
  ro.observe(viewport);
}

// ─── Three.js Setup ───────────────────────────────────────────────────────────

function setupRenderer(viewport) {
  renderer = new THREE.WebGLRenderer({
    antialias: true,
    alpha: true,
    powerPreference: 'low-power',
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.1;
  renderer.outputColorSpace = THREE.SRGBColorSpace;

  const canvas = renderer.domElement;
  canvas.style.cssText = `
    position: absolute; inset: 0; width: 100%; height: 100%;
    opacity: 1;
    border-radius: var(--radius-lg);
    z-index: 1;
    pointer-events: none;
  `;
  viewport.style.position = 'relative';
  viewport.appendChild(canvas);

  resizeRenderer(viewport);
}

function setupScene(tier) {
  scene = new THREE.Scene();
  // Subtle environment gradient fog — matches brand dark palette
  scene.background = null;   // transparent — CSS background shows through

  if (tier === 'A') {
    // Add a very subtle environment for reflections
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    pmremGenerator.compileEquirectangularShader();
    // Simple neutral environment (no HDR file needed — procedural gradient)
    const envScene = buildGradientEnvScene();
    scene.environment = pmremGenerator.fromScene(envScene).texture;
    pmremGenerator.dispose();
  }
}

function setupCamera(viewport) {
  const w = viewport.clientWidth  || 400;
  const h = viewport.clientHeight || 400;
  camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 100);
  camera.position.set(0, 0, 4.5);
}

function setupLights(tier) {
  // Ambient — keeps shadow areas from going fully black
  const ambient = new THREE.AmbientLight(0x1a1b2e, 1.8);
  scene.add(ambient);

  // Key light — cool blue-shifted, from upper-left
  const key = new THREE.DirectionalLight(0x8baeff, tier === 'A' ? 2.6 : 1.8);
  key.position.set(-2, 3, 4);
  scene.add(key);

  // Fill light — warm violet, from lower-right
  const fill = new THREE.DirectionalLight(0xb07cff, tier === 'A' ? 1.4 : 0.8);
  fill.position.set(3, -1, 2);
  scene.add(fill);

  // Soft luminous backlight positioned directly behind the model
  // Provides the bright backdrop required for glass transmission/refraction to glow
  const backGlow = new THREE.PointLight(0x7e7bf5, tier === 'A' ? 5.0 : 3.0, 10, 1.2);
  backGlow.position.set(0, 0, -1.6);
  scene.add(backGlow);

  if (tier === 'A') {
    // Back rim light — sharp blue edge rim
    const rim = new THREE.DirectionalLight(0x5B8DEF, 1.2);
    rim.position.set(0, -2, -3);
    scene.add(rim);

    // Radial backdrop aura behind the 3D model for transmission refraction
    const auraCanvas = document.createElement('canvas');
    auraCanvas.width = auraCanvas.height = 256;
    const ctx = auraCanvas.getContext('2d');
    const radGrad = ctx.createRadialGradient(128, 128, 10, 128, 128, 128);
    radGrad.addColorStop(0, 'rgba(120, 140, 255, 0.45)');
    radGrad.addColorStop(0.5, 'rgba(155, 107, 240, 0.25)');
    radGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
    ctx.fillStyle = radGrad;
    ctx.fillRect(0, 0, 256, 256);

    const auraTex = new THREE.CanvasTexture(auraCanvas);
    const auraMat = new THREE.MeshBasicMaterial({
      map: auraTex,
      transparent: true,
      opacity: 0.85,
      depthWrite: false,
    });
    const auraPlane = new THREE.Mesh(new THREE.PlaneGeometry(3.6, 2.8), auraMat);
    auraPlane.position.set(0, 0, -1.2);
    scene.add(auraPlane);
  }
}

function resizeRenderer(viewport) {
  const w = viewport.clientWidth  || 400;
  const h = viewport.clientHeight || 400;
  if (renderer) renderer.setSize(w, h, false);
  if (camera) {
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
}

// ─── glTF Model Loading ───────────────────────────────────────────────────────

function loadModel(url, tier) {
  return new Promise((resolve, reject) => {
    const loader = new GLTFLoader();
    loader.load(
      url,
      (gltf) => {
        model = gltf.scene;
        // Re-apply PBR material so we're not dependent on what the glTF bakes in
        applyBrandMaterial(model, tier);
        // Centre the model
        const box = new THREE.Box3().setFromObject(model);
        const centre = box.getCenter(new THREE.Vector3());
        model.position.sub(centre);
        // Scale to consistent viewport size
        const size = box.getSize(new THREE.Vector3());
        const maxDim = Math.max(size.x, size.y, size.z);
        const scale = 1.8 / maxDim;
        model.scale.setScalar(scale);

        // Initial resting angle so 3D depth, bevels, and glass sheen are immediately visible
        model.rotation.y = 0.32;
        model.rotation.x = 0.12;
        currentRotY = 0.32;

        scene.add(model);
        resolve(model);
      },
      undefined,
      reject
    );
  });
}

function applyBrandMaterial(object, tier) {
  object.traverse((child) => {
    if (!child.isMesh) return;

    if (tier === 'A') {
      child.material = new THREE.MeshPhysicalMaterial({
        vertexColors: true,     // Uses baked brand gradient (Blue #5B8DEF -> Violet #9B6BF0)
        color: 0xffffff,        // Pure white base to preserve 100% vertex color vibrancy
        emissive: 0x221844,     // Subtle violet night glow
        emissiveIntensity: 0.25,
        metalness: 0.05,
        roughness: 0.10,        // High-gloss finish
        transmission: 0.78,     // Refractive frosted glass
        thickness: 0.55,
        ior: 1.48,              // Refraction index like crown glass
        transparent: true,
        opacity: 0.94,
        side: THREE.DoubleSide,
        envMapIntensity: 1.5,
      });
    } else {
      // Tier B — solid gradient material with vertex colors
      child.material = new THREE.MeshStandardMaterial({
        vertexColors: true,
        color: 0xffffff,
        emissive: 0x1a1235,
        emissiveIntensity: 0.15,
        metalness: 0.10,
        roughness: 0.25,
        transparent: true,
        opacity: 0.96,
        side: THREE.DoubleSide,
      });
    }
  });
}

// ─── Procedural Environment Scene ────────────────────────────────────────────

function buildGradientEnvScene() {
  // A simple RoomEnvironment-style dark scene with coloured lights
  // used only for reflections — never rendered directly
  const envScene = new THREE.Scene();
  envScene.background = new THREE.Color(0x0e0f1a);

  const lights = [
    { color: 0x5B8DEF, intensity: 4, pos: [5, 5, 5] },
    { color: 0x9B6BF0, intensity: 3, pos: [-5, 3, -5] },
    { color: 0x8baeff, intensity: 2, pos: [0, -5, 0] },
  ];
  lights.forEach(({ color, intensity, pos }) => {
    const l = new THREE.PointLight(color, intensity, 20);
    l.position.set(...pos);
    envScene.add(l);
  });

  return envScene;
}

// ─── Input Handlers (Tier A parallax) ────────────────────────────────────────

function setupParallax(viewport) {
  // Desktop: pointer move over the hero viewport
  viewport.addEventListener('pointermove', (e) => {
    const rect = viewport.getBoundingClientRect();
    const nx   = (e.clientX - rect.left)  / rect.width  - 0.5;   // [-0.5, 0.5]
    const ny   = (e.clientY - rect.top)   / rect.height - 0.5;
    targetParallaxX = nx * PARALLAX_SCALE;
    targetParallaxY = -ny * PARALLAX_SCALE;
    targetRotY = nx * Math.PI * 0.12;
  }, { passive: true });

  viewport.addEventListener('pointerleave', () => {
    targetParallaxX = 0;
    targetParallaxY = 0;
    targetRotY = 0;
  }, { passive: true });

  // Mobile/tablet: device orientation (gyroscope)
  if (typeof DeviceOrientationEvent !== 'undefined') {
    const handler = (e) => {
      if (e.beta == null || e.gamma == null) return;
      // gamma: left-right tilt [-90, 90]; beta: front-back tilt [-180, 180]
      const gNorm = Math.max(-45, Math.min(45, e.gamma)) / 45;   // [-1, 1]
      const bNorm = Math.max(-30, Math.min(30, e.beta - 45)) / 30;
      targetParallaxX = gNorm * PARALLAX_SCALE;
      targetParallaxY = -bNorm * PARALLAX_SCALE;
      targetRotY = gNorm * Math.PI * 0.08;
    };

    // DeviceOrientationEvent.requestPermission (iOS 13+)
    if (typeof DeviceOrientationEvent.requestPermission === 'function') {
      // Must be triggered by a user gesture — we attach to the first touch on viewport
      viewport.addEventListener('touchstart', async () => {
        try {
          const perm = await DeviceOrientationEvent.requestPermission();
          if (perm === 'granted') window.addEventListener('deviceorientation', handler);
        } catch (_) {}
      }, { once: true, passive: true });
    } else {
      window.addEventListener('deviceorientation', handler, { passive: true });
    }
  }
}

// ─── Render Loop ──────────────────────────────────────────────────────────────

function startLoop() {
  lastFrameTime = performance.now();
  rafId = requestAnimationFrame(renderLoop);
}

function renderLoop(now) {
  if (!heroVisible) {
    rafId = null;
    return;
  }

  rafId = requestAnimationFrame(renderLoop);

  // 30 fps cap
  const delta = now - lastFrameTime;
  if (delta < FRAME_INTERVAL_MS) return;
  lastFrameTime = now - (delta % FRAME_INTERVAL_MS);

  // Ambient rotation
  if (model) {
    currentRotY += (targetRotY + currentRotY * 0) - currentRotY;  // snap target for rotation
    model.rotation.y += ROTATION_SPEED;
    // Clamp so auto-rotation and parallax don't fight
    if (targetRotY !== 0) {
      model.rotation.y += (targetRotY - model.rotation.y) * PARALLAX_SMOOTH * 0.5;
    }
  }

  // Smooth parallax camera offset
  currentParallaxX += (targetParallaxX - currentParallaxX) * PARALLAX_SMOOTH;
  currentParallaxY += (targetParallaxY - currentParallaxY) * PARALLAX_SMOOTH;
  if (camera) {
    camera.position.x = currentParallaxX;
    camera.position.y = currentParallaxY;
    camera.lookAt(0, 0, 0);
  }

  if (renderer && scene && camera) {
    renderer.render(scene, camera);
  }
}

function cleanupRenderer() {
  if (rafId) cancelAnimationFrame(rafId);
  if (renderer) {
    renderer.dispose();
    renderer.domElement.remove();
    renderer = null;
  }
  scene = camera = model = rafId = null;
}

// ─── Tier C Static Fallback ───────────────────────────────────────────────────

function renderStaticFallback(viewport) {
  // Preserve hero-scanner-card if present
  const card = viewport.querySelector('#hero-scanner-card');
  const fallbackDiv = document.createElement('div');
  fallbackDiv.style.cssText = `
    width: 100%; height: 100%;
    display: flex; align-items: center; justify-content: center;
    background: radial-gradient(ellipse at 55% 45%, rgba(91,141,239,0.18) 0%, rgba(155,107,240,0.10) 65%, transparent 100%);
    border-radius: var(--radius-lg);
    border: 1px solid var(--color-border);
  `;
  fallbackDiv.innerHTML = `
    <svg viewBox="0 0 120 120" width="140" height="140" fill="none"
         aria-label="softXchange logo — 3D view unavailable" role="img">
      <defs>
        <linearGradient id="fg-grad-static" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stop-color="#5B8DEF" stop-opacity="0.95"/>
          <stop offset="100%" stop-color="#9B6BF0" stop-opacity="0.95"/>
        </linearGradient>
        <filter id="fg-glow">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur"/>
          <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
      </defs>
      <!-- Left arrow prism (flat) -->
      <polygon points="12,24  60,60  12,96"  fill="url(#fg-grad-static)" opacity="0.9" filter="url(#fg-glow)"/>
      <!-- Right arrow prism (flat) -->
      <polygon points="108,24  60,60  108,96" fill="url(#fg-grad-static)" opacity="0.9" filter="url(#fg-glow)"/>
      <!-- Centre bridge -->
      <circle cx="60" cy="60" r="4" fill="white" opacity="0.6"/>
    </svg>
  `;
  viewport.replaceChildren(fallbackDiv);
  if (card) viewport.appendChild(card);
  viewport.classList.remove('hero-3d-placeholder');
}
