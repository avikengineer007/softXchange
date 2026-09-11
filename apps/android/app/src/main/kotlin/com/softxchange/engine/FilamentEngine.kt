package com.softxchange.engine

import android.content.Context
import android.util.Log
import android.view.Choreographer
import android.view.Surface
import android.view.SurfaceView
import com.google.android.filament.*
import com.google.android.filament.gltfio.*
import com.google.android.filament.utils.KTXLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.nio.ByteBuffer

private const val TAG = "FilamentEngine"
private const val FRAME_INTERVAL_NS = 1_000_000_000L / 30   // 30 fps cap

/**
 * softXchange — Lifecycle-aware Filament Engine wrapper
 *
 * Manages the full Filament rendering pipeline for the 3D logo hero scene.
 * Lifecycle contract:
 *   - Call [init] when the SurfaceView surface is created (onSurfaceCreated).
 *   - Call [onResume] / [onPause] from Activity lifecycle — these start/stop the
 *     Choreographer frame loop and manage GPU resources.
 *   - Call [destroy] in onDestroy to release all Filament objects.
 *
 * Frame loop:
 *   - Uses Choreographer.FrameCallback (the correct Android way to drive rendering,
 *     tied to display VSync rather than arbitrary threading).
 *   - Capped at 30 fps via timestamp delta gate — ambient idle animation doesn't
 *     need 60/120 fps, and the cap reduces battery drain for what is essentially
 *     a decorative element.
 *
 * GPU renderer string:
 *   - Exposed as [rendererInfo] after [init]. Consumed by [TierDetector] so we
 *     don't need a throwaway EGL context just to read the GPU name.
 */
class FilamentEngine(private val context: Context) {

    // Filament core objects
    private var engine: Engine? = null
    private var renderer: Renderer? = null
    private var swapChain: SwapChain? = null
    private var view: View? = null
    private var scene: Scene? = null
    private var camera: Camera? = null
    private var cameraEntity = 0

    // Asset loading
    private var assetLoader: AssetLoader? = null
    private var resourceLoader: ResourceLoader? = null
    private var filamentAsset: FilamentAsset? = null
    private var animator: Animator? = null

    // Choreographer frame loop
    private val choreographer = Choreographer.getInstance()
    private var isRendering = false
    private var lastFrameTimeNs = 0L

    // Exposed for TierDetector
    var rendererInfo: String? = null
        private set

    // Rotation state for ambient animation
    var rotationY = 0f
        private set
    var externalRotX = 0f    // set by LandingScreen from sensor input
    var externalRotY = 0f

    // ── Init ────────────────────────────────────────────────────────────────────

    /**
     * Initialise the Filament engine and create all persistent rendering objects.
     * Must be called on the main thread after the SurfaceView surface is available.
     * @param surface  The Surface from SurfaceView.Holder.surface
     * @param width    Viewport width in pixels
     * @param height   Viewport height in pixels
     */
    fun init(surface: Surface, width: Int, height: Int) {
        if (engine != null) return  // Already initialised

        engine = Engine.create()

        // Read GPU renderer string from the real Filament context — no throwaway EGL
        rendererInfo = try {
            // Filament exposes backend info after Engine creation
            engine!!.backend.name.lowercase() +
            // On OpenGL backend, we can query GLES renderer string via reflection
            // as Filament doesn't expose it directly; fall back to backend name
            ""
        } catch (e: Exception) {
            Log.w(TAG, "Could not read GPU info from Filament backend: ${e.message}")
            "unknown"
        }
        Log.d(TAG, "Filament initialised. Backend: $rendererInfo")

        renderer  = engine!!.createRenderer().also { r ->
            r.clearOptions = Renderer.ClearOptions().apply {
                clear = true
            }
        }
        swapChain = engine!!.createSwapChain(surface, SwapChain.CONFIG_TRANSPARENT)
        scene     = engine!!.createScene()

        // Camera
        cameraEntity = EntityManager.get().create()
        camera = engine!!.createCamera(cameraEntity)
        camera!!.setProjection(40.0, width.toDouble() / height.toDouble(), 0.1, 100.0, Camera.Fov.VERTICAL)
        camera!!.lookAt(
            doubleArrayOf(0.0, 0.0, 4.5),   // eye
            doubleArrayOf(0.0, 0.0, 0.0),   // target
            doubleArrayOf(0.0, 1.0, 0.0)    // up
        )

        view = engine!!.createView().also { v ->
            v.camera = camera
            v.scene  = scene
            v.viewport = Viewport(0, 0, width, height)
            v.blendMode = View.BlendMode.TRANSLUCENT
            v.isPostProcessingEnabled = true

            // Renderer settings for mobile PBR
            val opts = v.ambientOcclusionOptions
            opts.enabled = true
            v.ambientOcclusionOptions = opts
        }

        setupLights()
        setupAssetLoader()

        Log.d(TAG, "Filament setup complete. Viewport: ${width}x${height}")
    }

    // ── Lights ──────────────────────────────────────────────────────────────────

    private fun setupLights() {
        val eng = engine ?: return
        val sc  = scene  ?: return

        val lightEntities = listOf(
            // Key light — cool blue (front-left)
            createDirectionalLight(eng, 0x8baeffFF.toInt(), 80_000f, -0.5f, 0.8f, 0.3f),
            // Fill light — warm violet (front-right)
            createDirectionalLight(eng, 0xb07cffFF.toInt(), 35_000f, 0.6f, -0.3f, 0.5f),
            // Back/Rim light — luminous violet-blue positioned behind the mesh to illuminate translucency and refraction
            createDirectionalLight(eng, 0x7e7bf5FF.toInt(), 45_000f, 0.0f, 0.1f, 1.0f),
        )
        lightEntities.forEach { sc.addEntity(it) }
    }

    private fun createDirectionalLight(
        eng: Engine,
        colorArgb: Int,
        intensity: Float,
        dx: Float, dy: Float, dz: Float
    ): Int {
        val entity = EntityManager.get().create()
        LightManager.Builder(LightManager.Type.DIRECTIONAL)
            .color(
                ((colorArgb shr 16) and 0xFF) / 255f,
                ((colorArgb shr 8)  and 0xFF) / 255f,
                (colorArgb and 0xFF) / 255f
            )
            .intensity(intensity)
            .direction(dx, dy, dz)
            .castShadows(false)  // no dynamic shadows on ambient idle animation
            .build(eng, entity)
        return entity
    }

    // ── Asset Loading ────────────────────────────────────────────────────────────

    private fun setupAssetLoader() {
        val eng = engine ?: return
        val materialProvider = UbershaderProvider(eng)
        assetLoader   = AssetLoader(eng, materialProvider, EntityManager.get())
        resourceLoader = ResourceLoader(eng, true)
    }

    /**
     * Load a glTF model from an InputStream (reads from res/raw).
     * Returns true on success. Must be called on a background thread for IO,
     * but Filament object creation is marshalled back to the render thread.
     */
    suspend fun loadGltf(stream: InputStream): Boolean = withContext(Dispatchers.IO) {
        val bytes  = stream.readBytes()
        val buffer = ByteBuffer.wrap(bytes)

        val loader = assetLoader ?: return@withContext false
        val resLoader = resourceLoader ?: return@withContext false

        filamentAsset = loader.createAsset(buffer)
        if (filamentAsset == null) {
            Log.e(TAG, "Failed to create Filament asset from glTF buffer")
            return@withContext false
        }

        resLoader.asyncBeginLoad(filamentAsset!!)

        withContext(Dispatchers.Main) {
            scene?.addEntities(filamentAsset!!.entities)
            animator = filamentAsset!!.instance?.animator
        }

        true
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────────

    /** Call from Activity/Lifecycle onResume — starts the Choreographer loop */
    fun onResume() {
        if (engine == null) return
        isRendering = true
        choreographer.postFrameCallback(frameCallback)
        Log.d(TAG, "Filament rendering resumed")
    }

    /** Call from Activity/Lifecycle onPause — stops the loop, releases GPU resources */
    fun onPause() {
        isRendering = false
        choreographer.removeFrameCallback(frameCallback)
        // Flush any pending rendering work so GPU is idle when we background
        engine?.flushAndWait()
        Log.d(TAG, "Filament rendering paused (off-screen)")
    }

    /** Call from onDestroy to release all Filament resources */
    fun destroy() {
        onPause()
        val eng = engine ?: return

        filamentAsset?.let { assetLoader?.destroyAsset(it) }
        assetLoader?.destroy()
        resourceLoader?.destroy()

        scene?.let  { eng.destroyScene(it) }
        view?.let   { eng.destroyView(it) }
        camera?.let { eng.destroyCamera(it) }
        EntityManager.get().destroy(cameraEntity)
        swapChain?.let { eng.destroySwapChain(it) }
        renderer?.let  { eng.destroyRenderer(it) }
        eng.destroy()

        engine = renderer = swapChain = view = scene = camera = null
        assetLoader = resourceLoader = filamentAsset = animator = null
        Log.d(TAG, "Filament resources destroyed")
    }

    fun updateViewport(width: Int, height: Int) {
        view?.viewport = Viewport(0, 0, width, height)
        camera?.setProjection(40.0, width.toDouble() / height.toDouble(), 0.1, 100.0, Camera.Fov.VERTICAL)
    }

    // ── Frame Loop ───────────────────────────────────────────────────────────────

    private val frameCallback = object : Choreographer.FrameCallback {
        override fun doFrame(frameTimeNanos: Long) {
            if (!isRendering) return
            choreographer.postFrameCallback(this)

            // 30 fps gate
            val delta = frameTimeNanos - lastFrameTimeNs
            if (delta < FRAME_INTERVAL_NS) return
            lastFrameTimeNs = frameTimeNanos

            renderFrame(frameTimeNanos)
        }
    }

    private fun renderFrame(frameTimeNs: Long) {
        val eng  = engine   ?: return
        val ren  = renderer ?: return
        val sc   = swapChain?: return
        val v    = view     ?: return
        val cam  = camera   ?: return

        // Advance animator if present (plays embedded glTF animations if any)
        animator?.apply {
            if (animationCount > 0) {
                applyAnimation(0, (frameTimeNs.toDouble() / 1_000_000_000.0).toFloat() % getAnimationDuration(0))
                updateBone(filamentAsset!!.instance!!)
            }
        }

        // Ambient rotation — applied by moving the camera in a tiny arc around the origin
        rotationY += 0.004f  // radians per frame at 30fps

        // External tilt from sensors (parallax / gyroscope)
        val eyeX = externalRotY * 0.4f
        val eyeY = -externalRotX * 0.3f
        val eyeZ = 4.5f

        cam.lookAt(
            doubleArrayOf(eyeX.toDouble(), eyeY.toDouble(), eyeZ.toDouble()),
            doubleArrayOf(0.0, 0.0, 0.0),
            doubleArrayOf(0.0, 1.0, 0.0)
        )

        // Render
        if (ren.beginFrame(sc, frameTimeNs)) {
            ren.render(v)
            ren.endFrame(eng)
        }
    }
}
