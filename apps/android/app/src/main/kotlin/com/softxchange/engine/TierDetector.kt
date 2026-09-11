package com.softxchange.engine

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.provider.Settings

/**
 * softXchange Android Device Tier Detector
 *
 * Maps Android device capability to the same three-tier system as the web:
 *   Tier A — High:  Filament initialised, capable GPU, sufficient memory, animations on
 *   Tier B — Mid:   GPU detected but mid-range, or marginal memory
 *   Tier C — Low:   API level too old, accessibility remove-animations set, or post-init
 *                   GPU string unrecognised/low-end
 *
 * IMPORTANT: Call [detectTier] AFTER [FilamentEngine.init] has been called.
 * The GPU renderer string is read from Filament's own initialised context — this avoids
 * creating a separate throwaway EGL context that can leak on unusual devices.
 *
 * Accessibility note: Settings.Global.ANIMATOR_DURATION_SCALE == 0 means the user
 * has enabled "Remove animations" in Developer Options or Accessibility settings.
 * This ALWAYS forces Tier C, regardless of hardware capability — same behaviour as
 * prefers-reduced-motion on web.
 */

enum class DeviceTier { A, B, C }

data class TierResult(
    val tier: DeviceTier,
    val reason: String
)

object TierDetector {

    // Known low-end GPU substrings → Tier C
    private val GPU_TIER_C = listOf(
        "adreno (tm) 3", "adreno 3",
        "mali-t", "mali-4",
        "powervr sgx",
        "swiftshader", "mesa"
    )

    // Known mid-range GPU substrings → Tier B
    private val GPU_TIER_B = listOf(
        "adreno (tm) 4", "adreno 4",
        "adreno (tm) 5", "adreno 5",
        "mali-g5", "mali-g6",
        "mali-g7"  // lower G7x range
    )

    // Known high-end GPU substrings → Tier A
    private val GPU_TIER_A = listOf(
        "adreno (tm) 6", "adreno 6",
        "adreno (tm) 7", "adreno 7",
        "adreno (tm) 8", "adreno 8",
        "mali-g7", "mali-g8", "mali-g9",  // high G7x+
        "apple",  // for reference devices
        "xclipse"  // Samsung Xclipse (Radeon-derived)
    )

    /**
     * Detect device tier.
     *
     * @param context   Application or Activity context
     * @param gpuRenderer  GPU renderer string from Filament's initialised Engine.
     *                     Pass null if Filament hasn't initialised yet (will fall back
     *                     to Tier B for safety). Pass FilamentEngine.rendererInfo after init.
     */
    fun detectTier(context: Context, gpuRenderer: String?): TierResult {
        // 1. Accessibility: "Remove animations" always forces Tier C
        val animScale = Settings.Global.getFloat(
            context.contentResolver,
            Settings.Global.ANIMATOR_DURATION_SCALE,
            1f
        )
        if (animScale == 0f) {
            return TierResult(DeviceTier.C, "accessibility:remove-animations")
        }

        // 2. API level floor — API 26 minimum for Filament; below this is always Tier C
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return TierResult(DeviceTier.C, "api:${Build.VERSION.SDK_INT}<26")
        }

        // 3. Memory check — < 2 GB total RAM → cap at Tier B
        val actManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        actManager.getMemoryInfo(memInfo)
        val totalRamGB = memInfo.totalMem.toDouble() / (1024.0 * 1024.0 * 1024.0)
        if (totalRamGB < 2.0) {
            return TierResult(DeviceTier.B, "memory:${String.format("%.1f", totalRamGB)}GB<2")
        }

        // 4. GPU renderer string classification (from Filament's context post-init)
        if (gpuRenderer == null) {
            // Filament not yet initialised — safe middle assumption
            return TierResult(DeviceTier.B, "gpu:filament-not-initialised")
        }

        val renderer = gpuRenderer.lowercase()
        return classifyGPU(renderer)
    }

    private fun classifyGPU(renderer: String): TierResult {
        if (GPU_TIER_C.any { renderer.contains(it) }) {
            return TierResult(DeviceTier.C, "gpu:low-end:$renderer")
        }

        // Check Tier A first (more specific patterns)
        val isHighEnd = GPU_TIER_A.any { renderer.contains(it) }
        if (isHighEnd) {
            // But Mali-G7x lower tier still lands in Tier B via Tier B check
            if (GPU_TIER_B.any { renderer.contains(it) } && !renderer.contains("mali-g8") && !renderer.contains("mali-g9")) {
                return TierResult(DeviceTier.B, "gpu:mid-range:$renderer")
            }
            return TierResult(DeviceTier.A, "gpu:high-end:$renderer")
        }

        if (GPU_TIER_B.any { renderer.contains(it) }) {
            return TierResult(DeviceTier.B, "gpu:mid-range:$renderer")
        }

        // Unrecognized GPU string → Tier B (safe middle default, mirrors web behaviour)
        return TierResult(DeviceTier.B, "gpu:unrecognized[B-default]:$renderer")
    }
}
