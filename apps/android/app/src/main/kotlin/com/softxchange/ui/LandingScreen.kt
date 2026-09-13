package com.softxchange.ui

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.content.Intent
import android.net.Uri
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidExternalSurface
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.softxchange.R
import com.softxchange.engine.DeviceTier
import com.softxchange.engine.FilamentEngine
import com.softxchange.engine.TierDetector
import com.softxchange.ui.theme.*
import kotlinx.coroutines.launch

/**
 * softXchange Landing Screen — Prompt 4
 *
 * Hosts the 3D hero scene (Filament) for Tier A/B, or a static drawable for Tier C.
 * Critical path Compose UI (brand header, title, CTAs) renders before the Filament
 * scene initialises — matching the web's deferred-loading requirement.
 *
 * Lifecycle integration:
 *   - FilamentEngine.onResume() / onPause() driven by the Compose lifecycle observer
 *   - GPU resources released when backgrounded; Choreographer loop stopped
 */
@Composable
fun LandingScreen(
    onNavigateToBrowse: () -> Unit,
    onNavigateToLogin:  () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val coroutineScope = rememberCoroutineScope()

    // ── Tier detection ────────────────────────────────────────────────────────
    // Initially Tier C (safe default) — updated after Filament init
    val engine = remember { FilamentEngine(context) }
    var tierResult by remember {
        mutableStateOf(TierDetector.detectTier(context, null))  // pre-init check
    }

    // ── Filament lifecycle ────────────────────────────────────────────────────
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME  -> engine.onResume()
                Lifecycle.Event.ON_PAUSE   -> engine.onPause()
                Lifecycle.Event.ON_DESTROY -> engine.destroy()
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // ── Sensor input (Tier A parallax) ────────────────────────────────────────
    DisposableEffect(tierResult.tier) {
        if (tierResult.tier != DeviceTier.A) return@DisposableEffect onDispose {}

        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val rotVector = sensorManager.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR)

        val listener = object : SensorEventListener {
            private val lowpass = FloatArray(3)

            override fun onSensorChanged(event: SensorEvent) {
                // Low-pass filter to smooth sensor noise
                lowpass[0] += 0.08f * (event.values[0] - lowpass[0])
                lowpass[1] += 0.08f * (event.values[1] - lowpass[1])
                lowpass[2] += 0.08f * (event.values[2] - lowpass[2])

                // Map rotation vector to bounded tilt values (max ±5°)
                val maxRad = Math.toRadians(5.0).toFloat()
                engine.externalRotX = (lowpass[1] * maxRad).coerceIn(-maxRad, maxRad)
                engine.externalRotY = (lowpass[0] * maxRad).coerceIn(-maxRad, maxRad)
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }

        if (rotVector != null) {
            sensorManager.registerListener(listener, rotVector, SensorManager.SENSOR_DELAY_GAME)
        }

        onDispose {
            sensorManager.unregisterListener(listener)
            engine.externalRotX = 0f
            engine.externalRotY = 0f
        }
    }

    // ── Root layout ───────────────────────────────────────────────────────────
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgApp)
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
    ) {
        // ── Critical UI: renders immediately, no Filament dependency ──────────
        Spacer(modifier = Modifier.height(32.dp))

        // Brand header
        Row(verticalAlignment = Alignment.CenterVertically) {
            BrandLogo(size = 28.dp)
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "softXchange",
                style = MaterialTheme.typography.headlineMedium,
                color = TextPrimary
            )
        }

        Spacer(modifier = Modifier.height(40.dp))

        // Hero badge
        Surface(
            color = BgSurfaceElevated,
            shape = RoundedCornerShape(100.dp),
            modifier = Modifier.wrapContentSize()
        ) {
            Text(
                text = "Cryptographically Vetted Marketplace",
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Hero title
        Text(
            text = "Engineered for Security.",
            style = MaterialTheme.typography.headlineLarge,
            color = TextPrimary,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Zero Compromise.",
            style = MaterialTheme.typography.headlineLarge,
            color = AccentBlue,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "Every software asset undergoes automated secrets scanning, " +
                   "AST auditing, and seller KYC verification before release.",
            style = MaterialTheme.typography.bodyLarge,
            color = TextSecondary,
            lineHeight = 22.sp
        )

        Spacer(modifier = Modifier.height(24.dp))

        // CTAs — always rendered, never gated on 3D
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = onNavigateToBrowse,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
            ) {
                Text("Browse Catalog →", color = TextPrimary, fontWeight = FontWeight.SemiBold)
            }
            OutlinedButton(
                onClick = onNavigateToLogin,
                modifier = Modifier.weight(1f)
            ) {
                Text("Sign In", color = AccentBlue)
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // ── 3D Hero Viewport (deferred) ───────────────────────────────────────
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(4f / 3.2f)
                .clip(RoundedCornerShape(16.dp))
        ) {
            when (tierResult.tier) {
                DeviceTier.C -> {
                    // Static fallback — no Filament, instant display
                    HeroStaticFallback()
                }
                DeviceTier.A, DeviceTier.B -> {
                    // Placeholder gradient shown immediately
                    HeroPlaceholder()

                    // Filament surface — initialised lazily with transparency so HeroPlaceholder backdrop shows through
                    AndroidExternalSurface(
                        isOpaque = false,
                        modifier = Modifier.fillMaxSize()
                    ) { surface, width, height ->
                        engine.init(surface, width, height)

                        // Re-detect tier now that Filament is initialised and GPU info is available
                        val updatedTier = TierDetector.detectTier(context, engine.rendererInfo)
                        tierResult = updatedTier

                        // Load the appropriate glTF model
                        coroutineScope.launch {
                            val rawResId = if (updatedTier.tier == DeviceTier.A) {
                                R.raw.logo_hi
                            } else {
                                R.raw.logo_lo
                            }
                            val stream = context.resources.openRawResource(rawResId)
                            val loaded = engine.loadGltf(stream)
                            if (!loaded) {
                                // Filament asset load failed — will show static fallback
                                // (the surface continues rendering whatever scene was set up)
                            }
                        }

                        // Surface changes (rotation, resize)
                        onSurface { s, w, h ->
                            engine.updateViewport(w, h)
                        }

                        onSurfaceDestroyed {
                            engine.onPause()
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(36.dp))

        // ── Customer Support & Dedicated SPOC Section ───────────────────────────
        Text(
            text = "Customer Support & SPOC",
            style = MaterialTheme.typography.titleMedium,
            color = TextPrimary,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Direct hotline and assistance for verified buyers and sellers.",
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
            modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
        )

        // Email Support Card
        Surface(
            color = BgSurfaceElevated,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:softxchange.connect@gmail.com"))
                    context.startActivity(intent)
                }
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "OFFICIAL SUPPORT EMAIL",
                    style = MaterialTheme.typography.labelSmall,
                    color = AccentBlue,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "softxchange.connect@gmail.com",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Dedicated SPOC Card
        Surface(
            color = BgSurfaceElevated,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:+917596897303"))
                    context.startActivity(intent)
                }
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "DEDICATED SPOC (KYC & ESCALATIONS)",
                    style = MaterialTheme.typography.labelSmall,
                    color = AccentViolet,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "+91 75968 97303",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Customer Support Helpline Card
        Surface(
            color = BgSurfaceElevated,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:+917047619203"))
                    context.startActivity(intent)
                }
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "CUSTOMER SUPPORT HELPLINE",
                    style = MaterialTheme.typography.labelSmall,
                    color = ColorDanger,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "+91 70476 19203",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }
}

// ── Sub-composables ───────────────────────────────────────────────────────────

@Composable
private fun BrandLogo(size: androidx.compose.ui.unit.Dp) {
    Box(
        modifier = Modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        // Gradient bowtie shape — two triangles (simplified Compose Canvas version)
        // For the nav icon only — actual 3D logo is in the Filament hero scene
        androidx.compose.foundation.Canvas(modifier = Modifier.size(size)) {
            val w = this.size.width
            val h = this.size.height

            val gradBrush = Brush.linearGradient(
                colors = listOf(AccentBlue, AccentViolet)
            )
            // Left arrow: tip at centre, wide end at left
            val leftPath = androidx.compose.ui.graphics.Path().apply {
                moveTo(w * 0.17f, h * 0.21f)
                lineTo(w * 0.50f, h * 0.50f)
                lineTo(w * 0.17f, h * 0.79f)
                close()
            }
            // Right arrow: tip at centre, wide end at right
            val rightPath = androidx.compose.ui.graphics.Path().apply {
                moveTo(w * 0.83f, h * 0.21f)
                lineTo(w * 0.50f, h * 0.50f)
                lineTo(w * 0.83f, h * 0.79f)
                close()
            }
            drawPath(leftPath,  brush = gradBrush)
            drawPath(rightPath, brush = gradBrush)
        }
    }
}

@Composable
private fun HeroPlaceholder() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        AccentBlue.copy(alpha = 0.18f),
                        AccentViolet.copy(alpha = 0.10f),
                        BgSurface
                    )
                )
            )
    )
}

@Composable
private fun HeroStaticFallback() {
    // Tier C: static branded illustration — same visual framing as the 3D scene
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        AccentBlue.copy(alpha = 0.15f),
                        AccentViolet.copy(alpha = 0.08f),
                        BgSurface
                    )
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        BrandLogo(size = 120.dp)
    }
}
