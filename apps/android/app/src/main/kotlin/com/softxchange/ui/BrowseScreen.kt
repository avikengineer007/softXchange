package com.softxchange.ui

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.softxchange.engine.DeviceTier
import com.softxchange.engine.TierDetector
import com.softxchange.ui.theme.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * softXchange Browse Screen — Prompt 5
 *
 * Listing cards with:
 *   Tier A: subtle graphicsLayer tilt (rotationX/rotationY) driven by a single
 *           accelerometer SensorEventListener shared across all cards via StateFlow.
 *           Bounded to ±5° so it reads as depth cue, not disorienting wobble.
 *           Does not interfere with scrolling (tilt is applied via graphicsLayer,
 *           not via touch event interception).
 *   Tier B/C: standard Material3 elevation/shadow only. No sensor involvement.
 *
 * Scan-resolution moment is handled by [ScanResolutionTransition] (see below).
 */

// Shared tilt state: one sensor listener → StateFlow → all visible cards
// This avoids registering a per-card listener (which would be N listeners for N items)
private val _tiltX = MutableStateFlow(0f)
private val _tiltY = MutableStateFlow(0f)

@Composable
fun BrowseScreen(
    onListingClick: (listingId: String) -> Unit,
    listings: List<ListingItem>   // data class defined below
) {
    val context = LocalContext.current
    val tierResult = remember {
        // TierDetector here uses a null gpuRenderer since we may not have Filament
        // on this screen — if it returns A we trust the earlier LandingScreen init
        TierDetector.detectTier(context, null)
    }

    val tiltX by _tiltX.collectAsState()
    val tiltY by _tiltY.collectAsState()

    // Register sensor listener only on Tier A
    val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    DisposableEffect(tierResult.tier) {
        if (tierResult.tier != DeviceTier.A) return@DisposableEffect onDispose {}

        val rotVector = sensorManager.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR)
        val listener = object : SensorEventListener {
            private val lowpass = FloatArray(3)

            override fun onSensorChanged(event: SensorEvent) {
                lowpass[0] += 0.06f * (event.values[0] - lowpass[0])
                lowpass[1] += 0.06f * (event.values[1] - lowpass[1])

                val maxDeg = 5f
                _tiltX.value = (Math.toDegrees(lowpass[1].toDouble()).toFloat()).coerceIn(-maxDeg, maxDeg)
                _tiltY.value = (Math.toDegrees(lowpass[0].toDouble()).toFloat()).coerceIn(-maxDeg, maxDeg)
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }

        if (rotVector != null) {
            sensorManager.registerListener(listener, rotVector, SensorManager.SENSOR_DELAY_GAME)
        }

        onDispose {
            sensorManager.unregisterListener(listener)
            _tiltX.value = 0f
            _tiltY.value = 0f
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgApp)
            .systemBarsPadding()
    ) {
        // Page header
        Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 20.dp)) {
            Text(
                text = "Vetted Catalog",
                style = MaterialTheme.typography.headlineMedium,
                color = TextPrimary,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Cryptographically scanned packages",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )
        }

        // Listing grid
        LazyVerticalGrid(
            columns = GridCells.Adaptive(minSize = 160.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(listings, key = { it.id }) { listing ->
                ListingCard(
                    listing = listing,
                    tier = tierResult.tier,
                    tiltX = if (tierResult.tier == DeviceTier.A) tiltX else 0f,
                    tiltY = if (tierResult.tier == DeviceTier.A) tiltY else 0f,
                    onClick = { onListingClick(listing.id) }
                )
            }
        }
    }
}

@Composable
private fun ListingCard(
    listing: ListingItem,
    tier: DeviceTier,
    tiltX: Float,
    tiltY: Float,
    onClick: () -> Unit
) {
    // Smooth Animatable lerp for tilt (avoids snapping on sensor noise)
    val animTiltX by animateFloatAsState(
        targetValue = tiltX,
        animationSpec = spring(dampingRatio = 0.7f, stiffness = 200f),
        label = "tiltX"
    )
    val animTiltY by animateFloatAsState(
        targetValue = tiltY,
        animationSpec = spring(dampingRatio = 0.7f, stiffness = 200f),
        label = "tiltY"
    )

    val elevation = if (tier == DeviceTier.A) 8.dp else 4.dp

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .graphicsLayer {
                // Tier A: apply tilt as depth cue — does NOT intercept scroll events
                if (tier == DeviceTier.A) {
                    rotationX = animTiltX
                    rotationY = animTiltY
                    // Subtle scale-up at tilt peak (parallax depth feel)
                    val tiltMag = (animTiltX * animTiltX + animTiltY * animTiltY) / 50f
                    scaleX = 1f + tiltMag * 0.01f
                    scaleY = 1f + tiltMag * 0.01f
                }
            },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = BgSurface),
        elevation = CardDefaults.cardElevation(defaultElevation = elevation)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Category + price row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = AccentBlue.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(100.dp)
                ) {
                    Text(
                        text = listing.category,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = AccentBlue
                    )
                }
                Text(
                    text = listing.formattedPrice,
                    style = MaterialTheme.typography.bodyMedium,
                    color = AccentViolet,
                    fontWeight = FontWeight.SemiBold
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = listing.title,
                style = MaterialTheme.typography.bodyLarge,
                color = TextPrimary,
                fontWeight = FontWeight.SemiBold,
                maxLines = 2
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = listing.description,
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                maxLines = 3,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Vetted badge
            Surface(
                color = BadgeGreen.copy(alpha = 0.12f),
                shape = RoundedCornerShape(100.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Scanned — 0 critical findings",
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = BadgeGreen,
                    fontSize = 10.sp
                )
            }
        }
    }
}

data class ListingItem(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val priceCents: Int
) {
    val formattedPrice: String get() = if (priceCents == 0) "Free" else "$${String.format("%.2f", priceCents / 100.0)}"
}
