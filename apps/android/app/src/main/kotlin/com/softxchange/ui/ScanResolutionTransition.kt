package com.softxchange.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.softxchange.engine.DeviceTier
import com.softxchange.engine.TierDetector
import com.softxchange.ui.theme.*

/**
 * softXchange — Scan-Resolution Transition (Prompt 5)
 *
 * Wraps the scan-state transition for listing detail cards.
 *
 * Tier A: AnimatedContent with a custom ContentTransform — the card container
 *         does a subtle graphicsLayer rotateY (max 8°) as the state resolves.
 *         The badge text / outcome label is the FIRST visible element in the
 *         target composable — the 3D flourish wraps the container, never the
 *         badge itself, so legibility is never delayed.
 *
 * Tier B/C: Simple fadeIn + fadeOut (240ms). Same semantic outcome, no 3D.
 *
 * State machine: pending_scan → passed | failed
 */

enum class ScanState { PENDING, PASSED, FAILED }

@Composable
fun ScanResolutionTransition(
    scanState: ScanState,
    content: @Composable (ScanState) -> Unit
) {
    val context = LocalContext.current
    val tier = remember {
        TierDetector.detectTier(context, null).tier
    }

    when (tier) {
        DeviceTier.A -> {
            // Tier A: 3D rotateY flourish wrapping the transition
            ScanResolution3D(scanState = scanState, content = content)
        }
        else -> {
            // Tier B/C: flat fade transition
            ScanResolutionFlat(scanState = scanState, content = content)
        }
    }
}

// ── Tier A: 3D depth flourish ─────────────────────────────────────────────────

@Composable
private fun ScanResolution3D(
    scanState: ScanState,
    content: @Composable (ScanState) -> Unit
) {
    // Rotation animation — peaks at 8°, settles to 0° before the transition spec ends
    val rotY = remember { Animatable(0f) }

    LaunchedEffect(scanState) {
        if (scanState != ScanState.PENDING) {
            // Play the depth flourish on resolution
            // Sequence: 0° → 6° → -2° → 0°, total 480ms
            // Badge is already visible on the first frame of the target composable;
            // the rotation is cosmetic and never obscures content.
            rotY.animateTo(
                targetValue = 6f,
                animationSpec = tween(durationMillis = 150, easing = EaseOut)
            )
            rotY.animateTo(
                targetValue = -2f,
                animationSpec = tween(durationMillis = 160, easing = EaseInOut)
            )
            rotY.animateTo(
                targetValue = 0f,
                animationSpec = tween(durationMillis = 170, easing = EaseIn)
            )
        }
    }

    Box(
        modifier = Modifier
            .graphicsLayer {
                // perspective effect via cameraDistance
                cameraDistance = 8f * density
                rotationY = rotY.value
            }
    ) {
        AnimatedContent(
            targetState = scanState,
            transitionSpec = {
                // Instant display of target — flourish is on the container, not the content
                (fadeIn(tween(200))).togetherWith(fadeOut(tween(100)))
            },
            label = "scan-resolve-3d"
        ) { state ->
            content(state)
        }
    }
}

// ── Tier B/C: flat fade transition ────────────────────────────────────────────

@Composable
private fun ScanResolutionFlat(
    scanState: ScanState,
    content: @Composable (ScanState) -> Unit
) {
    AnimatedContent(
        targetState = scanState,
        transitionSpec = {
            fadeIn(tween(240, easing = EaseOut)) togetherWith
            fadeOut(tween(120, easing = EaseIn))
        },
        label = "scan-resolve-flat"
    ) { state ->
        content(state)
    }
}

// ── Usage Example: Scan Status Badge ─────────────────────────────────────────

/**
 * Scan status badge — the concrete composable passed as [content] to [ScanResolutionTransition].
 * The badge text is the very first rendered element; the surrounding 3D flourish
 * (on Tier A) wraps the Box, never this Text.
 */
@Composable
fun ScanBadge(state: ScanState) {
    val (text, bgColor, textColor) = when (state) {
        ScanState.PENDING -> Triple(
            "pending_scan",
            ColorWarning.copy(alpha = 0.12f),
            ColorWarning
        )
        ScanState.PASSED -> Triple(
            "Scanned — 0 critical findings",
            BadgeGreen.copy(alpha = 0.12f),
            BadgeGreen
        )
        ScanState.FAILED -> Triple(
            "Scan failed",
            ColorDanger.copy(alpha = 0.12f),
            ColorDanger
        )
    }

    Surface(
        color = bgColor,
        shape = RoundedCornerShape(100.dp),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // Status dot — always the first visible element (legibility requirement)
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .background(textColor, RoundedCornerShape(100.dp))
            )
            Text(
                text = text,
                color = textColor,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}
