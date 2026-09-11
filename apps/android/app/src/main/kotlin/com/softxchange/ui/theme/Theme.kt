package com.softxchange.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ── Brand Colours (matching packages/tokens.css) ─────────────────────────────

val BgApp             = Color(0xFF12131C)
val BgSurface         = Color(0xFF1B1C29)
val BgSurfaceElevated = Color(0xFF222334)
val ColorBorder       = Color(0xFF2A2B3B)

val TextPrimary   = Color(0xFFF2F1F7)
val TextSecondary = Color(0xFF8B899E)
val TextMuted     = Color(0xFF6B6980)

val AccentBlue   = Color(0xFF5B8DEF)
val AccentViolet = Color(0xFF9B6BF0)
val BadgeGreen   = Color(0xFF4ADE80)
val ColorDanger  = Color(0xFFF87171)
val ColorWarning = Color(0xFFFBBF24)

// ── Typography ────────────────────────────────────────────────────────────────
// Note: Custom fonts (Space Grotesk, JetBrains Mono) would be added to
// res/font/ in a production build. Using system defaults here for correctness.

val SoftXchangeTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 30.sp,
        letterSpacing = (-0.5).sp,
        color = TextPrimary
    ),
    headlineMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        color = TextPrimary
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        color = TextSecondary
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        color = TextSecondary
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        color = TextMuted
    )
)

// ── Material3 Dark Colour Scheme ─────────────────────────────────────────────

val SoftXchangeColorScheme = darkColorScheme(
    primary         = AccentBlue,
    secondary       = AccentViolet,
    background      = BgApp,
    surface         = BgSurface,
    surfaceVariant  = BgSurfaceElevated,
    onPrimary       = TextPrimary,
    onBackground    = TextPrimary,
    onSurface       = TextPrimary,
    outline         = ColorBorder,
    error           = ColorDanger
)

// ── Theme Composable ─────────────────────────────────────────────────────────

@Composable
fun SoftXchangeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SoftXchangeColorScheme,
        typography  = SoftXchangeTypography,
        content     = content
    )
}
