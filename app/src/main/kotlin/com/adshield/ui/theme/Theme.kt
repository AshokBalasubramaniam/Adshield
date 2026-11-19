package com.adshield.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object Palette {
    val Charcoal = Color(0xFF14171A)
    val Surface = Color(0xFF1B1F23)
    val SurfaceHigh = Color(0xFF242A30)
    val Outline = Color(0xFF39414A)
    val TextPrimary = Color(0xFFF4F6F8)
    val TextSecondary = Color(0xFF9BA5AE)
    val Teal = Color(0xFF3CC8B4)
    val TealDim = Color(0xFF1F6B60)
    val OnTeal = Color(0xFF04201C)
    val Warning = Color(0xFFE2B35B)
    val Danger = Color(0xFFE5736B)
}

private val Scheme = darkColorScheme(
    primary = Palette.Teal,
    onPrimary = Palette.OnTeal,
    primaryContainer = Palette.TealDim,
    onPrimaryContainer = Palette.TextPrimary,
    secondary = Palette.Teal,
    onSecondary = Palette.OnTeal,
    background = Palette.Charcoal,
    onBackground = Palette.TextPrimary,
    surface = Palette.Surface,
    onSurface = Palette.TextPrimary,
    surfaceVariant = Palette.SurfaceHigh,
    onSurfaceVariant = Palette.TextSecondary,
    surfaceContainer = Palette.Surface,
    surfaceContainerHigh = Palette.SurfaceHigh,
    surfaceContainerHighest = Palette.SurfaceHigh,
    outline = Palette.Outline,
    outlineVariant = Palette.Outline,
    error = Palette.Danger,
    onError = Palette.Charcoal,
)

private val Type = Typography(
    displayLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Light, fontSize = 48.sp, letterSpacing = (-1).sp),
    headlineMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold, fontSize = 20.sp),
    titleMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 16.sp),
    bodyLarge = TextStyle(fontFamily = FontFamily.Default, fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.Default, fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.Default, fontSize = 12.sp, lineHeight = 16.sp),
    labelLarge = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 14.sp),
    labelMedium = TextStyle(fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium, fontSize = 12.sp, letterSpacing = 0.5.sp),
)

/** AdShield is a dark-only design: charcoal, neutral grays, white type and one subtle teal accent. */
@Composable
@Suppress("UNUSED_PARAMETER")
fun AdShieldTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Scheme, typography = Type, content = content)
}
