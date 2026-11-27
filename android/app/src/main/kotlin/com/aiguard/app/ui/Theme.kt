package com.aiguard.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/** 状态语义色：界面里所有「安全/危险/警告」都从这里取，深浅色各一套，保证对比度 */
@Immutable
data class StatusColors(
    val safe: Color,
    val onSafe: Color,
    val danger: Color,
    val onDanger: Color,
    val warn: Color,
    val onWarn: Color,
    val info: Color,
    val muted: Color,
    val safeContainer: Color,
    val dangerContainer: Color,
    val warnContainer: Color,
)

private val DarkStatus = StatusColors(
    safe = Color(0xFF4FD1A5), onSafe = Color(0xFF00382A),
    danger = Color(0xFFFF7A70), onDanger = Color(0xFF4A0A06),
    warn = Color(0xFFFFC15C), onWarn = Color(0xFF3F2A00),
    info = Color(0xFF8DC2FF), muted = Color(0xFF8A9A98),
    safeContainer = Color(0xFF123A30), dangerContainer = Color(0xFF4A1A17), warnContainer = Color(0xFF3D3015),
)

private val LightStatus = StatusColors(
    safe = Color(0xFF0B7A57), onSafe = Color.White,
    danger = Color(0xFFC0302A), onDanger = Color.White,
    warn = Color(0xFF8A5A00), onWarn = Color.White,
    info = Color(0xFF1F5FA8), muted = Color(0xFF5E6B69),
    safeContainer = Color(0xFFD3F2E6), dangerContainer = Color(0xFFFBDCD8), warnContainer = Color(0xFFF8E7C4),
)

val LocalStatusColors = staticCompositionLocalOf { DarkStatus }

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF4FD1A5),
    onPrimary = Color(0xFF00382A),
    primaryContainer = Color(0xFF123A30),
    onPrimaryContainer = Color(0xFFB6F2DA),
    secondary = Color(0xFF8DC2FF),
    onSecondary = Color(0xFF00315C),
    secondaryContainer = Color(0xFF1C3550),
    onSecondaryContainer = Color(0xFFD3E6FF),
    tertiary = Color(0xFFFFC15C),
    onTertiary = Color(0xFF3F2A00),
    background = Color(0xFF0C1213),
    onBackground = Color(0xFFE1E7E5),
    surface = Color(0xFF0C1213),
    onSurface = Color(0xFFE1E7E5),
    surfaceVariant = Color(0xFF1B2426),
    onSurfaceVariant = Color(0xFFB7C4C1),
    surfaceContainerLowest = Color(0xFF080D0E),
    surfaceContainerLow = Color(0xFF121A1B),
    surfaceContainer = Color(0xFF162021),
    surfaceContainerHigh = Color(0xFF1D2829),
    surfaceContainerHighest = Color(0xFF253132),
    outline = Color(0xFF5A6967),
    outlineVariant = Color(0xFF2E3A3B),
    error = Color(0xFFFF7A70),
    onError = Color(0xFF4A0A06),
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0B7A57),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD3F2E6),
    onPrimaryContainer = Color(0xFF002117),
    secondary = Color(0xFF1F5FA8),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD6E5F8),
    onSecondaryContainer = Color(0xFF001C38),
    tertiary = Color(0xFF8A5A00),
    onTertiary = Color.White,
    background = Color(0xFFF3F6F5),
    onBackground = Color(0xFF151C1B),
    surface = Color(0xFFF3F6F5),
    onSurface = Color(0xFF151C1B),
    surfaceVariant = Color(0xFFDCE5E2),
    onSurfaceVariant = Color(0xFF3F4A48),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFEDF2F0),
    surfaceContainer = Color(0xFFE7EDEB),
    surfaceContainerHigh = Color(0xFFE1E8E6),
    surfaceContainerHighest = Color(0xFFDAE2E0),
    outline = Color(0xFF6F7B79),
    outlineVariant = Color(0xFFC2CCCA),
    error = Color(0xFFC0302A),
    onError = Color.White,
)

private val base = Typography()

/** 数字与 IP 用等宽字体，刷新时不跳动 */
val MonoStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp)

private val AppTypography = base.copy(
    headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
    titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
    titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
    labelLarge = base.labelLarge.copy(fontWeight = FontWeight.SemiBold),
)

@Composable
fun AIGuardTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalStatusColors provides if (dark) DarkStatus else LightStatus) {
        MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme, typography = AppTypography, content = content)
    }
}

val status: StatusColors
    @Composable get() = LocalStatusColors.current
