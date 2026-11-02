package dev.vardevall.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val TealLight = lightColorScheme(
    primary = Color(0xFF00696B),
    secondary = Color(0xFF4A6364),
    tertiary = Color(0xFF9A4521),
)
private val TealDark = darkColorScheme(
    primary = Color(0xFF4CDADC),
    secondary = Color(0xFFB0CCCD),
    tertiary = Color(0xFFFFB693),
)

/** Material 3 Expressive with the wallpaper's colours where the system gives them, and the dark theme. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun VardevallTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> TealDark
        else -> TealLight
    }
    MaterialExpressiveTheme(colorScheme = scheme, motionScheme = MotionScheme.expressive(), content = content)
}

/** The colour of a helper in use (a relay or a switch): warm, apart from the primary of a direct path. */
val helperColor: Color
    @Composable get() = if (isSystemInDarkTheme()) Color(0xFFFFB86B) else Color(0xFFB45309)
