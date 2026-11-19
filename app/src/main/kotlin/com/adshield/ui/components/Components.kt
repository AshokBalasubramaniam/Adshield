package com.adshield.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.adshield.ui.theme.Palette
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.NumberFormat

fun formatCount(n: Long): String = NumberFormat.getIntegerInstance().format(n)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(title, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "Back") }
                    }
                },
                actions = { actions() },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                ),
            )
        },
        content = content,
    )
}

@Composable
fun Panel(modifier: Modifier = Modifier, onClick: (() -> Unit)? = null, content: @Composable () -> Unit) {
    val shape = RoundedCornerShape(20.dp)
    val base = modifier.fillMaxWidth().clip(shape)
    Surface(
        modifier = if (onClick != null) base.clickable(onClick = onClick) else base,
        shape = shape,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
    ) {
        Box(Modifier.padding(16.dp)) { content() }
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(start = 4.dp, top = 12.dp, bottom = 2.dp),
    )
}

@Composable
fun StatTile(label: String, value: Long, modifier: Modifier = Modifier, accent: Color = Palette.TextPrimary) {
    val animated by animateIntAsState(value.coerceIn(0, Int.MAX_VALUE.toLong()).toInt(), tween(600), label = "stat")
    Surface(modifier = modifier, shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surface) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(formatCount(animated.toLong()), style = MaterialTheme.typography.headlineMedium, color = accent)
        }
    }
}

@Composable
fun InfoRow(label: String, value: String, modifier: Modifier = Modifier, valueColor: Color = MaterialTheme.colorScheme.onSurface) {
    Row(modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(16.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = valueColor, modifier = Modifier.weight(1f, fill = false), maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
fun SwitchRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    enabled: Boolean = true,
) {
    Row(
        modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, role = Role.Switch) { onCheckedChange(!checked) }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(
            checked = checked, onCheckedChange = onCheckedChange, enabled = enabled,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Palette.OnTeal, checkedTrackColor = Palette.Teal,
                uncheckedThumbColor = Palette.TextSecondary, uncheckedTrackColor = Palette.SurfaceHigh, uncheckedBorderColor = Palette.Outline,
            ),
        )
    }
}

@Composable
fun Pill(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier.clip(CircleShape).background(color.copy(alpha = 0.16f)).padding(horizontal = 10.dp, vertical = 4.dp),
    ) { Text(text, style = MaterialTheme.typography.labelMedium, color = color) }
}

@Composable
fun IconBadge(icon: ImageVector, tint: Color = Palette.Teal, size: Dp = 40.dp) {
    Box(Modifier.size(size).clip(CircleShape).background(tint.copy(alpha = 0.14f)), contentAlignment = Alignment.Center) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
    }
}

@Composable
fun BodyText(text: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurfaceVariant) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = color, modifier = modifier)
}

@Composable
fun AppIcon(packageName: String, size: Dp = 40.dp) {
    val context = LocalContext.current
    val bitmap by produceState<ImageBitmap?>(null, packageName) {
        value = withContext(Dispatchers.IO) {
            runCatching { context.packageManager.getApplicationIcon(packageName).toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    val bmp = bitmap
    if (bmp != null) {
        Image(bmp, contentDescription = null, modifier = Modifier.size(size).clip(RoundedCornerShape(10.dp)))
    } else {
        Box(Modifier.size(size).clip(RoundedCornerShape(10.dp)).background(MaterialTheme.colorScheme.surfaceVariant))
    }
}

enum class PowerVisual { OFF, STARTING, ON, ERROR }

/**
 * The one-tap control. Its look is derived purely from the real protection state: it only shows the "ON"
 * visual when the VPN service reports that packet processing is live.
 */
@Composable
fun PowerButton(visual: PowerVisual, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val ring by animateColorAsState(
        when (visual) {
            PowerVisual.ON -> Palette.Teal
            PowerVisual.STARTING -> Palette.Warning
            PowerVisual.ERROR -> Palette.Danger
            PowerVisual.OFF -> Palette.Outline
        },
        tween(400), label = "ring",
    )
    val core by animateColorAsState(if (visual == PowerVisual.ON) Palette.Teal.copy(alpha = 0.14f) else Palette.Surface, tween(400), label = "core")
    val transition = rememberInfiniteTransition(label = "power")
    val pulse by transition.animateFloat(0f, 1f, infiniteRepeatable(tween(2200, easing = LinearEasing), RepeatMode.Restart), label = "pulse")
    val spin by transition.animateFloat(0f, 360f, infiniteRepeatable(tween(1100, easing = LinearEasing), RepeatMode.Restart), label = "spin")
    val label = when (visual) {
        PowerVisual.ON -> "Protection is on. Tap to turn off."
        PowerVisual.STARTING -> "Starting protection"
        PowerVisual.ERROR -> "Protection failed. Tap to try again."
        PowerVisual.OFF -> "Protection is off. Tap to turn on."
    }
    Box(
        modifier
            .size(220.dp)
            .semantics { contentDescription = label; role = Role.Button; stateDescription = visual.name }
            .clip(CircleShape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 6.dp.toPx()
            val inset = 18.dp.toPx()
            if (visual == PowerVisual.ON) {
                val r = size.minDimension / 2
                drawCircle(Palette.Teal.copy(alpha = 0.18f * (1f - pulse)), radius = r * (0.78f + 0.22f * pulse))
            }
            drawCircle(core, radius = size.minDimension / 2 - inset)
            if (visual == PowerVisual.STARTING) {
                drawArc(ring, spin, 100f, false, Offset(inset, inset), Size(size.width - 2 * inset, size.height - 2 * inset), style = Stroke(stroke, cap = StrokeCap.Round))
            } else {
                drawCircle(ring, radius = size.minDimension / 2 - inset, style = Stroke(stroke))
            }
        }
        Icon(
            Icons.Rounded.PowerSettingsNew, contentDescription = null,
            tint = if (visual == PowerVisual.OFF) Palette.TextSecondary else ring,
            modifier = Modifier.size(72.dp).alpha(if (visual == PowerVisual.STARTING) 0.7f else 1f),
        )
    }
}
