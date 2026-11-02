package dev.vardevall.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.vardevall.model.Device
import dev.vardevall.model.DeviceRoute
import dev.vardevall.model.PathView
import dev.vardevall.model.rttText

/** A NAT on the line: a tick, in the secondary colour when it cannot be punched. */
data class Tick(val punchable: Boolean)

/** What a path line shows about one device, from the node's own view. */
data class PathLineModel(val shape: Shape, val rtt: Int?, val name: String) {
    sealed interface Shape {
        data object Idle : Shape

        data object Connecting : Shape

        data object Local : Shape

        data class Internet(val thisTick: Tick?, val peerTick: Tick?) : Shape

        /** Through a server of the cloud; [name] is "Switch" or "Relay". */
        data class Helper(val name: String) : Shape
    }

    val rttText: String? get() = rtt?.let(::rttText)

    /** "Phone: direct through the internet, 12 ms". */
    val summary: String
        get() {
            var parts = when (shape) {
                Shape.Idle -> "not connected"
                Shape.Connecting -> "connecting"
                Shape.Local -> "direct on the local network"
                is Shape.Internet -> {
                    val limited = listOfNotNull(shape.thisTick, shape.peerTick).any { !it.punchable }
                    "direct through the internet" + if (limited) ", a NAT that cannot be punched" else ""
                }
                is Shape.Helper -> "through a ${shape.name.lowercase()}, metered"
            }
            rttText?.let { parts += ", $it" }
            return "$name: $parts"
        }

    companion object {
        fun of(device: Device): PathLineModel {
            val shape = when (val route = device.route) {
                DeviceRoute.Idle -> Shape.Idle
                DeviceRoute.Connecting -> Shape.Connecting
                is DeviceRoute.Direct -> if (route.onLan) Shape.Local else Shape.Internet(thisTick(device), peerTick(device))
                is DeviceRoute.Helper -> Shape.Helper(if (route.kind == "switch") "Switch" else "Relay")
            }
            return PathLineModel(shape, device.paths?.rtt, device.name)
        }

        /** This node's NAT in the family of the route, or the better of the two when the route has no address. */
        private fun thisTick(device: Device): Tick? {
            val local = device.local ?: return null
            val addr = device.paths?.route?.addr
            val nat: PathView.Nat = if (addr != null) {
                if (addr.startsWith("[")) local.ipv6 else local.ipv4
            } else {
                listOf(local.ipv4, local.ipv6).firstOrNull { it.nat == "punchable" } ?: local.ipv4
            }
            return if (nat.nat == "unknown") null else Tick(nat.nat == "punchable")
        }

        private fun peerTick(device: Device): Tick? = when (device.paths?.nat) {
            "punchable" -> Tick(true)
            "relay_only" -> Tick(false)
            else -> null
        }
    }
}

enum class LineSize(val circle: Dp, val tick: Dp, val width: Dp) {
    Compact(28.dp, 10.dp, 2.dp),
    Regular(34.dp, 12.dp, 2.dp),
    Large(44.dp, 16.dp, 2.5.dp),
}

/** The colour of a device's route. */
@Composable
fun DeviceRoute.color(): Color = when (this) {
    is DeviceRoute.Direct -> MaterialTheme.colorScheme.primary
    is DeviceRoute.Helper -> helperColor
    DeviceRoute.Connecting, DeviceRoute.Idle -> MaterialTheme.colorScheme.outline
}

/**
 * This node, one line and the device, at the height of the end circles. The line says how the
 * device is reached: straight on the local network, through the internet past the NATs (a cloud
 * in the line, the RTT inside it, and a tick per NAT), or through a switch or a relay of the cloud
 * (warm and dashed, the cloud, then its name and the RTT).
 */
@Composable
fun PathLine(device: Device, modifier: Modifier = Modifier, size: LineSize = LineSize.Regular) {
    val model = PathLineModel.of(device)
    val color = device.route.color()
    val ticks = (model.shape as? PathLineModel.Shape.Internet)?.let { it.thisTick to it.peerTick } ?: (null to null)
    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(size.circle)
            .testTag("pathline")
            .semantics(mergeDescendants = true) { contentDescription = model.summary },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Endpoint("You", size)
        Segment(color, ticks.first, 0.35f, size, dashed(model.shape), Modifier.weight(1f))
        Label(model, color, size)
        Segment(color, ticks.second, 0.65f, size, dashed(model.shape), Modifier.weight(1f))
        Endpoint(device.initial, size)
    }
}

private fun dashed(shape: PathLineModel.Shape) = when (shape) {
    PathLineModel.Shape.Local, is PathLineModel.Shape.Internet -> false
    else -> true
}

@Composable
private fun Endpoint(text: String, size: LineSize) {
    Box(
        Modifier
            .size(size.circle)
            .clip(CircleShape)
            .border(1.5.dp, MaterialTheme.colorScheme.outline, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, fontSize = if (size == LineSize.Compact) 10.sp else 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

/** Half of the line, with a NAT's tick at [at] of its width. */
@Composable
private fun Segment(color: Color, tick: Tick?, at: Float, size: LineSize, dashed: Boolean, modifier: Modifier) {
    val tickOff = MaterialTheme.colorScheme.outline
    Canvas(modifier.height(size.circle).widthIn(min = 12.dp)) {
        val y = this.size.height / 2
        val stroke = Stroke(
            width = size.width.toPx(),
            cap = StrokeCap.Round,
            pathEffect = if (dashed) PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 4.dp.toPx())) else null,
        )
        drawLine(color, Offset(0f, y), Offset(this.size.width, y), stroke.width, StrokeCap.Round, stroke.pathEffect)
        if (tick != null) {
            val x = this.size.width * at
            val half = size.tick.toPx() / 2
            drawLine(if (tick.punchable) color else tickOff, Offset(x, y - half), Offset(x, y + half), stroke.width + 0.5.dp.toPx(), StrokeCap.Round)
        }
    }
}

/** The way and the RTT, on the line: "Local · 3 ms"; a cloud with the RTT inside; or an empty cloud and "Relay · 40 ms". */
@Composable
private fun Label(model: PathLineModel, color: Color, size: LineSize) {
    val joined = { text: String -> model.rttText?.let { "$text · $it" } ?: text }
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    when (val shape = model.shape) {
        PathLineModel.Shape.Idle -> LineText("Not connected", quiet, size)
        PathLineModel.Shape.Connecting -> LineText("Connecting", quiet, size)
        PathLineModel.Shape.Local -> LineText(joined("Local"), color, size)
        is PathLineModel.Shape.Internet -> Cloud(model.rttText, color, size)
        is PathLineModel.Shape.Helper -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
            Cloud(null, color, size)
            LineText(joined(shape.name), color, size)
        }
    }
}

@Composable
private fun LineText(text: String, color: Color, size: LineSize) {
    Text(
        text,
        color = color,
        fontSize = if (size == LineSize.Large) 13.sp else 12.sp,
        fontWeight = FontWeight.Medium,
        maxLines = 1,
        modifier = Modifier.padding(horizontal = 6.dp),
    )
}

/** The internet, with the RTT inside if there is one. */
@Composable
private fun Cloud(rtt: String?, color: Color, size: LineSize) {
    Box(Modifier.padding(horizontal = 2.dp), contentAlignment = Alignment.Center) {
        Icon(Icons.Outlined.Cloud, contentDescription = null, tint = color, modifier = Modifier.size(size.circle * 1.3f))
        if (rtt != null) {
            Text(rtt, color = color, fontSize = (size.circle.value * 0.24f).sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = size.circle * 0.1f))
        }
    }
}
