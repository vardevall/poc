package dev.vardevall.ui

import android.os.SystemClock
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.vardevall.NetworkDraft
import dev.vardevall.model.ConfigSummary
import dev.vardevall.model.Device
import dev.vardevall.model.PathView
import dev.vardevall.model.TunnelState
import dev.vardevall.model.formatBytes
import dev.vardevall.model.rttText
import kotlinx.coroutines.delay

/** The time left until [end] at [now], both in milliseconds of one clock: "12 s", "3 min", or null once it has passed. */
fun timeLeft(end: Long, now: Long): String? {
    val seconds = Math.ceil((end - now) / 1000.0).toLong()
    if (seconds <= 0) return null
    return if (seconds < 90) "$seconds s" else "${(seconds + 30) / 60} min"
}

/** A text with the time left until [ms] after [since], counted down each second: [text] gets "12 s" or null once it has passed. */
@Composable
fun countdown(ms: Long, since: Long, text: (String?) -> String): String {
    val now by produceState(SystemClock.elapsedRealtime()) {
        while (true) {
            delay(1000)
            value = SystemClock.elapsedRealtime()
        }
    }
    return text(timeLeft(since + ms, now))
}

/** A titled group of rows in a card, with an optional footnote under it. */
@Composable
fun Section(title: String?, modifier: Modifier = Modifier, footer: String? = null, content: @Composable () -> Unit) {
    Column(modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        if (title != null) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(start = 8.dp, bottom = 6.dp),
            )
        }
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            shape = MaterialTheme.shapes.extraLarge,
        ) {
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) { content() }
        }
        if (footer != null) {
            Text(
                footer,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 8.dp, top = 6.dp, end = 8.dp),
            )
        }
    }
}

/** A row of a card, padded. */
@Composable
fun Row16(modifier: Modifier = Modifier, onClick: (() -> Unit)? = null, content: @Composable () -> Unit) {
    val base = if (onClick != null) modifier.fillMaxWidth().clickable(onClick = onClick) else modifier.fillMaxWidth()
    Column(base.padding(horizontal = 16.dp, vertical = 10.dp)) { content() }
}

@Composable
fun EmptyRow(text: String) {
    Row16 { Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant) }
}

@Composable
fun Divider() = HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)

/** A label with its value on the right. */
@Composable
fun Labeled(label: String, value: String, mono: Boolean = false) {
    Row16 {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Text(label, modifier = Modifier.width(120.dp))
            SelectionContainer(Modifier.weight(1f)) {
                Text(
                    value,
                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = if (mono) FontFamily.Monospace else null,
                    fontSize = if (mono) 12.sp else 14.sp,
                    overflow = TextOverflow.MiddleEllipsis,
                    maxLines = if (mono) 2 else 4,
                )
            }
        }
    }
}

@Composable
fun Mono(text: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurfaceVariant, size: Int = 12) {
    SelectionContainer {
        Text(text, modifier, color = color, fontFamily = FontFamily.Monospace, fontSize = size.sp)
    }
}

/** A device with its network and the line to it. */
@Composable
fun DeviceRow(device: Device, showNetwork: Boolean, onClick: () -> Unit) {
    Row16(onClick = onClick) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(device.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (showNetwork) {
                Surface(shape = CircleShape, color = MaterialTheme.colorScheme.secondaryContainer) {
                    Text(
                        device.network,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
                    )
                }
            }
        }
        Spacer(Modifier.size(6.dp))
        PathLine(device)
    }
}

/** A device as a network lists it: a dot in the colour of its route, its name and the RTT. */
@Composable
fun DeviceDotRow(name: String, device: Device?, onClick: () -> Unit) {
    Row16(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = device?.route?.color() ?: MaterialTheme.colorScheme.outline, modifier = Modifier.size(10.dp)) {}
            Spacer(Modifier.width(12.dp))
            Text(name, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            val rtt = device?.paths?.rtt
            if (rtt != null) Text(rttText(rtt), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * A switch of a network with where its registration stands and, while it is disconnected, when it
 * is tried again. Without a live entry it is the switch of the file.
 */
@Composable
fun SwitchRow(address: String, auth: String?, live: TunnelState.SwitchState?, network: TunnelState.NetworkState?) {
    val viewed = network?.view?.local?.switches?.firstOrNull { it.address == address }
    val color = when (live?.state) {
        "registered" -> MaterialTheme.colorScheme.primary
        "disconnected" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row16 {
        Mono(address, color = MaterialTheme.colorScheme.onSurface)
        val retry = viewed?.retryIn
        val text = when {
            live != null && live.state == "disconnected" && retry != null && network.viewAt != null -> {
                val base = describeSwitch(live, auth ?: viewed.auth, null)
                countdown(retry, network.viewAt) { left -> left?.let { "$base · tried again in $it" } ?: "$base · trying again" }
            }
            live != null -> describeSwitch(live, auth ?: viewed?.auth, viewed?.transport)
            else -> if (auth == "web") "web address" else "pinned"
        }
        Text(text, style = MaterialTheme.typography.bodySmall, color = color)
    }
}

private fun describeSwitch(entry: TunnelState.SwitchState, auth: String?, transport: String?): String {
    val prefix = auth?.let { "$it · " } ?: ""
    val reason = entry.reason ?: return prefix + (transport?.let { "${entry.state} over ${it.uppercase()}" } ?: entry.state)
    return prefix + "${entry.state} (${reason.replace('_', ' ')})"
}

/** The relay the engine reports for a network. */
@Composable
fun RelayRow(relay: PathView.Relay, inUse: Boolean) {
    Row16 {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Mono(relay.server, color = MaterialTheme.colorScheme.onSurface)
            Text(
                if (inUse) "In use" else "Ready",
                style = MaterialTheme.typography.labelMedium,
                color = if (inUse) helperColor else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text("${relay.addr} · ${relay.transport.uppercase()}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** The bytes carried by a transport and, for a switch or TURN server, the volume it still lets through. */
@Composable
fun TransportRow(transport: PathView.Transport) {
    Row16 {
        Text(transport.title, style = MaterialTheme.typography.bodyMedium)
        Text(transport.meter.summaryText(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        transport.budget?.let { budget ->
            val color = when (budget.level) {
                "plenty" -> MaterialTheme.colorScheme.primary
                "half" -> MaterialTheme.colorScheme.onSurfaceVariant
                "low" -> helperColor
                else -> MaterialTheme.colorScheme.error
            }
            LinearProgressIndicator(
                progress = { (budget.remaining.toDouble() / maxOf(budget.total.toDouble(), 1.0)).toFloat() },
                color = color,
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
            )
            val total = formatBytes(budget.total)
            val text = if (budget.level == "exhausted") {
                "Used up ($total): carries nothing until renewed"
            } else {
                "${formatBytes(budget.remaining)} of $total left" + if (transport.usable) "" else ", not usable"
            }
            Text(text, style = MaterialTheme.typography.bodySmall, color = color, fontWeight = FontWeight.Medium)
        }
    }
}

private fun PathView.Meter.summaryText() = "↑ ${formatBytes(sent)}  ↓ ${formatBytes(received)}"

/** The text under a network's name in a list: the domain, the devices online. */
fun networkDetail(network: NetworkDraft, live: TunnelState.NetworkState?): String? {
    val parts = mutableListOf<String>()
    network.summary?.domain?.let(parts::add)
    if (live != null) {
        val online = live.peers.count { it.isUp }
        parts += "$online ${if (online == 1) "device" else "devices"} online"
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(" · ")
}

/** Whether the summary says anything about the services the network announces. */
fun ConfigSummary.servicesText(): String = services.joinToString("\n") { "${it.name}  ${it.port}/${it.proto}" }
