package dev.vardevall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.vardevall.model.Device
import dev.vardevall.model.PathView
import dev.vardevall.model.formatBytes
import dev.vardevall.model.rttText

/** One device: what it is, how it is reached and the routes the node knows and tries. */
@Composable
fun DeviceScreen(device: Device?) {
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
        if (device == null) {
            Section(null) { EmptyRow("This device is not connected now.") }
            return
        }
        Section("Details") {
            Labeled("Network", device.network)
            Labeled("Address", device.peer.addr, mono = true)
            Labeled("Public key", device.peer.key, mono = true)
            device.paths?.meter?.let { Labeled("Sent / received", "${formatBytes(it.sent)} / ${formatBytes(it.received)}") }
        }
        Section(null) {
            Row16 { PathLine(device, size = LineSize.Large) }
        }
        Section("Routes", footer = "The paths to this peer, best first.") {
            if (device.trace.isEmpty()) EmptyRow("None while there is no session.")
            device.trace.forEachIndexed { i, route ->
                if (i > 0) Divider()
                RouteRow(device, route)
            }
        }
    }
}

/** A route of the trace: what it is, where it goes, where it stands, when a failed one is tried again, and how long a ping takes. */
@Composable
private fun RouteRow(device: Device, route: PathView.TraceRoute) {
    val switchAddress = route.switchIndex?.let { i -> device.local?.switches?.firstOrNull { it.index == i }?.address }
    Row16 {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Text(routeKind(device, route))
                Mono(route.addr ?: switchAddress ?: route.switchIndex?.let { "switch $it" } ?: "")
                val (text, color) = routeStatus(device, route)
                Text(text, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = color)
            }
            Text(route.rtt?.let(::rttText) ?: "–", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Routes name the other node the peer: "Peer's relay", and "My relay to the peer's relay" for this node's allocation sending to the peer's relay address. */
fun routeKind(device: Device, route: PathView.TraceRoute): String = when (route.kind) {
    "lan" -> "Local network"
    "internet" -> "Internet"
    "switch" -> "Switch"
    "own_relay" -> if (route.addr?.let(device::isRelay) == true) "My relay to the peer's relay" else "My relay"
    "peer_relay" -> "Peer's relay"
    else -> route.kind
}

@Composable
private fun routeStatus(device: Device, route: PathView.TraceRoute): Pair<String, Color> {
    val primary = MaterialTheme.colorScheme.primary
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    val error = MaterialTheme.colorScheme.error
    if (route.active) return "Active" to primary
    if (route.status == "failed") {
        val retry = route.retryIn
        val forget = route.forgetIn
        val since = device.viewAt
        val text = when {
            retry != null && since != null -> countdown(retry, since) { left -> left?.let { "Failed · tried again in $it" } ?: "Failed · trying again" }
            forget != null && since != null -> countdown(forget, since) { left -> left?.let { "Failed · forgotten in $it" } ?: "Failed · forgotten" }
            else -> "Failed · not tried while a better route works"
        }
        return text to error
    }
    val word = when (route.status) {
        "verified" -> "Verified"
        "candidate" -> "Trying"
        "suspect" -> "Not answering"
        else -> "Not tried"
    }
    return word to quiet
}
