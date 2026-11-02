package dev.vardevall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.vardevall.model.PathView
import dev.vardevall.model.TunnelState
import dev.vardevall.model.devices

/**
 * How each network reaches the devices: this device's NATs and engine, the switches that find
 * them, the relay for when a direct path is not possible, and the traffic of each transport.
 */
@Composable
fun ConnectivityScreen(state: TunnelState?, onLog: () -> Unit) {
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
        if (state == null) {
            Section(null) { EmptyRow("Connect to see how your devices are reached.") }
            return
        }
        val many = state.networks.size > 1
        fun title(name: String, part: String) = if (many) "$name · $part" else part
        for (network in state.networks) {
            Section(title(network.name, "This device")) {
                Labeled("Engine", network.engine.replaceFirstChar { it.uppercase() })
                network.view?.local?.let { local ->
                    Natrow("NAT, IPv4", local.ipv4)
                    Natrow("NAT, IPv6", local.ipv6)
                }
            }
            Section(title(network.name, "Switches"), footer = "A switch helps your devices find each other.") {
                if (network.switches.isEmpty()) EmptyRow("None configured.")
                network.switches.forEachIndexed { i, entry ->
                    if (i > 0) Divider()
                    SwitchRow(entry.address, entry.auth, entry, network)
                }
            }
            Section(title(network.name, "Relay"), footer = "A relay is used only when two devices cannot connect directly.") {
                val relay = network.view?.local?.relay
                if (relay != null) {
                    RelayRow(relay, inUse = state.devices.any { it.network == network.name && it.paths?.route?.kind == "own_relay" })
                } else {
                    EmptyRow("None.")
                }
            }
            Section(title(network.name, "Traffic")) {
                val transports = network.view?.local?.transports.orEmpty()
                if (transports.isEmpty()) EmptyRow("None yet.")
                transports.forEachIndexed { i, transport ->
                    if (i > 0) Divider()
                    TransportRow(transport)
                }
            }
        }
        Section(null) {
            Row16(onClick = onLog) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("Log", Modifier.weight(1f))
                    Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun Natrow(title: String, nat: PathView.Nat) {
    Row16 {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            Text(title, Modifier.weight(1f))
            Column(horizontalAlignment = Alignment.End) {
                Text(nat.word, color = MaterialTheme.colorScheme.onSurfaceVariant)
                nat.addr?.let { Mono(it) }
            }
        }
    }
}

/** The recent lines of each engine's log, and of the tunnel's own. */
@Composable
fun LogScreen(state: TunnelState?) {
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
        if (state == null) {
            Section(null) { EmptyRow("Connect to see the log.") }
            return
        }
        val count = state.networks.size
        for (network in state.networks) {
            Section(if (count > 1) "Log · ${network.name}" else "Log") {
                Row16 { Mono(state.lines(network.name, withTunnel = count == 1).takeLast(LOG_SHOWN).joinToString("\n"), size = 11) }
            }
        }
        if (count > 1) {
            Section("Log · tunnel") {
                Row16 { Mono(state.tunnelLines().takeLast(LOG_SHOWN).joinToString("\n"), size = 11) }
            }
        }
    }
}

private const val LOG_SHOWN = 40
