package dev.vardevall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.vardevall.NetworkDraft
import dev.vardevall.model.DeviceId
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.TunnelState
import dev.vardevall.model.device
import dev.vardevall.model.devices
import dev.vardevall.model.note

/** The networks, and a way to add one. */
@Composable
fun NetworksScreen(
    networks: List<NetworkDraft>,
    state: TunnelState?,
    onNetwork: (String) -> Unit,
) {
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 96.dp)) {
        Section(null, footer = "Each network is separate: devices in one cannot see the others.") {
            if (networks.isEmpty()) EmptyRow("No networks yet.")
            networks.forEachIndexed { i, network ->
                if (i > 0) Divider()
                NetworkRow(network, state?.network(network.name), onClick = { onNetwork(network.name) })
            }
        }
    }
}

/** A network of the list: its domain, the devices online and the exit it offers. */
@Composable
private fun NetworkRow(network: NetworkDraft, live: TunnelState.NetworkState?, onClick: () -> Unit) {
    Row16(onClick = onClick) {
        Text(network.name, style = MaterialTheme.typography.titleMedium)
        networkDetail(network, live)?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        val sites = live?.view?.sites.orEmpty()
        if (sites.isNotEmpty()) {
            Text(
                "Exit · " + sites.joinToString(", ") { ExitChoice(network.name, it.site).note() },
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

/** One network: what its interface file says, its devices, switches and relay. */
@Composable
fun NetworkScreen(
    network: NetworkDraft,
    state: TunnelState?,
    failure: String?,
    onDevice: (DeviceId) -> Unit,
    onEdit: () -> Unit,
    onRemove: () -> Unit,
) {
    var confirming by remember { mutableStateOf(false) }
    val live = state?.network(network.name)
    val summary = network.summary
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
        Section("This network", footer = "These are set in the text of the network; use Edit to change them.") {
            Labeled("Name", network.name)
            if (summary != null) {
                Labeled("Domain", summary.domain)
                Labeled("Overlay address", summary.addrs.ula, mono = true)
                Labeled("Public key", summary.publicKey, mono = true)
                if (summary.listenPort != 0) Labeled("Port", summary.listenPort.toString())
                Labeled("Find devices on my Wi-Fi", if (summary.mdns) "On" else "Off")
                if (summary.stunServers > 0) Labeled("STUN servers", summary.stunServers.toString())
                if (summary.services.isNotEmpty()) Labeled("Services", summary.servicesText())
            } else {
                Row16 { Text("The text of the network is not valid; use Edit to fix it.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
        }
        Section("Devices") {
            if (summary != null) {
                Labeled("This device", summary.publicKey, mono = true)
                summary.peers.forEach { peer ->
                    Divider()
                    val id = DeviceId(network.name, peer.publicKey)
                    DeviceDotRow(peer.name ?: peer.addr, state?.device(id)) { onDevice(id) }
                }
                if (summary.peers.isEmpty()) EmptyRow("No other devices in the text.")
            } else {
                EmptyRow("The text of the network is not valid.")
            }
        }
        Section("Switches") {
            val configured = summary?.switches.orEmpty()
            if (configured.isEmpty()) EmptyRow("None configured.")
            configured.forEachIndexed { i, switch ->
                if (i > 0) Divider()
                SwitchRow(switch.address, switch.auth, live?.switches?.firstOrNull { it.address == switch.address }, live)
            }
        }
        Section("Relays", footer = "A relay is used only when two devices cannot connect directly.") {
            val relay = live?.view?.local?.relay
            if (relay != null) {
                RelayRow(relay, inUse = state.devices.any { it.network == network.name && it.paths?.route?.kind == "own_relay" })
            } else {
                EmptyRow(if (state == null) "Set up once connected." else "None.")
            }
        }
        Section(null, footer = failure) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                OutlinedButton(onClick = onEdit) { Text("Edit") }
                TextButton(onClick = { confirming = true }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            }
        }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Remove ${network.name}?") },
            text = { Text("Its keys are deleted from this device.") },
            confirmButton = {
                TextButton(onClick = { confirming = false; onRemove() }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}
