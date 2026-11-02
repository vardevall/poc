package dev.vardevall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.vardevall.model.DeviceId
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.TunnelState
import dev.vardevall.model.devices
import dev.vardevall.model.exitOptions
import dev.vardevall.model.helperData
import dev.vardevall.model.note
import dev.vardevall.model.onlineSummary
import dev.vardevall.model.relayInUse
import dev.vardevall.model.switchesOnline
import dev.vardevall.vpn.TunnelHost

/** Everything the overview needs, gathered by the app. */
data class OverviewModel(
    val status: TunnelHost.Status,
    val state: TunnelState?,
    val networkNames: List<String>,
    val exit: ExitChoice?,
    val message: String?,
    val privateDnsStrict: Boolean,
)

/** The connection, the exit, the servers and the devices of every network. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun OverviewScreen(
    model: OverviewModel,
    onConnect: (Boolean) -> Unit,
    onExit: (ExitChoice?) -> Unit,
    onServers: () -> Unit,
    onDevice: (DeviceId) -> Unit,
) {
    val state = model.state
    Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 16.dp)) {
        ConnectCard(model, onConnect)
        if (model.privateDnsStrict && model.status is TunnelHost.Status.Connected) {
            Section(null) {
                Row16 {
                    Text("Private DNS is set to a host name", fontWeight = FontWeight.Medium)
                    Text(
                        "Android then sends names past the VPN, so names of your devices do not resolve. Set Private DNS to Automatic or Off in Settings, Network and internet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        state?.helperData?.let { data ->
            Section(null, footer = "Direct connections use none of it.") {
                Row16 {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Helper data")
                        Text(data.text, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    LinearProgressIndicator(
                        progress = { (data.remaining.toDouble() / maxOf(data.total.toDouble(), 1.0)).toFloat() },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    )
                }
            }
        }
        ExitSection(model, onExit)
        Section(null) {
            Row16(onClick = onServers) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("Servers", Modifier.weight(1f))
                    if (state?.relayInUse == true) {
                        Text("Relay in use  ·  ", color = helperColor)
                    }
                    Text(serversValue(state), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Section("Devices") {
            val devices = state?.devices.orEmpty()
            if (devices.isEmpty()) EmptyRow(if (state == null) "Connect to see your devices." else "None yet.")
            devices.forEachIndexed { i, device ->
                if (i > 0) Divider()
                DeviceRow(device, showNetwork = true) { onDevice(device.id) }
            }
        }
    }
}

private fun serversValue(state: TunnelState?): String {
    if (state == null) return "Not connected"
    val (online, total) = state.switchesOnline
    return if (total == 0) "None" else "$online of $total online"
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun ConnectCard(model: OverviewModel, onConnect: (Boolean) -> Unit) {
    val on = model.status is TunnelHost.Status.Connected || model.status is TunnelHost.Status.Connecting
    val title = when (model.status) {
        TunnelHost.Status.Connected -> "Connected"
        TunnelHost.Status.Connecting -> "Connecting"
        else -> "Not connected"
    }
    val subtitle = when {
        model.state != null && model.status is TunnelHost.Status.Connected -> model.state.onlineSummary
        model.networkNames.isEmpty() -> "Add a network to start"
        else -> "Turn on to reach your devices"
    }
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(
            containerColor = if (on) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh,
            contentColor = if (on) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
        ),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.headlineMedium)
                    Text(subtitle, style = MaterialTheme.typography.bodyMedium)
                }
                if (model.status is TunnelHost.Status.Connecting) {
                    LoadingIndicator(Modifier.padding(end = 12.dp))
                }
                Switch(checked = on, onCheckedChange = onConnect, enabled = model.networkNames.isNotEmpty() || on)
            }
            val failure = (model.status as? TunnelHost.Status.Failed)?.message ?: model.message
            if (failure != null) {
                Text(
                    failure,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (model.status is TunnelHost.Status.Failed) MaterialTheme.colorScheme.error else LocalContentColor.current,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }
    }
}

/** "Send my internet through": Overlay only, or the exit of a network. */
@Composable
private fun ExitSection(model: OverviewModel, onExit: (ExitChoice?) -> Unit) {
    val options = exitOptions(model.networkNames, model.state, model.exit)
    Section(
        "Send my internet through",
        footer = exitText(model) ?: "Your normal internet connection is not changed.",
    ) {
        ExitOption("Overlay only", "Only traffic between your devices uses vardevall", model.exit == null, model.networkNames.isNotEmpty()) { onExit(null) }
        options.forEach { option ->
            Divider()
            ExitOption(option.network, option.note(), model.exit == option, true) { onExit(option) }
        }
    }
}

@Composable
private fun ExitOption(title: String, note: String, selected: Boolean, enabled: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onSelect)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null, enabled = enabled)
        Column(Modifier.padding(start = 16.dp)) {
            Text(title)
            Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** The exit and what stands behind it, for the status. */
private fun exitText(model: OverviewModel): String? {
    val exit = model.exit ?: return null
    val name = exit.site?.let { "${exit.network} · $it" } ?: exit.network
    if (model.status !is TunnelHost.Status.Connected) return "Exit $name, used once connected"
    val used = model.state?.exit
    if (used == null || used.network != exit.network) return "Exit $name, starting"
    val via = used.via ?: return "Exit $name: none is live, traffic is dropped"
    val shown = used.site?.let { "${exit.network} · $it" } ?: exit.network
    return "Exit $shown via $via"
}
