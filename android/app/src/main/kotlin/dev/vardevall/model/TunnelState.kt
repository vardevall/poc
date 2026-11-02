package dev.vardevall.model

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** What the app knows of the tunnel, built from the engine's events. */
data class TunnelState(
    /** In the order of the tunnel's networks, the first being the default one. */
    val networks: List<NetworkState> = emptyList(),
    val log: List<Line> = emptyList(),
    /** Null while no exit is in use. */
    val exit: ExitState? = null,
) {
    /** A peer of a network with the link state and the route the last events gave. */
    data class PeerState(
        val key: String,
        val addr: String,
        val name: String?,
        val link: String = "idle",
        val route: String? = null,
    ) {
        /** "up via lan 192.0.2.1:1". */
        val detail: String get() = if (route != null) "$link via $route" else link
        val isUp: Boolean get() = link == "up"
    }

    /** A switch of the config and where its registration stands. */
    data class SwitchState(val address: String, val auth: String?, val state: String, val reason: String?)

    /** One network of the tunnel; the events of the engine are filed by their `network`. */
    data class NetworkState(
        val name: String,
        val engine: String = "stopped",
        val port: Int? = null,
        val switches: List<SwitchState> = emptyList(),
        val peers: List<PeerState> = emptyList(),
        /** The latest `view` event. */
        val view: PathView? = null,
        /** When the app received it, in milliseconds of the clock: the times to go in it count from then. */
        val viewAt: Long? = null,
    )

    /** A line of the log; `network` is null for the tunnel's own. */
    data class Line(val network: String?, val text: String)

    /** The exit the user chose and what stands behind it. */
    data class ExitState(
        val network: String,
        /** The site in use, once an exit is chosen. */
        val site: String?,
        /** The exit chosen, by name or key; null while the site has no live exit. */
        val via: String?,
    )

    /** What the app has to do after an event. */
    sealed interface Effect {
        /** The network reported the offers it remembers; keep them for the next run. */
        data class RememberExits(val network: String, val offersJson: String) : Effect

        /** The exit or the view changed; check what the exit in use asks of the tunnel. */
        data object RefreshExit : Effect
    }

    data class Reduced(val state: TunnelState, val effects: List<Effect> = emptyList())

    fun tunnelLines(): List<String> = log.filter { it.network == null }.map { it.text }

    /** The lines of network [name], followed by the tunnel's own when [withTunnel]. */
    fun lines(name: String, withTunnel: Boolean): List<String> =
        log.filter { it.network == name || (withTunnel && it.network == null) }.map { it.text }

    fun network(name: String): NetworkState? = networks.firstOrNull { it.name == name }

    /** A state with the networks of a tunnel that is starting. */
    fun seeded(names: List<String>) = copy(networks = names.map { NetworkState(it) }, exit = null)

    /** Adds a line of the tunnel's own to the log. */
    fun noted(text: String): TunnelState = appended(Line(null, "[tunnel] $text"))

    private fun appended(line: Line): TunnelState = copy(log = (log + line).takeLast(LOG_LINES))

    private fun updated(name: String, change: (NetworkState) -> NetworkState): TunnelState =
        copy(networks = networks.map { if (it.name == name) change(it) else it })

    /** Files an event under the network it names. [nowMs] stamps a `view`. */
    fun reduce(json: String, nowMs: Long): Reduced {
        val obj = runCatching { VvJson.parseToJsonElement(json).jsonObject }.getOrNull() ?: return Reduced(this)
        val type = obj.string("type") ?: return Reduced(this)
        val network = obj.string("network") ?: return Reduced(this)
        if (networks.none { it.name == network }) return Reduced(this)
        return when (type) {
            "status" -> Reduced(
                updated(network) {
                    it.copy(engine = obj.string("state") ?: it.engine, port = obj.int("listen_port") ?: it.port)
                },
            )
            "added", "peer", "route" -> Reduced(peerEvent(network, type, obj) ?: this)
            "removed" -> {
                val key = obj.string("key") ?: return Reduced(this)
                Reduced(updated(network) { n -> n.copy(peers = n.peers.filterNot { it.key == key }) })
            }
            "switch" -> {
                val address = obj.string("address") ?: return Reduced(this)
                val state = obj.string("state") ?: return Reduced(this)
                val entry = SwitchState(address, obj.string("auth"), state, obj.string("reason"))
                Reduced(
                    updated(network) { n ->
                        val known = n.switches.any { it.address == address }
                        n.copy(
                            switches = if (known) n.switches.map { if (it.address == address) entry else it } else n.switches + entry,
                        )
                    },
                )
            }
            "exit" -> Reduced(this, listOf(Effect.RefreshExit))
            "exits" -> {
                val offers = obj["offers"] as? JsonArray
                Reduced(this, listOfNotNull(offers?.let { Effect.RememberExits(network, it.toString()) }))
            }
            "view" -> {
                val view = runCatching { PathView.parse(json) }.getOrNull() ?: return Reduced(this)
                Reduced(updated(network) { it.copy(view = view, viewAt = nowMs) }, listOf(Effect.RefreshExit))
            }
            "log" -> {
                val level = obj.string("level") ?: "info"
                Reduced(appended(Line(network, "[$level] ${obj.string("message") ?: ""}")))
            }
            else -> Reduced(this)
        }
    }

    private fun peerEvent(network: String, type: String, obj: JsonObject): TunnelState? {
        val key = obj.string("key") ?: return null
        val addr = obj.string("addr") ?: return null
        val name = obj.string("name")
        return updated(network) { n ->
            val before = n.peers.firstOrNull { it.key == key } ?: PeerState(key, addr, name)
            var link = before.link
            var route = before.route
            if (type == "peer") {
                obj.string("state")?.let { state ->
                    link = state
                    obj.string("reason")?.let { link += " ($it)" }
                }
            }
            if (type == "route") route = describeRoute(obj["route"] as? JsonObject)
            val peer = PeerState(key, addr, name, link, route)
            val known = n.peers.any { it.key == key }
            n.copy(peers = if (known) n.peers.map { if (it.key == key) peer else it } else n.peers + peer)
        }
    }

    companion object {
        /** The log keeps the last hundred lines. */
        const val LOG_LINES = 100

        /** A short text for the `route` object of a `route` event; null for `null`. */
        fun describeRoute(route: JsonObject?): String? {
            val kind = route?.string("kind") ?: return null
            route.int("switch")?.let { return "$kind $it" }
            route.string("addr")?.let { return "$kind $it" }
            return kind
        }
    }
}

private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

/** How a device is reached right now. */
sealed interface DeviceRoute {
    data class Direct(val onLan: Boolean) : DeviceRoute

    /** Through a switch or a TURN relay; [kind] is the route kind of the `view` event. */
    data class Helper(val kind: String) : DeviceRoute

    data object Connecting : DeviceRoute

    data object Idle : DeviceRoute
}

/** Names a device across networks. */
data class DeviceId(val network: String, val key: String)

/** A peer of a connected network with what the engine says about its paths. */
data class Device(
    val network: String,
    val peer: TunnelState.PeerState,
    val paths: PathView.Peer?,
    val local: PathView.Local?,
    /** When the view of [paths] arrived, in milliseconds of the clock. */
    val viewAt: Long?,
) {
    val id: DeviceId get() = DeviceId(network, peer.key)
    val name: String get() = peer.name ?: peer.key.take(8)
    val initial: String get() = name.firstOrNull()?.uppercase() ?: "?"
    private val linkState: String get() = paths?.state ?: peer.link
    val isUp: Boolean get() = linkState == "up"

    /** The routes of the link in the engine's rank order. */
    val trace: List<PathView.TraceRoute> get() = paths?.routes.orEmpty()

    /** Whether [addr] is a relay address the device shared. */
    fun isRelay(addr: String): Boolean = paths?.candidates?.any { it.kind == "relay" && it.addr == addr } ?: false

    val route: DeviceRoute
        get() {
            if (!isUp) return if (linkState == "connecting") DeviceRoute.Connecting else DeviceRoute.Idle
            return when (val kind = paths?.route?.kind) {
                "lan" -> DeviceRoute.Direct(onLan = true)
                "internet" -> DeviceRoute.Direct(onLan = false)
                "own_relay", "peer_relay", "switch" -> DeviceRoute.Helper(kind)
                else -> DeviceRoute.Connecting
            }
        }
}

/** The volume the switches and TURN servers still let through. */
data class HelperData(val total: ULong, val remaining: ULong) {
    val text: String get() = "${formatBytes(remaining)} left of ${formatBytes(total)}"
}

val TunnelState.devices: List<Device>
    get() = networks.flatMap { network ->
        network.peers.map { peer ->
            Device(network.name, peer, network.view?.peers?.firstOrNull { it.key == peer.key }, network.view?.local, network.viewAt)
        }
    }

fun TunnelState.device(id: DeviceId): Device? = devices.firstOrNull { it.id == id }

val TunnelState.devicesOnline: Int get() = devices.count { it.isUp }

/** The budgets of all networks added up; null while no transport has one. */
val TunnelState.helperData: HelperData?
    get() {
        val budgets = networks.flatMap { it.view?.local?.transports.orEmpty() }.mapNotNull { it.budget }
        if (budgets.isEmpty()) return null
        return HelperData(budgets.sumOf { it.total }, budgets.sumOf { it.remaining })
    }

/** The switches of all networks that are registered, and how many there are. */
val TunnelState.switchesOnline: Pair<Int, Int>
    get() {
        val switches = networks.flatMap { it.switches }
        return switches.count { it.state == "registered" } to switches.size
    }

/** Whether some device is reached through a relay, mine or the device's. */
val TunnelState.relayInUse: Boolean
    get() = devices.any { it.paths?.route?.kind == "own_relay" || it.paths?.route?.kind == "peer_relay" }

/** "2 networks · 4 devices online". */
val TunnelState.onlineSummary: String
    get() {
        val n = networks.size
        val d = devicesOnline
        return "$n ${if (n == 1) "network" else "networks"} · $d ${if (d == 1) "device" else "devices"} online"
    }

/** What the user can pick for the exit: each network, and each of its sites when it offers several. */
fun exitOptions(networks: List<String>, state: TunnelState?, current: ExitChoice?): List<ExitChoice> {
    val options = networks.flatMap { name ->
        val sites = state?.network(name)?.view?.sites?.map { it.site }.orEmpty()
        if (sites.size > 1) sites.map { ExitChoice(name, it) } else listOf(ExitChoice(name))
    }.toMutableList()
    if (current != null && current !in options) options += current
    return options
}

/** "Italy · home" for the site `it/home`; the note of an option without a site. */
fun ExitChoice.note(): String {
    val site = site ?: return "The exit of this network"
    val parts = site.split('/', limit = 2)
    val country = parts[0].let { code ->
        java.util.Locale("", code.uppercase()).displayCountry.takeIf { it.isNotEmpty() && it != code.uppercase() } ?: code.uppercase()
    }
    return if (parts.size > 1) "$country · ${parts[1]}" else country
}
