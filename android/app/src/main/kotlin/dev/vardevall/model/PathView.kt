package dev.vardevall.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The JSON of the engine's documents; members the app does not know are ignored. */
val VvJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

/** The `view` event: what the node believes about its paths (`apple/include/vardevall.h`). */
@Serializable
data class PathView(
    val local: Local,
    val peers: List<Peer> = emptyList(),
    val sites: List<Site>? = null,
) {
    @Serializable
    data class Nat(
        /** "unknown", "punchable", "symmetric" or "udp_blocked". */
        val nat: String,
        val addr: String? = null,
    ) {
        /** "Open", "Symmetric", "No UDP" or "Unknown". */
        val word: String
            get() = when (nat) {
                "punchable" -> "Open"
                "symmetric" -> "Symmetric"
                "udp_blocked" -> "No UDP"
                else -> "Unknown"
            }
    }

    @Serializable
    data class Relay(
        val addr: String,
        val server: String,
        /** "udp" or "tls". */
        val transport: String,
    )

    @Serializable
    data class Switch(
        val index: Int,
        val address: String,
        /** "pinned" for an address known by its key, "web" for a web address. */
        val auth: String? = null,
        val state: String,
        val reason: String? = null,
        val transport: String? = null,
        /** While disconnected, the milliseconds from the view to the next attempt. */
        @SerialName("retry_in_ms") val retryIn: Long? = null,
    )

    /** Bytes counted on a transport or on a peer's routes. */
    @Serializable
    data class Meter(val sent: ULong, val received: ULong)

    /** The volume a switch or TURN server lets a transport carry. */
    @Serializable
    data class Budget(
        val total: ULong,
        val remaining: ULong,
        /** "switch" or "turn". */
        val source: String,
        /** "plenty", "half", "low" or "exhausted". */
        val level: String,
    )

    @Serializable
    data class Transport(
        /** "udp", "turn" or the `host:port` of a switch. */
        val name: String,
        val usable: Boolean,
        val meter: Meter,
        val budget: Budget? = null,
    ) {
        /** What the user knows the transport as. */
        val title: String
            get() = when (name) {
                "udp" -> "Direct (UDP)"
                "turn" -> "TURN relay"
                else -> "Switch $name"
            }
    }

    @Serializable
    data class Local(
        val ipv6: Nat,
        val ipv4: Nat,
        val relay: Relay? = null,
        val switches: List<Switch> = emptyList(),
        val transports: List<Transport> = emptyList(),
    )

    @Serializable
    data class Route(
        /** "lan", "internet", "peer_relay", "own_relay" or "switch". */
        val kind: String,
        val metered: Boolean = false,
        val degraded: Boolean? = null,
        val addr: String? = null,
        @SerialName("switch") val switchIndex: Int? = null,
    )

    /** One route of a link, from the trace the node keeps: the active one carries data. */
    @Serializable
    data class TraceRoute(
        val kind: String,
        val addr: String? = null,
        @SerialName("switch") val switchIndex: Int? = null,
        /** "dormant", "candidate", "verified", "suspect" or "failed". */
        val status: String,
        @SerialName("rtt_ms") val rtt: Int? = null,
        val active: Boolean,
        val metered: Boolean = false,
        /** A failed route that could still win: the milliseconds from the view to its next ping. */
        @SerialName("retry_in_ms") val retryIn: Long? = null,
        /** A failed route learned from the peer's frames: the milliseconds until it is dropped. */
        @SerialName("forget_in_ms") val forgetIn: Long? = null,
    ) {
        val id: String get() = "$kind/${addr ?: ""}/${switchIndex ?: ""}"
    }

    @Serializable
    data class Candidate(
        val kind: String,
        val addr: String,
        val local: Boolean? = null,
        val metered: Boolean? = null,
    )

    @Serializable
    data class Peer(
        val key: String,
        val addr: String,
        val name: String? = null,
        /** "idle", "connecting", "up" or "down". */
        val state: String,
        val route: Route? = null,
        /** "unknown", "punchable" or "relay_only". */
        val nat: String = "unknown",
        val candidates: List<Candidate> = emptyList(),
        val switches: List<Int> = emptyList(),
        val probing: Boolean = false,
        val fallback: Boolean = false,
        val meter: Meter? = null,
        @SerialName("rtt_ms") val rtt: Int? = null,
        /** Every route of the link, best first. */
        val routes: List<TraceRoute>? = null,
    )

    /** A site some peer offered an exit for, live or not: "it" or "it/home". */
    @Serializable
    data class Site(val site: String)

    companion object {
        fun parse(json: String): PathView = VvJson.decodeFromString(serializer(), json)
    }
}

/** A volume of bytes as a person reads it: "1.2 MB". */
fun formatBytes(n: ULong): String {
    val units = listOf("bytes", "KB", "MB", "GB", "TB", "PB", "EB")
    var value = n.toDouble()
    var unit = 0
    while (value >= 1000 && unit < units.lastIndex) {
        value /= 1000
        unit++
    }
    if (unit == 0) return "$n bytes"
    val text = "%.1f".format(java.util.Locale.ROOT, value)
    return "${text.removeSuffix(".0")} ${units[unit]}"
}

/** "↑ 1.2 MB  ↓ 340 KB". */
val PathView.Meter.summary: String get() = "↑ ${formatBytes(sent)}  ↓ ${formatBytes(received)}"

/** "<1 ms" or "12 ms". */
fun rttText(ms: Int): String = if (ms == 0) "<1 ms" else "$ms ms"
