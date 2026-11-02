package dev.vardevall.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** The result of `vv_validate_config`: the file without its secrets. */
@Serializable
data class ConfigSummary(
    @SerialName("public_key") val publicKey: String,
    @SerialName("network_id") val networkId: String,
    val name: String? = null,
    val addrs: Addrs,
    val domain: String,
    val mtu: Int,
    @SerialName("listen_port") val listenPort: Int = 0,
    val mdns: Boolean = true,
    @SerialName("stun_servers") val stunServers: Int = 0,
    @SerialName("turn_servers") val turnServers: Int = 0,
    val switches: List<Switch> = emptyList(),
    /** Whether the file names upstream resolvers, so that an exit in use does not receive the DNS. */
    val forward: Boolean = false,
    /** The site of the `[exit]` table, if this node serves an exit. */
    val exit: String? = null,
    /** The IPv4 address an exit gives this node when it is free. */
    @SerialName("ipv4_home") val ipv4Home: String,
    val services: List<Service> = emptyList(),
    val peers: List<Peer> = emptyList(),
) {
    @Serializable
    data class Addrs(val ula: String, @SerialName("link_local") val linkLocal: String)

    @Serializable
    data class Peer(
        @SerialName("public_key") val publicKey: String,
        val name: String? = null,
        val addr: String,
    )

    /** A `[[switch]]` entry: `host:port` as the `switch` event names it, and "pinned" or "web". */
    @Serializable
    data class Switch(val address: String, val auth: String)

    /** A `[[service]]` entry. */
    @Serializable
    data class Service(val name: String, val port: Int, val proto: String)

    companion object {
        fun parse(json: String): ConfigSummary = VvJson.decodeFromString(serializer(), json)
    }
}

/** The result of `vv_tunnel_settings_networks`. */
@Serializable
data class TunnelSettings(
    val addrs: List<Addr>,
    val routes: List<Addr>,
    val mtu: Int,
    val dns: Dns,
) {
    @Serializable
    data class Addr(val addr: String, val prefix: Int)

    @Serializable
    data class Dns(val servers: List<String>, @SerialName("match_domains") val matchDomains: List<String>)

    companion object {
        fun parse(json: String): TunnelSettings = VvJson.decodeFromString(serializer(), json)
    }
}

/** The result of `vv_exit_in_use` when an exit carries the device's traffic. */
@Serializable
data class ExitInUse(
    val network: String,
    val site: String,
    /** The exit's node key. */
    val via: String,
    /** This node's address in the site. */
    val addr: String,
    /** The IPv4 address the exit gave this node; null when it carries no IPv4. */
    val ipv4: String? = null,
) {
    companion object {
        /** `null` for the engine's string "null". */
        fun parse(json: String): ExitInUse? =
            if (json.trim() == "null") null else VvJson.decodeFromString(serializer(), json)
    }
}

/** A provider of a service, as `vv_providers` reports it. */
@Serializable
data class ServiceProvider(
    val key: String,
    val addr: String,
    val name: String? = null,
    val port: Int,
    val proto: String,
    val live: Boolean,
)

/** A network of the tunnel: the name the user gave it and its interface file. */
data class NetworkConfig(val name: String, val text: String)

/** The user's choice to send the device's traffic through the exit of a network. */
data class ExitChoice(val network: String, val site: String? = null)
