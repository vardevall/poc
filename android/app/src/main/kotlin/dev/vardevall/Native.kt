package dev.vardevall

/**
 * What the engine tells the host. Both calls run on the engine's thread, one at a time, and must
 * return quickly and not throw.
 */
interface EngineCallbacks {
    /** A JSON event (`apple/include/vardevall.h`, `vv_event_cb`). */
    fun onEvent(json: String)

    /** A JSON request for an mDNS backend, only when the engine was started with `mdns` (`vv_mdns_cb`). */
    fun onMdns(json: String)
}

/** A call into the engine failed; the message says why. */
class VvException(message: String) : Exception(message)

/**
 * JNI interface of the Rust engine (`jni/`). It mirrors `apple/include/vardevall.h` function for
 * function and this file is authoritative for the names and parameters: `jni/src/symbols.rs` fails
 * when the exported `Java_dev_vardevall_Native_*` functions differ from it. Failures throw
 * [VvException].
 *
 * A handle is the engine started by [vvStart] or [vvStartNetworks]; it is valid until [vvStop],
 * and no function may be called with it during or after that call.
 *
 * Differences from the C interface: the packets of the interface are read and written in Rust,
 * from the descriptor given at the start ([vvSetTun] replaces it), so there is no packet callback;
 * [vvPacketsIn] remains for a host that reads them itself. Strings are returned as JVM strings,
 * so there is no `vv_string_free`. [vvSetResolvers] and [vvResolverAlias] belong to the Android host
 *.
 */
object Native {
    init {
        System.loadLibrary("vardevall_jni")
    }

    /** `vv_start`: the one network `vardevall`. `tunFd` is detached from its `ParcelFileDescriptor`; Rust owns it, even when the call fails. With `mdns`, requests go to [EngineCallbacks.onMdns]; without, the engine runs its own mDNS sockets. */
    external fun vvStart(config: String, tunFd: Int, callbacks: EngineCallbacks, mdns: Boolean): Long

    /** `vv_start_networks`: 1 to 8 networks, `names[i]` with the interface file `configs[i]`. */
    external fun vvStartNetworks(names: Array<String>, configs: Array<String>, tunFd: Int, callbacks: EngineCallbacks, mdns: Boolean): Long

    /** `vv_stop`. Blocks for up to 500 ms while the engine says goodbye. */
    external fun vvStop(handle: Long)

    /** Makes the new interface of the same service the one packets are read from and written to; the old descriptor is closed and the engine keeps its sessions. */
    external fun vvSetTun(handle: Long, tunFd: Int)

    /** `vv_packets_in`, for a host that reads the packets itself. */
    external fun vvPacketsIn(handle: Long, packets: Array<ByteArray>)

    /** `vv_path_changed`; `json` may be null. */
    external fun vvPathChanged(handle: Long, json: String?)

    /** Sets the resolvers of the underlying network, `192.0.2.1`, `2001:db8::1` or `fe80::1%23` (with the interface index), in the order they are tried. Names outside every overlay go to them. */
    external fun vvSetResolvers(handle: Long, servers: Array<String>)

    /** `vv_announce`; `network` null is the first. */
    external fun vvAnnounce(handle: Long, network: String?, name: String, port: Int, proto: String)

    /** `vv_withdraw`. */
    external fun vvWithdraw(handle: Long, network: String?, name: String): Boolean

    /** `vv_providers`. */
    external fun vvProviders(handle: Long, network: String?, name: String): String

    /** `vv_set_exit`: `network` null turns the exit off. */
    external fun vvSetExit(handle: Long, network: String?, site: String?)

    /** `vv_remember_exits`. */
    external fun vvRememberExits(handle: Long, network: String?, json: String)

    /** `vv_exit_in_use`: the string `null` or a JSON object. */
    external fun vvExitInUse(handle: Long): String

    /** `vv_mdns_event`. */
    external fun vvMdnsEvent(handle: Long, json: String)

    /** `vv_tunnel_settings`. */
    external fun vvTunnelSettings(config: String): String

    /** `vv_tunnel_settings_networks`. */
    external fun vvTunnelSettingsNetworks(names: Array<String>, configs: Array<String>): String

    /** The address of the `/64` of `ula` where the device sends its DNS queries: `<ula /64>::53`. The `dns.servers` of the settings is the node's own address, which Android delivers locally. */
    external fun vvResolverAlias(ula: String): String

    /** `vv_generate_node_key`. */
    external fun vvGenerateNodeKey(): String

    /** `vv_generate_network_secret`. */
    external fun vvGenerateNetworkSecret(): String

    /** `vv_public_key`. */
    external fun vvPublicKey(secret: String): String

    /** `vv_validate_config`: the JSON summary of the file, without secrets. */
    external fun vvValidateConfig(config: String): String
}
