package dev.vardevall.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dev.vardevall.model.PathReport
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import dev.vardevall.model.UnderlyingNetwork
import java.io.IOException
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * Follows the networks of the device that are not the tunnel and tells the engine what changed:
 * the path (`vv_path_changed`), the resolvers of the active network for the names outside the
 * overlay, the underlying networks of the VPN, and whether the active one has IPv6 internet.
 */
internal class NetworkWatcher(
    private val manager: ConnectivityManager,
    private val onPath: (String) -> Unit,
    private val onResolvers: (List<String>) -> Unit,
    private val onUnderlying: (Array<Network>?) -> Unit,
    private val onIpv6: (Boolean) -> Unit,
) {
    companion object {
        private val probe: InetAddress = InetAddress.getByName("2000::")

        /**
         * Whether [network] routes IPv6 to the internet: a UDP socket on it connects to `2000::`,
         * the check of Android's resolver for `AI_ADDRCONFIG`. Nothing is sent.
         */
        fun hasIpv6Internet(network: Network?): Boolean {
            if (network == null) return false
            val fd = try {
                Os.socket(OsConstants.AF_INET6, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP)
            } catch (_: ErrnoException) {
                return false
            }
            return try {
                network.bindSocket(fd)
                Os.connect(fd, probe, 53)
                true
            } catch (_: ErrnoException) {
                false
            } catch (_: IOException) {
                false
            } finally {
                runCatching { Os.close(fd) }
            }
        }
    }

    private class Known(var network: Network, var link: android.net.LinkProperties? = null, var caps: NetworkCapabilities? = null)

    private val known = LinkedHashMap<Long, Known>()
    private val lock = Any()
    private var lastAddresses: Map<String, Set<String>>? = null
    private var lastActive: Long? = null
    private var lastMetered: Boolean? = null
    private var lastResolvers: List<String>? = null
    private var lastIpv6: Boolean? = null
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(lock) { known.getOrPut(network.networkHandle) { Known(network) }.network = network }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: android.net.LinkProperties) {
                synchronized(lock) { known.getOrPut(network.networkHandle) { Known(network) }.link = linkProperties }
                evaluate()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                synchronized(lock) { known.getOrPut(network.networkHandle) { Known(network) }.caps = networkCapabilities }
                evaluate()
            }

            override fun onLost(network: Network) {
                synchronized(lock) { known.remove(network.networkHandle) }
                evaluate()
            }
        }
        // NOT_VPN: the callback would otherwise report the tunnel and its resolver once it is up.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        manager.registerNetworkCallback(request, callback)
        this.callback = callback
    }

    fun stop() {
        callback?.let { runCatching { manager.unregisterNetworkCallback(it) } }
        callback = null
    }

    /** The networks the VPN runs over: the active one first. */
    fun underlying(): Array<Network>? = synchronized(lock) {
        val active = activeId()
        val ordered = known.values.filter { it.link != null }.sortedBy { it.network.networkHandle != active }
        ordered.takeIf { it.isNotEmpty() }?.map { it.network }?.toTypedArray()
    }

    /** The application's own sockets are outside the tunnel, so its active network is the underlying one. */
    private fun activeId(): Long? =
        manager.activeNetwork?.networkHandle?.takeIf { it in known }

    private fun evaluate() {
        var path: String? = null
        var resolvers: List<String>? = null
        var underlying: Array<Network>? = null
        var ipv6: Boolean? = null
        synchronized(lock) {
            val active = activeId()
            val networks = known.values.mapNotNull { k ->
                val link = k.link ?: return@mapNotNull null
                val index = link.interfaceName?.let { name -> runCatching { NetworkInterface.getByName(name)?.index }.getOrNull() } ?: 0
                UnderlyingNetwork(
                    id = k.network.networkHandle,
                    interfaceName = link.interfaceName,
                    interfaceIndex = index,
                    addresses = link.linkAddresses.mapNotNull { it.address.hostAddress?.substringBefore('%') },
                    resolvers = link.dnsServers.mapNotNull { dns ->
                        dns.hostAddress?.let { PathReport.resolver(it.substringBefore('%'), index) }
                    },
                    metered = k.caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false,
                )
            }
            val list = PathReport.resolvers(networks, active)
            if (list != lastResolvers) {
                lastResolvers = list
                resolvers = list
            }
            val addresses = PathReport.addresses(networks)
            val families = PathReport.changedFamilies(lastAddresses, addresses)
            val changed = lastAddresses != null && (families != null || active != lastActive)
            val metered = networks.firstOrNull { it.id == active }?.metered ?: false
            val first = lastAddresses == null
            if (first || changed || metered != lastMetered) {
                path = PathReport.json(changed, metered, networks, families)
            }
            lastAddresses = addresses
            lastActive = active
            lastMetered = metered
            underlying = underlying()
            val reachable = hasIpv6Internet(active?.let { known[it]?.network })
            if (reachable != lastIpv6) {
                lastIpv6 = reachable
                ipv6 = reachable
            }
        }
        resolvers?.let(onResolvers)
        path?.let(onPath)
        onUnderlying(underlying)
        ipv6?.let(onIpv6)
    }
}
