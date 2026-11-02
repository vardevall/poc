package dev.vardevall.model

/** What an exit in use adds to the tunnel settings. */
data class ExitRouting(
    /** This node's address in the site of the exit chosen; null while none is. */
    val siteAddress: String?,
    /** The IPv4 address of the tunnel, with the default route: the one the exit gave, or the home address while none did. */
    val ipv4Address: String,
) {
    companion object {
        /**
         * The routing for [choice] given the exit [inUse] and the summary of the chosen network;
         * null without a choice. With a choice and no exit, or an exit without IPv4, the default
         * routes stay, so that traffic is dropped, not sent around the tunnel.
         */
        fun wanted(choice: ExitChoice?, inUse: ExitInUse?, network: ConfigSummary?): ExitRouting? {
            if (choice == null || network == null) return null
            return ExitRouting(inUse?.addr, inUse?.ipv4 ?: network.ipv4Home)
        }
    }
}

/** An address or a route with its prefix length. */
data class Prefix(val address: String, val length: Int)

/** What the `VpnService.Builder` is asked for. */
data class InterfacePlan(
    val mtu: Int,
    val addresses: List<Prefix>,
    val routes: List<Prefix>,
    /** The one DNS server: the resolver alias, which the engine answers. */
    val dnsServer: String,
    val searchDomains: List<String>,
    /** IPv4 traffic that no route names stays on the underlying network. */
    val ipv4Bypass: Boolean,
) {
    companion object {
        /** The four private IPv4 ranges that stay off the tunnel with an exit in use. */
        val privateIpv4 = listOf(
            Prefix("10.0.0.0", 8),
            Prefix("172.16.0.0", 12),
            Prefix("192.168.0.0", 16),
            Prefix("169.254.0.0", 16),
        )

        /**
         * The addresses that Android's resolver (`2000::`, for `AI_ADDRCONFIG`) and Chromium
         * (`2001:4860:4860::8888`) connect a UDP socket to before they ask for AAAA records. Without
         * a route to them on a network with no IPv6 internet, the overlay's names do not resolve.
         */
        val ipv6Probes = listOf(
            Prefix("2000::", 128),
            Prefix("2001:4860:4860::8888", 128),
        )

        /**
         * The plan for the settings of the networks, the resolver [alias] and the [routing] of an
         * exit in use. Link-local addresses are skipped (the platform rejects them). With an exit,
         * `::/0` and `0.0.0.0/0` less the private ranges are routes, the site address and the IPv4
         * address are addresses, and without one IPv4 is let past the tunnel. Without an exit and
         * without [ipv6Internet] on the underlying network, the [ipv6Probes] are routed too.
         */
        fun of(settings: TunnelSettings, alias: String, routing: ExitRouting?, ipv6Internet: Boolean): InterfacePlan {
            val addresses = settings.addrs
                .filterNot { it.addr.lowercase().startsWith("fe80:") }
                .map { Prefix(it.addr, it.prefix) }
                .toMutableList()
            val routes = settings.routes.map { Prefix(it.addr, it.prefix) }.toMutableList()
            if (routing != null) {
                routing.siteAddress?.let { addresses += Prefix(it, 128) }
                addresses += Prefix(routing.ipv4Address, 32)
                routes += Prefix("::", 0)
                routes += routesLess(Prefix("0.0.0.0", 0), privateIpv4)
            } else if (!ipv6Internet) {
                routes += ipv6Probes
            }
            return InterfacePlan(
                mtu = settings.mtu,
                addresses = addresses,
                routes = routes,
                dnsServer = alias,
                searchDomains = settings.dns.matchDomains.filterNot { it.endsWith(".arpa") },
                ipv4Bypass = routing == null,
            )
        }

        /** The prefixes that cover [whole] and none of [excluded]; both are IPv4. */
        fun routesLess(whole: Prefix, excluded: List<Prefix>): List<Prefix> {
            val ranges = excluded.map { it.range() }
            val out = mutableListOf<Prefix>()
            fun split(start: Long, length: Int) {
                val end = start + (1L shl (32 - length)) - 1
                if (ranges.any { it.first <= start && end <= it.last }) return
                if (ranges.none { it.first <= end && start <= it.last }) {
                    out += Prefix(dotted(start), length)
                    return
                }
                split(start, length + 1)
                split(start + (1L shl (32 - length - 1)), length + 1)
            }
            split(whole.range().first, whole.length)
            return out
        }

        private fun Prefix.range(): LongRange {
            val start = address.split('.').fold(0L) { acc, part -> (acc shl 8) or part.toLong() }
            return start..(start + (1L shl (32 - length)) - 1)
        }

        private fun dotted(address: Long) =
            listOf(24, 16, 8, 0).joinToString(".") { ((address shr it) and 0xff).toString() }
    }
}
