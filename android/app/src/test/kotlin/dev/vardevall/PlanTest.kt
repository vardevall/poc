package dev.vardevall

import dev.vardevall.model.ConfigSummary
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.ExitInUse
import dev.vardevall.model.ExitRouting
import dev.vardevall.model.InterfacePlan
import dev.vardevall.model.PathReport
import dev.vardevall.model.Prefix
import dev.vardevall.model.TunnelSettings
import dev.vardevall.model.UnderlyingNetwork
import dev.vardevall.model.formatBytes
import dev.vardevall.ui.timeLeft
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlanTest {
    private val settings = TunnelSettings.parse(
        """{"addrs":[{"addr":"fd12:3456:789a::1","prefix":64},{"addr":"fe80::1","prefix":64},{"addr":"fd12:3456:789b::2","prefix":64}],
            "routes":[{"addr":"fd12:3456:789a::","prefix":64},{"addr":"fd12:3456:789b::","prefix":64}],"mtu":1280,
            "dns":{"servers":["fd12:3456:789a::1"],"match_domains":["home.internal","a.ip6.arpa","work.internal","b.ip6.arpa"]}}""",
    )

    private fun summary(forward: Boolean = false) = ConfigSummary.parse(
        """{"public_key":"k","network_id":"n","addrs":{"ula":"fd12::1","link_local":"fe80::1"},"domain":"home.internal","mtu":1280,
            "forward":$forward,"ipv4_home":"198.18.0.7","peers":[]}""",
    )

    @Test
    fun withoutAnExitOnlyTheOverlayIsRoutedAndIpv4PassesTheTunnel() {
        val plan = InterfacePlan.of(settings, "fd12:3456:789a::53", null, ipv6Internet = true)
        assertEquals(listOf(Prefix("fd12:3456:789a::1", 64), Prefix("fd12:3456:789b::2", 64)), plan.addresses)
        assertEquals(listOf(Prefix("fd12:3456:789a::", 64), Prefix("fd12:3456:789b::", 64)), plan.routes)
        assertEquals("fd12:3456:789a::53", plan.dnsServer)
        assertEquals(listOf("home.internal", "work.internal"), plan.searchDomains)
        assertTrue(plan.ipv4Bypass)
        assertEquals(1280, plan.mtu)
    }

    @Test
    fun anExitAddsTheDefaultRoutesLessThePrivateRanges() {
        val routing = ExitRouting("fd12:3456:789a:1::1", "198.18.3.4")
        val plan = InterfacePlan.of(settings, "fd12:3456:789a::53", routing, ipv6Internet = false)
        assertTrue(Prefix("fd12:3456:789a:1::1", 128) in plan.addresses)
        assertTrue(InterfacePlan.ipv6Probes.none { it in plan.routes })
        assertTrue(Prefix("198.18.3.4", 32) in plan.addresses)
        assertTrue(Prefix("::", 0) in plan.routes)
        assertFalse(plan.ipv4Bypass)
        val v4 = plan.routes.filter { '.' in it.address }
        val routed = v4.sumOf { 1L shl (32 - it.length) }
        val privateSize = (1L shl 24) + (1L shl 20) + (1L shl 16) + (1L shl 16)
        assertEquals("the routes and the private ranges are the whole space", 1L shl 32, routed + privateSize)
    }

    @Test
    fun withoutIpv6InternetTheProbesAreRouted() {
        val plan = InterfacePlan.of(settings, "fd12:3456:789a::53", null, ipv6Internet = false)
        assertEquals(
            listOf(
                Prefix("fd12:3456:789a::", 64),
                Prefix("fd12:3456:789b::", 64),
                Prefix("2000::", 128),
                Prefix("2001:4860:4860::8888", 128),
            ),
            plan.routes,
        )
        assertTrue(plan.ipv4Bypass)
    }

    @Test
    fun theRoutesDoNotOverlapThePrivateRanges() {
        val routes = InterfacePlan.routesLess(Prefix("0.0.0.0", 0), InterfacePlan.privateIpv4)
        fun start(p: Prefix) = p.address.split('.').fold(0L) { a, b -> (a shl 8) or b.toLong() }
        for (p in routes) {
            val s = start(p)
            val e = s + (1L shl (32 - p.length)) - 1
            for (q in InterfacePlan.privateIpv4) {
                val qs = start(q)
                val qe = qs + (1L shl (32 - q.length)) - 1
                assertTrue("$p overlaps $q", e < qs || qe < s)
            }
        }
        assertTrue(Prefix("8.0.0.0", 7) in routes)
        assertTrue(Prefix("11.0.0.0", 8) in routes)
        assertTrue(Prefix("172.32.0.0", 11) in routes)
        assertTrue(Prefix("192.169.0.0", 16) in routes)
        assertTrue(Prefix("169.255.0.0", 16) in routes)
    }

    @Test
    fun anExitWithoutAnAddressUsesTheHomeOne() {
        val choice = ExitChoice("home")
        assertNull(ExitRouting.wanted(null, null, summary()))
        assertEquals(ExitRouting(null, "198.18.0.7"), ExitRouting.wanted(choice, null, summary()))
        val inUse = ExitInUse.parse("""{"network":"home","site":"it/home","via":"k","addr":"fd00::1","ipv4":"198.18.9.9"}""")
        assertEquals(ExitRouting("fd00::1", "198.18.9.9"), ExitRouting.wanted(choice, inUse, summary()))
        val noIpv4 = ExitInUse.parse("""{"network":"home","site":"it/home","via":"k","addr":"fd00::1","ipv4":null}""")
        assertEquals(ExitRouting("fd00::1", "198.18.0.7"), ExitRouting.wanted(choice, noIpv4, summary()))
        assertNull(ExitInUse.parse("null"))
    }

    private fun net(id: Long, resolvers: List<String>, addresses: List<String>, metered: Boolean = false) =
        UnderlyingNetwork(id, "wlan$id", 10 + id.toInt(), addresses, resolvers, metered)

    @Test
    fun theActiveNetworksResolversComeFirst() {
        val nets = listOf(net(1, listOf("10.0.0.1", "10.0.0.2"), emptyList()), net(2, listOf("10.0.0.2", "8.8.8.8"), emptyList()))
        assertEquals(listOf("10.0.0.2", "8.8.8.8", "10.0.0.1"), PathReport.resolvers(nets, 2))
        assertEquals(listOf("10.0.0.1", "10.0.0.2", "8.8.8.8"), PathReport.resolvers(nets, null))
    }

    @Test
    fun aLinkLocalResolverCarriesItsInterface() {
        assertEquals("fe80::1%12", PathReport.resolver("fe80::1", 12))
        assertEquals("fe80::1", PathReport.resolver("fe80::1", 0))
        assertEquals("2001:db8::1", PathReport.resolver("2001:db8::1", 12))
    }

    @Test
    fun theFamiliesThatChangedAreNamed() {
        val before = PathReport.addresses(listOf(net(1, emptyList(), listOf("192.168.1.5", "2001:db8::5"))))
        assertNull(PathReport.changedFamilies(null, before))
        assertNull(PathReport.changedFamilies(before, before))
        val v4Only = PathReport.addresses(listOf(net(1, emptyList(), listOf("192.168.1.9", "2001:db8::5"))))
        assertEquals(listOf("v4"), PathReport.changedFamilies(before, v4Only))
        val other = PathReport.addresses(listOf(net(2, emptyList(), listOf("10.1.1.1", "2001:db8::5"))))
        assertEquals(listOf("v4", "v6"), PathReport.changedFamilies(before, other))
    }

    @Test
    fun thePathReportIsTheJsonOfTheHeader() {
        val json = PathReport.json(true, true, listOf(net(1, emptyList(), emptyList(), metered = true)), listOf("v6"))
        assertEquals("""{"changed":true,"metered":true,"interfaces":[{"name":"wlan1","metered":true}],"families":["v6"]}""", json)
        assertEquals("""{"changed":false,"metered":false,"interfaces":[]}""", PathReport.json(false, false, emptyList(), null))
    }

    @Test
    fun timeLeftCountsDownInSecondsThenMinutes() {
        assertNull(timeLeft(1000, 1000))
        assertNull(timeLeft(1000, 5000))
        assertEquals("1 s", timeLeft(1001, 1000))
        assertEquals("89 s", timeLeft(90_000, 1000))
        assertEquals("2 min", timeLeft(121_000, 1000))
    }

    @Test
    fun bytesAreWrittenAsPeopleRead() {
        assertEquals("0 bytes", formatBytes(0UL))
        assertEquals("999 bytes", formatBytes(999UL))
        assertEquals("1 KB", formatBytes(1000UL))
        assertEquals("1.5 MB", formatBytes(1_500_000UL))
        assertEquals("1.1 TB", formatBytes(1_100_000_000_000UL))
        assertEquals("18.4 EB", formatBytes(ULong.MAX_VALUE))
    }
}
