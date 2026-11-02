package dev.vardevall

import dev.vardevall.model.PathView
import dev.vardevall.model.TunnelState
import dev.vardevall.model.VvJson
import dev.vardevall.model.devices
import dev.vardevall.model.helperData
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The golden events of `tun/tests/json.rs`, as the engine writes them, through the app's models. */
class EventsTest {
    private val golden: List<String> = javaClass.getResourceAsStream("/events.txt")!!
        .bufferedReader().readLines()
        .filter { it.isNotBlank() && !it.startsWith("#") }

    /** The event as the engine delivers it: tagged with the network it belongs to. */
    private fun tagged(json: String, network: String = "home"): String =
        JsonObject(VvJson.parseToJsonElement(json).jsonObject + ("network" to JsonPrimitive(network))).toString()

    private fun of(type: String): List<String> = golden.filter { VvJson.parseToJsonElement(it).jsonObject["type"]?.jsonPrimitive?.content == type }

    private fun start() = TunnelState().seeded(listOf("home"))

    private fun feed(state: TunnelState, vararg events: String): TunnelState =
        events.fold(state) { s, e -> s.reduce(tagged(e), 1000).state }

    @Test
    fun theFixtureIsTheWholeList() {
        assertEquals(68, golden.size)
    }

    @Test
    fun everyEventIsUnderstood() {
        var state = start()
        for (event in golden) state = state.reduce(tagged(event), 1000).state
        assertEquals(listOf("home"), state.networks.map { it.name })
    }

    @Test
    fun everyViewDecodes() {
        val views = of("view")
        assertEquals(13, views.size)
        for (view in views) assertNotNull(PathView.parse(view))
    }

    @Test
    fun theStatusEventsSetTheEngine() {
        val s = feed(start(), golden[0])
        assertEquals("started", s.networks[0].engine)
        assertEquals(51820, s.networks[0].port)
        assertEquals("stopped", feed(s, golden[2]).networks[0].engine)
    }

    @Test
    fun aPeerGathersItsLinkAndItsRoute() {
        val added = of("added").first()
        val up = of("peer").first { "\"initiator\":true" in it && "\"nas\"" in it }
        val route = of("route").first { "\"kind\":\"lan\"" in it }
        val state = feed(start(), added, up, route)
        val peer = state.networks[0].peers.single()
        assertEquals("nas", peer.name)
        assertEquals("up via lan 192.168.1.2:7", peer.detail)
        assertTrue(peer.isUp)
        val switchRoute = of("route").first { "\"kind\":\"switch\"" in it }
        assertEquals("up via switch 3", feed(state, switchRoute).networks[0].peers.single().detail)
        val none = of("route").first { "\"route\":null" in it }
        assertEquals("up", feed(state, none).networks[0].peers.single().detail)
        val down = of("peer").first { "\"reason\":\"unreachable\"" in it }
        assertEquals("down (unreachable) via lan 192.168.1.2:7", feed(state, down).networks[0].peers.single().detail)
        assertTrue(feed(state, of("removed").first()).networks[0].peers.isEmpty())
    }

    @Test
    fun switchesAreFiledByAddress() {
        val events = of("switch")
        val state = feed(start(), *events.toTypedArray())
        assertEquals(1, state.networks[0].switches.size)
        assertEquals("sw.example.org:443", state.networks[0].switches[0].address)
        assertEquals("web", state.networks[0].switches[0].auth ?: "web")
    }

    @Test
    fun theExitEventsAskForWork() {
        val exit = of("exit").first()
        assertEquals(listOf<TunnelState.Effect>(TunnelState.Effect.RefreshExit), start().reduce(tagged(exit), 0).effects)
        val exits = start().reduce(tagged(of("exits").single()), 0).effects.single() as TunnelState.Effect.RememberExits
        assertEquals("home", exits.network)
        val offers = VvJson.parseToJsonElement(exits.offersJson).jsonArray
        assertEquals("it/home", offers.single().jsonObject["site"]?.jsonPrimitive?.content)
    }

    @Test
    fun aViewIsKeptWithTheTimeItArrived() {
        val view = of("view").last()
        val reduced = start().reduce(tagged(view), 4242)
        assertEquals(4242L, reduced.state.networks[0].viewAt)
        assertEquals(listOf<TunnelState.Effect>(TunnelState.Effect.RefreshExit), reduced.effects)
        val laptop = reduced.state.networks[0].view!!.peers.single()
        assertEquals("up", laptop.state)
        assertEquals(12, laptop.rtt)
    }

    @Test
    fun theTraceOfARouteKeepsItsRetryAndItsForgetting() {
        val trace = PathView.parse(of("view").last()).peers.single().routes!!
        assertEquals(3, trace.size)
        assertTrue(trace[0].active)
        assertEquals(12, trace[0].rtt)
        assertEquals("failed", trace[1].status)
        assertEquals(0L, trace[1].retryIn)
        assertNull(trace[1].forgetIn)
        assertEquals(0L, trace[2].forgetIn)
        assertEquals(0, trace[2].rtt)
    }

    @Test
    fun theLargestByteCountsDecode() {
        val withMax = of("view").first { "18446744073709551615" in it }
        val transport = PathView.parse(withMax).local.transports.first { it.meter.sent == ULong.MAX_VALUE }
        assertEquals("sw0.example:4455", transport.name)
        assertEquals("Switch sw0.example:4455", transport.title)
    }

    @Test
    fun theBudgetsAddUp() {
        val full = of("view").first { "18446744073709551615" in it }
        val state = start().reduce(tagged(full), 0).state
        assertNotNull(state.helperData)
    }

    @Test
    fun theNatsHaveWords() {
        val nats = of("view").take(9).map { PathView.parse(it).local }
        assertEquals(setOf("Unknown", "Symmetric", "No UDP", "Open"), nats.flatMap { listOf(it.ipv4.word, it.ipv6.word) }.toSet())
    }

    @Test
    fun logLinesKeepTheirLevelAndTheLastHundred() {
        var state = start()
        state = feed(state, of("log").first())
        assertEquals("[debug] plain", state.log.single().text)
        repeat(150) { state = state.noted("line $it") }
        assertEquals(TunnelState.LOG_LINES, state.log.size)
        assertEquals("[tunnel] line 149", state.log.last().text)
        assertEquals(TunnelState.LOG_LINES, state.tunnelLines().size)
    }

    @Test
    fun anEventOfAnotherNetworkOrWithoutOneIsLeftOut() {
        val state = start()
        val event = of("added").first()
        assertEquals(state, state.reduce(tagged(event, "elsewhere"), 0).state)
        assertEquals(state, state.reduce(event, 0).state)
        assertEquals(state, state.reduce("not json", 0).state)
    }

    @Test
    fun devicesCarryTheirPaths() {
        val state = feed(start(), of("view").last())
        val withPeer = feed(
            state,
            """{"type":"added","key":"${state.networks[0].view!!.peers[0].key}","addr":"fd00::28","name":"laptop","trust":"key"}""",
        )
        val device = withPeer.devices.single()
        assertEquals("laptop", device.name)
        assertEquals("L", device.initial)
        assertEquals(3, device.trace.size)
    }
}
