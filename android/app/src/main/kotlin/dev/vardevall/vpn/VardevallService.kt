package dev.vardevall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import dev.vardevall.EngineCallbacks
import dev.vardevall.MainActivity
import dev.vardevall.Native
import dev.vardevall.R
import dev.vardevall.data.NetworkStore
import dev.vardevall.data.Settings
import dev.vardevall.model.ConfigSummary
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.ExitInUse
import dev.vardevall.model.ExitRouting
import dev.vardevall.model.InterfacePlan
import dev.vardevall.model.NetworkConfig
import dev.vardevall.model.TunnelSettings
import dev.vardevall.model.TunnelState
import dev.vardevall.model.onlineSummary
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Hosts the engine: builds the interface, hands Rust its descriptor, follows the device's
 * networks and applies what an exit in use asks of the interface (`apple/Tunnel/` is the model).
 *
 * The engine's own sockets must not enter the tunnel. The app is therefore excluded from its own
 * VPN with `addDisallowedApplication`, rather than `protect()` on each socket: the engine opens
 * sockets in many places (UDP, TURN over TLS, the switches' HTTP/3, HTTP/2 and HTTP/1, host-name
 * lookups, mDNS and the resolvers' queries), none of which has a hook for the platform, and an
 * excluded application cannot leak one.
 */
class VardevallService : VpnService(), ExitController {
    companion object {
        const val ACTION_CONNECT = "dev.vardevall.CONNECT"
        const val ACTION_DISCONNECT = "dev.vardevall.DISCONNECT"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 1
        private const val TAG = "vardevall"
    }

    /** Start, stop and every change of the interface run here, one at a time. */
    private val worker = Executors.newSingleThreadExecutor()
    private val refreshPending = AtomicBoolean(false)

    private val store by lazy { NetworkStore(this) }
    private val settings by lazy { Settings(this) }

    private var handle = 0L
    private var watcher: NetworkWatcher? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    // Guarded by the worker thread.
    private var base: TunnelSettings? = null
    private var alias: String = ""
    private var summaries: Map<String, ConfigSummary> = emptyMap()
    private var choice: ExitChoice? = null
    private var applied: ExitRouting? = null
    private var ipv6Internet = false
    private var lastNotified = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            worker.execute {
                teardown()
                TunnelHost.setStatus(TunnelHost.Status.Disconnected)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // ACTION_CONNECT, or the system starting the service for an always-on VPN.
        promote("Connecting")
        worker.execute { bringUp() }
        return START_STICKY
    }

    override fun onRevoke() {
        worker.execute {
            teardown()
            TunnelHost.setStatus(TunnelHost.Status.Disconnected)
            stopSelf()
        }
    }

    override fun onDestroy() {
        worker.execute { teardown() }
        worker.shutdown()
        super.onDestroy()
    }

    private fun bringUp() {
        teardown()
        TunnelHost.setStatus(TunnelHost.Status.Connecting)
        try {
            val networks = store.load()
            check(networks.isNotEmpty()) { "Add a network first." }
            val names = networks.map { it.name }.toTypedArray()
            val configs = networks.map { it.text }.toTypedArray()
            val tunnel = TunnelSettings.parse(Native.vvTunnelSettingsNetworks(names, configs))
            base = tunnel
            alias = Native.vvResolverAlias(tunnel.dns.servers.first())
            summaries = networks.associate { it.name to ConfigSummary.parse(Native.vvValidateConfig(it.text)) }
            choice = settings.exit?.takeIf { c -> networks.any { it.name == c.network } }
            applied = ExitRouting.wanted(choice, null, choice?.let { summaries[it.network] })
            val connectivity = getSystemService(ConnectivityManager::class.java)
            ipv6Internet = NetworkWatcher.hasIpv6Internet(connectivity.activeNetwork)

            multicastLock = (applicationContext.getSystemService(WIFI_SERVICE) as WifiManager)
                .createMulticastLock("vardevall-mdns").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            val watcher = NetworkWatcher(
                connectivity,
                onPath = { json -> handle.takeIf { it != 0L }?.let { Native.vvPathChanged(it, json) } },
                onResolvers = { list -> handle.takeIf { it != 0L }?.let { Native.vvSetResolvers(it, list.toTypedArray()) } },
                onUnderlying = { nets -> setUnderlyingNetworks(nets) },
                onIpv6 = { reachable -> worker.execute { applyIpv6(reachable) } },
            )
            this.watcher = watcher

            TunnelHost.setState(TunnelState().seeded(names.toList()))
            val fd = establish(InterfacePlan.of(tunnel, alias, applied, ipv6Internet), watcher.underlying()).detachFd()
            handle = Native.vvStartNetworks(names, configs, fd, callbacks, false)
            TunnelHost.controller = this
            watcher.start()
            for (network in networks) {
                settings.exits(network.name)?.let { offers ->
                    runCatching { Native.vvRememberExits(handle, network.name, offers) }
                        .onFailure { note("${network.name}: the remembered exits are ignored: ${it.message}") }
                }
            }
            choice?.let { c ->
                runCatching { Native.vvSetExit(handle, c.network, c.site) }.onFailure {
                    note("the exit ${c.network} is not used: ${it.message}")
                    choice = null
                }
                requestRefresh()
            }
            TunnelHost.setStatus(TunnelHost.Status.Connected)
            notify(force = true)
        } catch (e: Throwable) {
            Log.e(TAG, "connect failed", e)
            teardown()
            TunnelHost.setStatus(TunnelHost.Status.Failed(e.message ?: e.javaClass.simpleName))
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun teardown() {
        TunnelHost.controller = null
        watcher?.stop()
        watcher = null
        if (handle != 0L) {
            val h = handle
            handle = 0
            runCatching { Native.vvStop(h) }
        }
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
        TunnelHost.setState(null)
    }

    private val callbacks = object : EngineCallbacks {
        override fun onEvent(json: String) {
            val now = SystemClock.elapsedRealtime()
            var effects = emptyList<TunnelState.Effect>()
            TunnelHost.updateState { state ->
                val reduced = state.reduce(json, now)
                effects = reduced.effects
                reduced.state
            }
            for (effect in effects) {
                when (effect) {
                    is TunnelState.Effect.RememberExits -> settings.setExits(effect.network, effect.offersJson)
                    TunnelState.Effect.RefreshExit -> requestRefresh()
                }
            }
            notify(force = false)
        }

        override fun onMdns(json: String) = Unit
    }

    override fun choose(choice: ExitChoice?): String? {
        return worker.submit<String?> {
            if (handle == 0L) return@submit "The tunnel is not running."
            try {
                Native.vvSetExit(handle, choice?.network, choice?.site)
                this.choice = choice
                refreshExit()
                null
            } catch (e: Exception) {
                e.message ?: "The exit could not be set."
            }
        }.get()
    }

    /** Looks at the exit now, or once the look in progress is done; the engine's events ask for it. */
    private fun requestRefresh() {
        if (refreshPending.compareAndSet(false, true)) {
            worker.execute {
                refreshPending.set(false)
                refreshExit()
            }
        }
    }

    /** Applies the interface the exit in use calls for, and publishes what stands behind the choice. */
    private fun refreshExit() {
        val h = handle
        val tunnel = base
        if (h == 0L || tunnel == null) return
        val chosen = choice
        val inUse = if (chosen == null) null else runCatching { ExitInUse.parse(Native.vvExitInUse(h)) }.getOrNull()
        TunnelHost.updateState { state ->
            state.copy(exit = chosen?.let { c ->
                val name = inUse?.let { used ->
                    state.network(c.network)?.peers?.firstOrNull { it.key == used.via }?.name
                }
                TunnelState.ExitState(c.network, inUse?.site ?: c.site, inUse?.let { name ?: it.via })
            })
        }
        val routing = ExitRouting.wanted(chosen, inUse, chosen?.let { summaries[it.network] })
        if (routing == applied) return
        try {
            val fd = establish(InterfacePlan.of(tunnel, alias, routing, ipv6Internet), watcher?.underlying()).detachFd()
            Native.vvSetTun(h, fd)
            applied = routing
            note(describe(chosen, inUse))
        } catch (e: Exception) {
            note("the exit settings were not applied: ${e.message}")
        }
    }

    /** Rebuilds the interface when the underlying network gains or loses IPv6 internet (the probe routes of [InterfacePlan]). */
    private fun applyIpv6(reachable: Boolean) {
        val h = handle
        val tunnel = base
        if (h == 0L || tunnel == null || reachable == ipv6Internet) return
        try {
            val fd = establish(InterfacePlan.of(tunnel, alias, applied, reachable), watcher?.underlying()).detachFd()
            Native.vvSetTun(h, fd)
            ipv6Internet = reachable
            note(if (reachable) "the network has IPv6 internet" else "the network has no IPv6 internet: the IPv6 probes go to the tunnel")
        } catch (e: Exception) {
            note("the IPv6 routes were not applied: ${e.message}")
        }
    }

    private fun describe(choice: ExitChoice?, inUse: ExitInUse?): String = when {
        choice == null -> "no exit in use"
        inUse == null -> "exit ${choice.network}: none is live, traffic outside the overlay is dropped"
        else -> "exit ${inUse.network} ${inUse.site} via ${inUse.via}"
    }

    private fun note(line: String) {
        Log.i(TAG, line)
        TunnelHost.updateState { it.noted(line) }
    }

    private fun establish(plan: InterfacePlan, underlying: Array<Network>?): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("vardevall")
            .setMtu(plan.mtu)
            .setMetered(false)
            // The engine's sockets, the resolvers' queries included, stay outside the tunnel.
            .addDisallowedApplication(packageName)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
            )
        plan.addresses.forEach { builder.addAddress(it.address, it.length) }
        plan.routes.forEach { builder.addRoute(it.address, it.length) }
        builder.addDnsServer(plan.dnsServer)
        plan.searchDomains.forEach { builder.addSearchDomain(it) }
        // Only IPv6 is configured without an exit; IPv4 would be dropped otherwise.
        if (plan.ipv4Bypass) builder.allowFamily(OsConstants.AF_INET)
        underlying?.let { builder.setUnderlyingNetworks(it) }
        return builder.establish() ?: error("The VPN permission was not granted.")
    }

    /** Puts the service in the foreground with the state of the tunnel. */
    private fun promote(text: String) {
        val notification = notification(text)
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0
        ServiceCompat.startForeground(this, NOTIFICATION, notification, type)
    }

    private fun notification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW),
            )
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, VardevallService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_vardevall)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(0, getString(R.string.disconnect), disconnect)
            .build()
    }

    /** Refreshes the notification with the state, at most once a second unless [force]. */
    private fun notify(force: Boolean) {
        val now = SystemClock.elapsedRealtime()
        if (!force && now - lastNotified < 1000) return
        lastNotified = now
        val state = TunnelHost.state.value ?: return
        val text = if (TunnelHost.status.value is TunnelHost.Status.Connected) state.onlineSummary else "Connecting"
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(text))
    }
}
