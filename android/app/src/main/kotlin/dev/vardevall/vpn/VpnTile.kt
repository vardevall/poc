package dev.vardevall.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.vardevall.MainActivity
import dev.vardevall.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

/** The quick settings tile: the connection at a tap, with the state in its subtitle. */
class VpnTile : TileService() {
    private var scope: CoroutineScope? = null
    private var job: Job? = null

    override fun onStartListening() {
        val scope = CoroutineScope(Dispatchers.Main)
        this.scope = scope
        job = TunnelHost.status.onEach { render(it) }.launchIn(scope)
    }

    override fun onStopListening() {
        job?.cancel()
        scope?.cancel()
        scope = null
    }

    override fun onClick() {
        if (TunnelHost.isActive) {
            TunnelHost.disconnect(this)
        } else if (VpnService.prepare(this) == null) {
            TunnelHost.connect(this)
        } else {
            // The permission is asked in the app.
            val open = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
                startActivityAndCollapse(open)
            }
        }
    }

    private fun render(status: TunnelHost.Status) {
        val tile = qsTile ?: return
        tile.state = if (status is TunnelHost.Status.Connected || status is TunnelHost.Status.Connecting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        tile.subtitle = when (status) {
            TunnelHost.Status.Connected -> getString(R.string.connected)
            TunnelHost.Status.Connecting -> getString(R.string.connecting)
            is TunnelHost.Status.Failed -> getString(R.string.failed)
            TunnelHost.Status.Disconnected -> getString(R.string.not_connected)
        }
        tile.updateTile()
    }
}
