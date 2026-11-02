package dev.vardevall.vpn

import android.content.Context
import android.content.Intent
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.TunnelState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * What the app and the service share, in one process: the connection, the state the engine's
 * events build and the calls into the service that runs the engine.
 */
object TunnelHost {
    sealed interface Status {
        data object Disconnected : Status

        data object Connecting : Status

        data object Connected : Status

        data class Failed(val message: String) : Status
    }

    private val statusFlow = MutableStateFlow<Status>(Status.Disconnected)
    private val stateFlow = MutableStateFlow<TunnelState?>(null)

    val status: StateFlow<Status> = statusFlow.asStateFlow()

    /** The tunnel's state while it runs, null otherwise. */
    val state: StateFlow<TunnelState?> = stateFlow.asStateFlow()

    @Volatile
    internal var controller: ExitController? = null

    internal fun setStatus(status: Status) {
        statusFlow.value = status
    }

    internal fun setState(state: TunnelState?) {
        stateFlow.value = state
    }

    internal fun updateState(change: (TunnelState) -> TunnelState) {
        stateFlow.update { it?.let(change) }
    }

    val isActive: Boolean get() = statusFlow.value is Status.Connecting || statusFlow.value is Status.Connected

    /** Starts the service, which connects with the networks that are saved. The VPN permission is granted before. */
    fun connect(context: Context) {
        context.startForegroundService(Intent(context, VardevallService::class.java).setAction(VardevallService.ACTION_CONNECT))
    }

    fun disconnect(context: Context) {
        context.startService(Intent(context, VardevallService::class.java).setAction(VardevallService.ACTION_DISCONNECT))
    }

    /** Makes the running tunnel carry the exit of [choice], or none; null on success, else why not. */
    fun chooseExit(choice: ExitChoice?): String? = controller?.choose(choice)
}

/** What the service offers the app while it runs. */
internal interface ExitController {
    fun choose(choice: ExitChoice?): String?
}
