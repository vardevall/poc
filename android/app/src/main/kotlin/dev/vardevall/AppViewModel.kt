package dev.vardevall

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vardevall.data.NetworkStore
import dev.vardevall.data.Settings
import dev.vardevall.model.ConfigSummary
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.NetworkConfig
import dev.vardevall.vpn.TunnelHost
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.getAndUpdate
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A network as the app edits it: the name it was given and its interface file. */
data class NetworkDraft(val name: String, val text: String, val summary: ConfigSummary?)

/** The owner of the networks, the exit choice and what the screens say about them. */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val store = NetworkStore(app)
    private val settings = Settings(app)

    private val networksFlow = MutableStateFlow<List<NetworkDraft>>(emptyList())

    /** In order; the first is the one whose address the system resolves through. */
    val networks: StateFlow<List<NetworkDraft>> = networksFlow.asStateFlow()

    private val exitFlow = MutableStateFlow(settings.exit)

    /** The exit the user chose for the device's traffic; null is off, the default. */
    val exit: StateFlow<ExitChoice?> = exitFlow.asStateFlow()

    private val messageFlow = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = messageFlow.asStateFlow()

    private val loadedFlow = MutableStateFlow(false)

    /** Whether the saved networks have been read. */
    val loaded: StateFlow<Boolean> = loadedFlow.asStateFlow()

    private val importFlow = MutableStateFlow<String?>(null)

    /** The text of an interface file handed to the app, to open in the editor. */
    val pendingImport: StateFlow<String?> = importFlow.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val saved = runCatching { store.load() }.getOrElse {
                messageFlow.value = "The saved networks could not be read: ${it.message}"
                emptyList()
            }
            networksFlow.value = saved.map { NetworkDraft(it.name, it.text, summaryOf(it.text)) }
            loadedFlow.value = true
        }
    }

    private fun summaryOf(text: String): ConfigSummary? =
        runCatching { ConfigSummary.parse(Native.vvValidateConfig(text)) }.getOrNull()

    fun clearMessage() {
        messageFlow.value = null
    }

    /** Offers [text], an interface file handed to the app, to the editor of a new network. */
    fun offerImport(text: String) {
        importFlow.value = text
    }

    fun takeImport(): String? = importFlow.getAndUpdate { null }

    /** Checks [text] as an interface file. */
    suspend fun validate(text: String): Result<ConfigSummary> = withContext(Dispatchers.Default) {
        runCatching { ConfigSummary.parse(Native.vvValidateConfig(text)) }
    }

    /** A config with fresh keys. */
    suspend fun newConfig(): String = withContext(Dispatchers.Default) {
        """
        [interface]
        private_key = "${Native.vvGenerateNodeKey()}"
        network_secret = "${Native.vvGenerateNetworkSecret()}"
        """.trimIndent()
    }

    /** The text of the document [uri] the user picked or shared; null if it is not text. */
    suspend fun readText(uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                val buffer = ByteArray(MAX_FILE)
                var n = 0
                while (n < MAX_FILE) {
                    val read = input.read(buffer, n, MAX_FILE - n)
                    if (read < 0) break
                    n += read
                }
                if (n == MAX_FILE && input.read() >= 0) null else buffer.decodeToString(0, n).takeIf { '\u0000' !in it }
            }
        }.getOrNull()
    }

    /**
     * Saves [text] as the interface file of network [name], adding the network if it is not
     * there. With [renaming], the network of that name is renamed to [name] and an exit chosen on
     * it follows. Returns null on success, else why not.
     */
    suspend fun commit(name: String, text: String, renaming: String? = null): String? = withContext(Dispatchers.IO) {
        val before = networksFlow.value
        val summary = try {
            ConfigSummary.parse(Native.vvValidateConfig(text))
        } catch (e: Exception) {
            return@withContext e.message ?: "The text is not valid."
        }
        val list = before.toMutableList()
        val renamedFrom = renaming?.takeIf { it != name }
        val renamed = renamedFrom != null
        val index = list.indexOfFirst { it.name == (renaming ?: name) }
        if (renamed || index < 0) {
            checkNewName(name)?.let { return@withContext it }
        }
        val draft = NetworkDraft(name, text, summary)
        if (index >= 0) list[index] = draft else list += draft
        save(list)?.let { return@withContext it }
        if (renamedFrom != null) {
            exitFlow.value?.takeIf { it.network == renamedFrom }?.let { setExitChoice(it.copy(network = name)) }
            settings.forgetExits(renamedFrom)
        }
        null
    }

    /** Removes network [name] and saves the rest at once. Returns null on success, else why not. */
    suspend fun remove(name: String): String? = withContext(Dispatchers.IO) {
        val rest = networksFlow.value.filterNot { it.name == name }
        save(rest)?.let { return@withContext it }
        settings.forgetExits(name)
        if (exitFlow.value?.network == name) setExitChoice(null)
        null
    }

    private fun checkNewName(name: String): String? = when {
        !isValidName(name) -> "A name is lowercase letters, digits and dashes, up to 51 characters."
        networksFlow.value.any { it.name == name } -> "There is a network called $name already."
        else -> null
    }

    /** Validates the whole set, as the engine would start it, and writes it. */
    private fun save(list: List<NetworkDraft>): String? {
        try {
            if (list.isNotEmpty()) {
                Native.vvTunnelSettingsNetworks(list.map { it.name }.toTypedArray(), list.map { it.text }.toTypedArray())
            }
            store.save(list.map { NetworkConfig(it.name, it.text) })
        } catch (e: Exception) {
            return e.message ?: "The networks could not be saved."
        }
        networksFlow.value = list
        messageFlow.value = if (TunnelHost.isActive) "Saved. Turn the connection off and on to use the change." else "Saved."
        return null
    }

    /** Sends the traffic outside the overlay through [choice], or not. The running tunnel takes it at once. */
    suspend fun setExit(choice: ExitChoice?) = withContext(Dispatchers.IO) {
        val before = exitFlow.value
        setExitChoice(choice)
        val failure = TunnelHost.chooseExit(choice)
        if (failure != null) {
            setExitChoice(before)
            messageFlow.value = failure
        }
    }

    private fun setExitChoice(choice: ExitChoice?) {
        settings.exit = choice
        exitFlow.value = choice
    }

    companion object {
        private const val MAX_FILE = 256 * 1024

        /** Whether [name] can name a network: a DNS label of at most 51 characters. */
        fun isValidName(name: String): Boolean = NAME.matches(name)

        private val NAME = Regex("^[a-z0-9]([a-z0-9-]{0,49}[a-z0-9])?$")
    }
}
