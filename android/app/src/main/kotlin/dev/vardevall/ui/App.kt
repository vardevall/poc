package dev.vardevall.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import dev.vardevall.AppViewModel
import dev.vardevall.model.DeviceId
import dev.vardevall.model.device
import dev.vardevall.vpn.TunnelHost
import kotlinx.coroutines.launch
import java.net.URLDecoder
import java.net.URLEncoder

private enum class Tab(val route: String, val label: String, val icon: ImageVector) {
    Overview("overview", "Overview", Icons.Outlined.Hub),
    Networks("networks", "Networks", Icons.Outlined.Language),
    Connectivity("connectivity", "Connectivity", Icons.Outlined.Lan),
}

private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

private fun dec(s: String?) = URLDecoder.decode(s ?: "", "UTF-8")

/** Whether Android sends the names past the VPN: Private DNS set to a host name. */
private fun privateDnsStrict(context: Context): Boolean =
    runCatching { Settings.Global.getString(context.contentResolver, "private_dns_mode") == "hostname" }.getOrDefault(false)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Page(
    title: String,
    nav: NavHostController,
    tab: Tab? = null,
    close: Boolean = false,
    actions: @Composable () -> Unit = {},
    fab: @Composable () -> Unit = {},
    snackbar: SnackbarHostState? = null,
    content: @Composable () -> Unit,
) {
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (tab == null) {
                        IconButton(onClick = { nav.popBackStack() }) {
                            Icon(if (close) Icons.Outlined.Close else Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = if (close) "Cancel" else "Back")
                        }
                    }
                },
                actions = { actions() },
            )
        },
        bottomBar = {
            if (tab != null) {
                NavigationBar {
                    for (t in Tab.entries) {
                        NavigationBarItem(
                            selected = t == tab,
                            onClick = {
                                nav.navigate(t.route) {
                                    popUpTo(Tab.Overview.route) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = t != tab
                                }
                            },
                            icon = { Icon(t.icon, contentDescription = null) },
                            label = { Text(t.label) },
                        )
                    }
                }
            }
        },
        floatingActionButton = fab,
        snackbarHost = { snackbar?.let { SnackbarHost(it) } },
    ) { padding ->
        androidx.compose.foundation.layout.Box(Modifier.padding(padding)) { content() }
    }
}

/** The app: Overview, Networks and Connectivity as the tabs of a navigation bar, and the screens they open. */
@Composable
fun VardevallApp(vm: AppViewModel) {
    val context = LocalContext.current
    val nav = rememberNavController()
    val scope = rememberCoroutineScope()
    val networks by vm.networks.collectAsStateWithLifecycle()
    val exit by vm.exit.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()
    val status by TunnelHost.status.collectAsStateWithLifecycle()
    val state by TunnelHost.state.collectAsStateWithLifecycle()
    val pending by vm.pendingImport.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) TunnelHost.connect(context)
    }
    fun setConnected(on: Boolean) {
        if (!on) return TunnelHost.disconnect(context)
        vm.clearMessage()
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val ask = VpnService.prepare(context)
        if (ask == null) TunnelHost.connect(context) else consent.launch(ask)
    }

    LaunchedEffect(message) {
        message?.let {
            snackbar.showSnackbar(it)
            vm.clearMessage()
        }
    }
    LaunchedEffect(pending) {
        if (pending != null) nav.navigate("editor")
    }

    NavHost(nav, startDestination = Tab.Overview.route) {
        composable(Tab.Overview.route) {
            Page("vardevall", nav, Tab.Overview, snackbar = snackbar) {
                OverviewScreen(
                    model = OverviewModel(status, state, networks.map { it.name }, exit, null, privateDnsStrict(context)),
                    onConnect = ::setConnected,
                    onExit = { choice -> scope.launch { vm.setExit(choice) } },
                    onServers = { nav.navigate(Tab.Connectivity.route) },
                    onDevice = { nav.navigate("device/${enc(it.network)}/${enc(it.key)}") },
                )
            }
        }
        composable(Tab.Networks.route) {
            Page(
                "Networks", nav, Tab.Networks, snackbar = snackbar,
                fab = {
                    ExtendedFloatingActionButton(
                        onClick = { nav.navigate("editor") },
                        icon = { Icon(Icons.Outlined.Add, contentDescription = null) },
                        text = { Text("Add network") },
                    )
                },
            ) {
                NetworksScreen(networks, state, onNetwork = { nav.navigate("network/${enc(it)}") })
            }
        }
        composable(Tab.Connectivity.route) {
            Page("Connectivity", nav, Tab.Connectivity) {
                ConnectivityScreen(state, onLog = { nav.navigate("log") })
            }
        }
        composable("log") {
            Page("Log", nav) { LogScreen(state) }
        }
        composable("network/{name}", arguments = listOf(navArgument("name") { type = NavType.StringType })) { entry ->
            val name = dec(entry.arguments?.getString("name"))
            val network = networks.firstOrNull { it.name == name }
            var failure by remember { mutableStateOf<String?>(null) }
            Page(name, nav, snackbar = snackbar) {
                if (network != null) {
                    NetworkScreen(
                        network, state, failure,
                        onDevice = { nav.navigate("device/${enc(it.network)}/${enc(it.key)}") },
                        onEdit = { nav.navigate("editor?name=${enc(name)}") },
                        onRemove = {
                            scope.launch {
                                failure = vm.remove(name)
                                if (failure == null) nav.popBackStack()
                            }
                        },
                    )
                }
            }
        }
        composable(
            "device/{network}/{key}",
            arguments = listOf(navArgument("network") { type = NavType.StringType }, navArgument("key") { type = NavType.StringType }),
        ) { entry ->
            val id = DeviceId(dec(entry.arguments?.getString("network")), dec(entry.arguments?.getString("key")))
            val device = state?.device(id)
            val title = device?.name ?: networks.firstOrNull { it.name == id.network }?.summary?.peers?.firstOrNull { it.publicKey == id.key }?.let { it.name ?: it.addr } ?: "Device"
            Page(title, nav) { DeviceScreen(device) }
        }
        composable(
            "editor?name={name}",
            arguments = listOf(navArgument("name") { type = NavType.StringType; nullable = true; defaultValue = null }),
        ) { entry ->
            val existing = entry.arguments?.getString("name")?.let(::dec)
            val draft = networks.firstOrNull { it.name == existing }
            EditorPage(vm, nav, existing, draft?.text)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditorPage(vm: AppViewModel, nav: NavHostController, existing: String?, text: String?) {
    val scope = rememberCoroutineScope()
    val editor = remember(existing) {
        if (existing == null) EditorState("", text ?: "", isNew = true) else EditorState(existing, text ?: "", isNew = false)
    }
    var failure by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    LaunchedEffect(existing) {
        if (existing == null) {
            editor.replace(vm.takeImport() ?: vm.newConfig())
        }
    }
    Page(
        if (existing == null) "New network" else "Edit $existing", nav, close = true,
        actions = {
            TextButton(
                enabled = editor.canSave && !saving,
                onClick = {
                    saving = true
                    scope.launch {
                        failure = vm.commit(editor.name, editor.text, existing)
                        saving = false
                        if (failure == null) nav.popBackStack()
                    }
                },
            ) { Text("Save") }
        },
    ) {
        EditorScreen(vm, editor, failure)
    }
}
