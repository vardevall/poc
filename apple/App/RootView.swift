import SwiftUI

/// The screens of the app. iOS shows Status, Networks and Connectivity as tabs, each with its own
/// stack; macOS shows them in the detail column of a sidebar, with no pushes.
struct RootView: View {
    #if os(macOS)
    @EnvironmentObject private var controller: TunnelController
    @EnvironmentObject private var navigator: MacNavigator
    @StateObject private var add = AddNetworkModel()

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 190, ideal: 230)
        } detail: {
            detail
        }
        .frame(minWidth: 820, minHeight: 560)
        .addingNetworks(add)
    }

    private var sidebar: some View {
        List(selection: $navigator.selection) {
            Label("Status", systemImage: "dot.radiowaves.left.and.right").tag(MacSelection.status)
            Label("Connectivity", systemImage: "network").tag(MacSelection.connectivity)
            Section("Networks") {
                ForEach(controller.networks) { network in
                    Label(network.name, systemImage: "point.3.connected.trianglepath.dotted")
                        .tag(MacSelection.network(network.name))
                }
                AddNetworkButton(model: add)
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
            Section("Devices") {
                let devices = controller.devices
                if devices.isEmpty {
                    Text(controller.state == nil ? "Connect to see them" : "None yet").foregroundStyle(.secondary)
                }
                ForEach(devices) { device in
                    Label {
                        Text(device.name)
                    } icon: {
                        StateDot(color: device.route.color)
                    }
                    .tag(MacSelection.device(device.id))
                }
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch navigator.selection ?? .status {
        case .status: StatusScreen(showConnectivity: { navigator.selection = .connectivity })
        case .connectivity: ConnectivityScreen()
        case .network(let name): NetworkScreen(name: name)
        case .device(let id): DeviceScreen(id: id)
        }
    }
    /// A device's state in the sidebar: a dot with a light ring, so that it stays visible on the
    /// selected row's accent fill.
    private struct StateDot: View {
        let color: Color

        var body: some View {
            Circle()
                .fill(color)
                .overlay(Circle().strokeBorder(.white.opacity(0.85), lineWidth: 1.5))
                .frame(width: 10, height: 10)
        }
    }
    #else
    enum Tab: Hashable {
        case status, networks, connectivity
    }

    @State private var tab = Tab.status
    @State private var statusPath = NavigationPath()
    @State private var networksPath = NavigationPath()
    @State private var connectivityPath = NavigationPath()

    /// Selecting the tab that is already selected pops it to its root.
    private var selection: Binding<Tab> {
        Binding(
            get: { tab },
            set: { new in
                if new == tab {
                    switch new {
                    case .status: statusPath = NavigationPath()
                    case .networks: networksPath = NavigationPath()
                    case .connectivity: connectivityPath = NavigationPath()
                    }
                }
                tab = new
            })
    }

    var body: some View {
        TabView(selection: selection) {
            NavigationStack(path: $statusPath) {
                StatusScreen(showConnectivity: { tab = .connectivity })
                    .navigationDestination(for: DeviceID.self) { DeviceScreen(id: $0) }
            }
            .tabItem { Label("Status", systemImage: "dot.radiowaves.left.and.right") }
            .tag(Tab.status)
            NavigationStack(path: $networksPath) {
                NetworksScreen()
                    .navigationDestination(for: String.self) { NetworkScreen(name: $0) }
                    .navigationDestination(for: DeviceID.self) { DeviceScreen(id: $0) }
            }
            .tabItem { Label("Networks", systemImage: "point.3.connected.trianglepath.dotted") }
            .tag(Tab.networks)
            NavigationStack(path: $connectivityPath) {
                ConnectivityScreen()
                    .navigationDestination(for: ConnectivityRoute.self) { route in
                        switch route {
                        case .log: LogScreen()
                        }
                    }
            }
            .tabItem { Label("Connectivity", systemImage: "network") }
            .tag(Tab.connectivity)
        }
    }
    #endif
}

/// The screens Connectivity pushes on iOS.
enum ConnectivityRoute: Hashable {
    case log
}
