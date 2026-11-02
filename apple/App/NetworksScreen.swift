import SwiftUI

#if os(iOS)
/// The networks, and a way to add one.
struct NetworksScreen: View {
    @EnvironmentObject private var controller: TunnelController
    @StateObject private var add = AddNetworkModel()

    var body: some View {
        Form {
            Section {
                if controller.networks.isEmpty {
                    Text("No networks yet.").foregroundStyle(.secondary)
                }
                ForEach(controller.networks) { network in
                    NavigationLink(value: network.name) { NetworkRow(network: network) }
                }
            } footer: {
                Text("Each network is separate: devices in one cannot see the others.")
            }
            Section {
                AddNetworkButton(model: add)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Networks")
        .addingNetworks(add)
    }

    /// A network of the list: its domain, the devices online and the exit it offers.
    struct NetworkRow: View {
        @EnvironmentObject private var controller: TunnelController
        let network: NetworkDraft

        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(network.name).font(.headline)
                if let line = detail {
                    Text(line).font(.footnote).foregroundStyle(.secondary)
                }
                if let exit {
                    Text(exit).font(.caption.weight(.semibold)).foregroundStyle(Color.accentColor)
                }
            }
            .padding(.vertical, 2)
        }

        private var detail: String? {
            var parts: [String] = []
            if let domain = network.summary?.domain { parts.append(domain) }
            if let live = controller.network(network.name) {
                let online = live.peers.filter { $0.state == "up" }.count
                parts.append("\(online) \(online == 1 ? "device" : "devices") online")
            }
            return parts.isEmpty ? nil : parts.joined(separator: " · ")
        }

        private var exit: String? {
            let sites = controller.network(network.name)?.view?.sites ?? []
            guard !sites.isEmpty else { return nil }
            return "Exit · " + sites.map { ExitChoice(network: network.name, site: $0.site).note }.joined(separator: ", ")
        }
    }
}
#endif
