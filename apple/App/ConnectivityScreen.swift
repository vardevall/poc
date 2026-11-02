import SwiftUI

/// How each network reaches the devices: this device's NATs and engine, the switches that find
/// them, the relay for when a direct path is not possible, and the traffic of each transport.
struct ConnectivityScreen: View {
    @EnvironmentObject private var controller: TunnelController

    var body: some View {
        Form {
            if let state = controller.state {
                ForEach(Part.all(of: state.networks)) { part in
                    switch part.kind {
                    case .thisDevice: thisDevice(part.network, of: state.networks.count)
                    case .switches: switches(part.network, of: state.networks.count)
                    case .relay: relay(part.network, of: state.networks.count)
                    case .traffic: traffic(part.network, of: state.networks.count)
                    }
                }
                #if os(macOS)
                LogSections()
                #else
                Section {
                    NavigationLink("Log", value: ConnectivityRoute.log)
                }
                #endif
            } else {
                Section {
                    Text("Connect to see how your devices are reached.").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Connectivity")
    }

    /// A section of one network. Each has an identity of its own: on macOS two sections that
    /// share one, such as a network's name, show one in place of the other.
    private struct Part: Identifiable {
        enum Kind: String, CaseIterable {
            case thisDevice, switches, relay, traffic
        }

        let network: TunnelState.Network
        let kind: Kind
        var id: String { "\(network.name)/\(kind.rawValue)" }

        static func all(of networks: [TunnelState.Network]) -> [Part] {
            networks.flatMap { network in Kind.allCases.map { Part(network: network, kind: $0) } }
        }
    }

    private func header(_ title: String, _ network: TunnelState.Network, of count: Int) -> Text {
        Text(count > 1 ? "\(network.name) · \(title)" : title)
    }

    private func thisDevice(_ network: TunnelState.Network, of count: Int) -> some View {
        Section {
            LabeledContent("Engine", value: network.engine.capitalized)
            if let local = network.view?.local {
                natRow("NAT, IPv4", local.ipv4)
                natRow("NAT, IPv6", local.ipv6)
            }
        } header: {
            header("This device", network, of: count)
        }
    }

    private func natRow(_ title: String, _ nat: PathView.Nat) -> some View {
        LabeledContent(title) {
            VStack(alignment: .trailing, spacing: 2) {
                Text(nat.word)
                if let addr = nat.addr {
                    Text(addr)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func switches(_ network: TunnelState.Network, of count: Int) -> some View {
        Section {
            if network.switches.isEmpty {
                Text("None configured.").foregroundStyle(.secondary)
            }
            ForEach(network.switches) { SwitchRow(network: network, entry: $0) }
        } header: {
            header("Switches", network, of: count)
        } footer: {
            Text("A switch helps your devices find each other.")
        }
    }

    private func relay(_ network: TunnelState.Network, of count: Int) -> some View {
        Section {
            if let relay = network.view?.local.relay {
                RelayRow(relay: relay, inUse: controller.devices.contains { $0.network == network.name && $0.paths?.route?.kind == "own_relay" })
            } else {
                Text("None.").foregroundStyle(.secondary)
            }
        } header: {
            header("Relay", network, of: count)
        } footer: {
            Text("A relay is used only when two devices cannot connect directly.")
        }
    }

    private func traffic(_ network: TunnelState.Network, of count: Int) -> some View {
        let transports = network.view?.local.transports ?? []
        return Section {
            if transports.isEmpty {
                Text("None yet.").foregroundStyle(.secondary)
            }
            ForEach(transports) { TransportRow(transport: $0) }
        } header: {
            header("Traffic", network, of: count)
        }
    }
}

/// The bytes carried by a transport and, for a switch or TURN server, the volume it still lets through.
private struct TransportRow: View {
    let transport: PathView.Transport

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(transport.title).font(.subheadline)
            Text(transport.meter.summary).font(.caption).foregroundStyle(.secondary)
            if let budget = transport.budget {
                ProgressView(value: Double(budget.remaining), total: Double(max(budget.total, 1)))
                    .tint(color(budget.level))
                Text(describe(budget)).font(.caption).foregroundStyle(color(budget.level))
            }
        }
    }

    private func describe(_ budget: PathView.Budget) -> String {
        let left = PathView.Meter.bytes(budget.remaining)
        let total = PathView.Meter.bytes(budget.total)
        if budget.level == "exhausted" { return "Used up (\(total)): carries nothing until renewed" }
        return "\(left) of \(total) left" + (transport.usable ? "" : ", not usable")
    }

    private func color(_ level: String) -> Color {
        switch level {
        case "plenty": .accentColor
        case "half": .secondary
        case "low": .helper
        default: .red
        }
    }
}

/// The recent lines of each engine's log, and of the tunnel's own.
struct LogSections: View {
    @EnvironmentObject private var controller: TunnelController

    var body: some View {
        if let state = controller.state {
            let count = state.networks.count
            ForEach(state.networks.map(\.name), id: \.self) { name in
                Section(count > 1 ? "Log · \(name)" : "Log") {
                    Text(state.lines(of: name, withTunnel: count == 1).suffix(20).joined(separator: "\n"))
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            if count > 1 {
                Section("Log · tunnel") {
                    Text(state.tunnelLines.suffix(20).joined(separator: "\n"))
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        } else {
            Section {
                Text("Connect to see the log.").foregroundStyle(.secondary)
            }
        }
    }
}

/// The screen Connectivity pushes on iOS for the log.
struct LogScreen: View {
    var body: some View {
        Form { LogSections() }
            .formStyle(.grouped)
            .navigationTitle("Log")
    }
}
