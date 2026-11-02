import SwiftUI

/// One device: what it is, how it is reached and the routes the node knows and tries.
struct DeviceScreen: View {
    @EnvironmentObject private var controller: TunnelController
    let id: DeviceID

    var body: some View {
        Form {
            if let device = controller.device(id) {
                Section("Details") {
                    LabeledContent("Network", value: device.network)
                    LabeledContent("Address") { mono(device.peer.addr) }
                    LabeledContent("Public key") { mono(device.peer.key).lineLimit(1).truncationMode(.middle) }
                    if let meter = device.paths?.meter {
                        LabeledContent("Sent / received", value: "\(PathView.Meter.bytes(meter.sent)) / \(PathView.Meter.bytes(meter.received))")
                    }
                }
                Section {
                    PathLine(device: device, size: .large)
                }
                routesSection(device)
            } else {
                Section {
                    Text("This device is not connected now.").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(controller.device(id)?.name ?? "Device")
    }

    private func routesSection(_ device: Device) -> some View {
        Section {
            if device.trace.isEmpty {
                Text("None while there is no session.").foregroundStyle(.secondary)
            }
            ForEach(device.trace) { route in
                RouteRow(device: device, route: route, switchAddress: switchAddress(route, device))
            }
        } header: {
            Text("Routes")
        } footer: {
            Text("The paths to this peer, best first.")
        }
    }

    private func switchAddress(_ route: PathView.TraceRoute, _ device: Device) -> String? {
        route.switch.flatMap { index in device.local?.switches.first { $0.index == index }?.address }
    }

    private func mono(_ text: String) -> some View {
        Text(text).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
    }
}

/// A route of the trace: what it is, where it goes, where it stands, when a failed one is tried
/// again, and how long a ping takes.
private struct RouteRow: View {
    let device: Device
    let route: PathView.TraceRoute
    let switchAddress: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(kind)
                Text(address)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                status.font(.caption.weight(.semibold)).foregroundStyle(color)
            }
            Spacer()
            Text(route.rtt.map { $0 == 0 ? "<1 ms" : "\($0) ms" } ?? "–")
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
    }

    /// The own relay to the peer's relay goes through both.
    private var kind: String {
        switch route.kind {
        case "lan": "Local network"
        case "internet": "Internet"
        case "switch": "Switch"
        case "own_relay": route.addr.map(device.isRelay) == true ? "My relay to the peer's relay" : "My relay"
        case "peer_relay": "Peer's relay"
        default: route.kind
        }
    }

    private var address: String {
        route.addr ?? switchAddress ?? route.switch.map { "switch \($0)" } ?? ""
    }

    @ViewBuilder
    private var status: some View {
        if route.active {
            Text("Active")
        } else if route.status == "failed" {
            if let ms = route.retryIn, let since = device.viewAt {
                Countdown(ms: ms, since: since) { $0.map { "Failed · tried again in \($0)" } ?? "Failed · trying again" }
            } else if let ms = route.forgetIn, let since = device.viewAt {
                Countdown(ms: ms, since: since) { $0.map { "Failed · forgotten in \($0)" } ?? "Failed · forgotten" }
            } else {
                Text("Failed · not tried while a better route works")
            }
        } else {
            Text(word)
        }
    }

    private var word: String {
        switch route.status {
        case "verified": "Verified"
        case "candidate": "Trying"
        case "suspect": "Not answering"
        default: "Not tried"
        }
    }

    private var color: Color {
        if route.active { return .accentColor }
        return route.status == "failed" ? .red : .secondary
    }
}
