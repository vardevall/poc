import SwiftUI

/// A switch of a network with where its registration stands (vv-04 §4.6) and, while it is
/// disconnected, when it is tried again. Without a live entry it is the switch of the file.
struct SwitchRow: View {
    let address: String
    var auth: String?
    var live: TunnelState.Switch?
    var network: TunnelState.Network?

    init(network: TunnelState.Network, entry: TunnelState.Switch) {
        address = entry.address
        auth = entry.auth
        live = entry
        self.network = network
    }

    init(configured: ConfigSummary.Switch, network: TunnelState.Network?) {
        address = configured.address
        auth = configured.auth
        live = network?.switches.first { $0.address == configured.address }
        self.network = network
    }

    var body: some View {
        let viewed = network?.view?.local.switches.first { $0.address == address }
        VStack(alignment: .leading, spacing: 2) {
            Text(address).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
            Group {
                if let live, live.state == "disconnected", let ms = viewed?.retryIn, let since = network?.viewAt {
                    let text = Self.describe(live, auth: auth ?? viewed?.auth, transport: nil)
                    Countdown(ms: ms, since: since) { $0.map { "\(text) · tried again in \($0)" } ?? "\(text) · trying again" }
                } else if let live {
                    Text(Self.describe(live, auth: auth ?? viewed?.auth, transport: viewed?.transport))
                } else {
                    Text(auth == "web" ? "web address" : "pinned")
                }
            }
            .font(.caption)
            .foregroundStyle(color)
        }
    }

    private var color: Color {
        switch live?.state {
        case "registered": .accentColor
        case "disconnected": .red
        default: .secondary
        }
    }

    private static func describe(_ entry: TunnelState.Switch, auth: String?, transport: String?) -> String {
        let prefix = auth.map { "\($0) · " } ?? ""
        guard let reason = entry.reason else {
            return prefix + (transport.map { "\(entry.state) over \($0.uppercased())" } ?? entry.state)
        }
        return prefix + "\(entry.state) (\(reason.replacingOccurrences(of: "_", with: " ")))"
    }
}

/// The relay the engine reports for a network.
struct RelayRow: View {
    let relay: PathView.Relay
    let inUse: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(relay.server).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                Spacer()
                Text(inUse ? "In use" : "Ready")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(inUse ? Color.helper : Color.secondary)
            }
            Text("\(relay.addr) · \(relay.transport.uppercased())").font(.caption).foregroundStyle(.secondary)
        }
    }
}
