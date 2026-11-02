import SwiftUI

/// Names a device across networks.
struct DeviceID: Hashable {
    let network: String
    let key: String
}

/// How a device is reached right now.
enum DeviceRoute: Equatable {
    case direct(onLAN: Bool)
    /// Through a switch or a TURN relay; `kind` is the route kind of the `view` event.
    case helper(kind: String)
    case connecting
    case idle

    var color: Color {
        switch self {
        case .direct: .accentColor
        case .helper: .helper
        case .connecting, .idle: .secondary
        }
    }
}

/// A peer of a connected network with what the engine says about its paths.
struct Device: Identifiable {
    let network: String
    let peer: TunnelState.Peer
    let paths: PathView.Peer?
    let local: PathView.Local?
    /// When the view of `paths` arrived.
    let viewAt: Date?

    var id: DeviceID { DeviceID(network: network, key: peer.key) }
    var name: String { peer.name ?? String(peer.key.prefix(8)) }
    var initial: String { name.first.map { String($0).uppercased() } ?? "?" }
    var isUp: Bool { (paths?.state ?? peer.state) == "up" }

    /// The routes of the link in the engine's rank order.
    var trace: [PathView.TraceRoute] { paths?.routes ?? [] }

    /// Whether `addr` is a relay address the device shared.
    func isRelay(_ addr: String) -> Bool {
        paths?.candidates.contains { $0.kind == "relay" && $0.addr == addr } ?? false
    }

    var route: DeviceRoute {
        guard isUp else { return (paths?.state ?? peer.state) == "connecting" ? .connecting : .idle }
        switch paths?.route?.kind {
        case "lan": return .direct(onLAN: true)
        case "internet": return .direct(onLAN: false)
        case "own_relay", "peer_relay", "switch": return .helper(kind: paths?.route?.kind ?? "")
        default: return .connecting
        }
    }
}

/// The volume the switches and TURN servers still let through.
struct HelperData: Equatable {
    var total: UInt64
    var remaining: UInt64

    var text: String { "\(PathView.Meter.bytes(remaining)) left of \(PathView.Meter.bytes(total))" }
}

extension TunnelController {
    func network(_ name: String) -> TunnelState.Network? {
        state?.networks.first { $0.name == name }
    }

    var devices: [Device] {
        (state?.networks ?? []).flatMap { network in
            network.peers.map { peer in
                Device(
                    network: network.name, peer: peer,
                    paths: network.view?.peers.first { $0.key == peer.key }, local: network.view?.local,
                    viewAt: network.viewAt)
            }
        }
    }

    func device(_ id: DeviceID) -> Device? {
        devices.first { $0.id == id }
    }

    var devicesOnline: Int { devices.filter(\.isUp).count }

    /// The budgets of all networks added up; nil while no transport has one.
    var helperData: HelperData? {
        let budgets = (state?.networks ?? []).flatMap { $0.view?.local.transports ?? [] }.compactMap(\.budget)
        guard !budgets.isEmpty else { return nil }
        return HelperData(total: budgets.map(\.total).reduce(0, +), remaining: budgets.map(\.remaining).reduce(0, +))
    }

    private var switches: [TunnelState.Switch] { (state?.networks ?? []).flatMap(\.switches) }

    /// The switches of all networks that are registered, and how many there are.
    var switchesOnline: (online: Int, total: Int) {
        (switches.filter { $0.state == "registered" }.count, switches.count)
    }

    /// Whether some device is reached through a relay, mine or the device's.
    var relayInUse: Bool {
        devices.contains { $0.paths?.route?.kind == "own_relay" || $0.paths?.route?.kind == "peer_relay" }
    }

    /// "2 networks · 4 devices online".
    var onlineSummary: String {
        let networks = state?.networks.count ?? 0
        let devices = devicesOnline
        return "\(networks) \(networks == 1 ? "network" : "networks") · \(devices) \(devices == 1 ? "device" : "devices") online"
    }

    /// "2 of 2 switches online · 1 relay in use".
    var serversSummary: String {
        guard let state else { return "Not connected" }
        let switches = switches
        let online = switches.filter { $0.state == "registered" }.count
        var parts = [switches.isEmpty ? "No switches" : "\(online) of \(switches.count) \(switches.count == 1 ? "switch" : "switches") online"]
        let relays = state.networks.filter { $0.view?.local.relay != nil }.count
        if relays > 0 {
            let inUse = devices.contains { $0.paths?.route?.kind == "own_relay" }
            parts.append("\(relays) \(relays == 1 ? "relay" : "relays") \(inUse ? "in use" : "ready")")
        }
        return parts.joined(separator: " · ")
    }
}

extension ExitChoice {
    var title: String { network }

    /// "Italy · home" for the site `it/home`.
    var note: String {
        guard let site else { return "The exit of this network" }
        let parts = site.split(separator: "/", maxSplits: 1).map(String.init)
        let country = parts.first.map { Locale.current.localizedString(forRegionCode: $0) ?? $0.uppercased() } ?? site
        return parts.count > 1 ? "\(country) · \(parts[1])" : country
    }
}

/// A text with the time left until `ms` after `since`, counted down each second: `text` gets
/// "12 s" or "3 min", or nil once the time has passed.
struct Countdown: View {
    let ms: Int
    let since: Date
    let text: (String?) -> String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            Text(text(Self.left(until: since.addingTimeInterval(Double(ms) / 1000), at: context.date)))
        }
    }

    static func left(until end: Date, at now: Date) -> String? {
        let seconds = Int(end.timeIntervalSince(now).rounded(.up))
        if seconds <= 0 { return nil }
        return seconds < 90 ? "\(seconds) s" : "\((seconds + 30) / 60) min"
    }
}
