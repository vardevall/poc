import Foundation

/// What the extension reports to the app through `sendProviderMessage`.
struct TunnelState: Codable, Equatable {
    struct Peer: Codable, Equatable, Identifiable {
        let key: String
        var addr: String
        var name: String?
        var state: String
        var id: String { key }
    }

    /// A switch of the config and where its registration stands (vv-04 §4.6).
    struct Switch: Codable, Equatable, Identifiable {
        let address: String
        /// "pinned" or "web".
        var auth: String?
        var state: String
        var reason: String?
        var id: String { address }
    }

    /// A line of the log; `network` is nil for the tunnel's own.
    struct Line: Codable, Equatable {
        var network: String?
        var text: String
    }

    /// One network of the tunnel; the events of the engine are filed by their `network`.
    struct Network: Codable, Equatable, Identifiable {
        let name: String
        var engine = "stopped"
        var port: Int?
        var switches: [Switch] = []
        var peers: [Peer] = []
        /// The latest `view` event.
        var view: PathView?
        /// When the extension received it: the times to go in it count from then.
        var viewAt: Date?
        var id: String { name }
    }

    /// The exit the user chose and what stands behind it.
    struct Exit: Codable, Equatable {
        let network: String
        /// The site in use, once an exit is chosen.
        var site: String?
        /// The exit chosen, by name or key; nil while the site has no live exit.
        var via: String?
    }

    /// In the order of the tunnel's networks, the first being the default one.
    var networks: [Network] = []
    var log: [Line] = []
    /// Nil while no exit is in use.
    var exit: Exit?

    /// The tunnel's own lines.
    var tunnelLines: [String] { log.filter { $0.network == nil }.map(\.text) }

    /// The lines of network `name`, followed by the tunnel's own when `withTunnel`.
    func lines(of name: String, withTunnel: Bool) -> [String] {
        log.filter { $0.network == name || (withTunnel && $0.network == nil) }.map(\.text)
    }
}
