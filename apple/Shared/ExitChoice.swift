import Foundation

/// The user's choice to send the device's traffic through the exit of a network.
/// Runtime state of the host: it holds nothing secret and is kept in `providerConfiguration`.
struct ExitChoice: Codable, Equatable, Hashable {
    var network: String
    /// A site such as `it/home`; nil is the network's only site.
    var site: String?

    init(network: String, site: String? = nil) {
        self.network = network
        self.site = site
    }

    /// The choice stored in `providerConfiguration`.
    init?(configuration: Any?) {
        guard let entry = configuration as? [String: Any], let network = entry[Shared.networkNameKey] as? String
        else { return nil }
        self.init(network: network, site: entry[Shared.exitSiteKey] as? String)
    }

    var configuration: [String: Any] {
        var entry: [String: Any] = [Shared.networkNameKey: network]
        if let site { entry[Shared.exitSiteKey] = site }
        return entry
    }
}

/// A request from the app to the extension to use the exit of a network, or none, sent with
/// `sendProviderMessage`; the reply is a `ServiceReply`.
struct ExitRequest: Codable, Equatable {
    var op = "exit"
    var exit: ExitChoice?
}

/// What an exit in use adds to the tunnel settings.
struct ExitRouting: Equatable {
    /// The private IPv4 ranges that stay off the tunnel, with the exit in use or waiting for one
    ///: the device reaches them as it would with no exit.
    static let privateIPv4: [(address: String, mask: String)] = [
        ("10.0.0.0", "255.0.0.0"),
        ("172.16.0.0", "255.240.0.0"),
        ("192.168.0.0", "255.255.0.0"),
        ("169.254.0.0", "255.255.0.0"),
    ]

    /// This node's address in the site of the exit chosen; nil while none is.
    var siteAddress: String?
    /// The IPv4 address of the tunnel, with the default route: the one the exit gave, or the home
    /// address while none did.
    var ipv4Address: String
    /// Whether every name goes to the node's resolver, which relays it to the exit.
    var dnsAll: Bool

    /// The routing for `choice` given the exit `inUse` and the summary of the chosen network; nil
    /// without a choice. With a choice and no exit, or an exit without IPv4, the default routes
    /// stay, so that traffic is dropped, not sent around the tunnel.
    static func wanted(_ choice: ExitChoice?, inUse: ExitInUse?, network: ConfigSummary?) -> ExitRouting? {
        guard choice != nil, let network else { return nil }
        return ExitRouting(
            siteAddress: inUse?.addr, ipv4Address: inUse?.ipv4 ?? network.ipv4Home, dnsAll: !network.forward)
    }
}
