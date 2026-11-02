import Foundation

/// A request from the app to the extension about vve-14 services, sent with `sendProviderMessage`.
struct ServiceRequest: Codable, Equatable {
    /// "announce", "withdraw" or "providers".
    var op: String
    /// The network the service belongs to; nil for the first.
    var network: String?
    var name: String
    var port: Int?
    /// "tcp" or "udp".
    var proto: String?
}

/// A provider of a service, as `vv_providers` reports it.
struct ServiceProvider: Codable, Equatable, Identifiable {
    var key: String
    var addr: String
    var name: String?
    var port: Int
    var proto: String
    var live: Bool
    var id: String { "\(key)/\(port)/\(proto)" }
}

/// The extension's answer to a `ServiceRequest`.
struct ServiceReply: Codable, Equatable {
    var error: String?
    /// For "withdraw": whether a service of that name existed.
    var withdrawn: Bool?
    /// For "providers".
    var providers: [ServiceProvider]?
}
