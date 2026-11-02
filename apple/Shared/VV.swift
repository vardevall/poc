import Foundation
import Vardevall

struct VVError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// A network of the tunnel: its name and its interface file.
struct NetworkConfig: Equatable {
    let name: String
    let config: String
}

/// The key, config and tunnel-settings helpers of `vardevall.h`.
enum VV {
    /// Calls `body` with the C strings of `strings`, which live for the call.
    static func withCStrings<R>(_ strings: [String], _ body: ([UnsafePointer<CChar>?]) -> R) -> R {
        let copies = strings.map { strdup($0) }
        defer { copies.forEach { free($0) } }
        return body(copies.map { $0.map { UnsafePointer($0) } })
    }


    private static func string(
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> UnsafeMutablePointer<CChar>?
    ) throws -> String {
        var err: UnsafeMutablePointer<CChar>?
        let out = body(&err)
        defer {
            vv_string_free(err)
            vv_string_free(out)
        }
        guard let out else {
            throw VVError(message: err.map { String(cString: $0) } ?? "unknown error")
        }
        return String(cString: out)
    }

    private static func decode<T: Decodable>(_ json: String) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(T.self, from: Data(json.utf8))
    }

    static func generateNodeKey() throws -> String {
        try string { vv_generate_node_key($0) }
    }

    static func generateNetworkSecret() throws -> String {
        try string { vv_generate_network_secret($0) }
    }

    static func publicKey(of secret: String) throws -> String {
        try string { vv_public_key(secret, $0) }
    }

    static func validate(config: String) throws -> ConfigSummary {
        try decode(try string { vv_validate_config(config, $0) })
    }

    static func tunnelSettings(config: String) throws -> TunnelSettings {
        try decode(try string { vv_tunnel_settings(config, $0) })
    }

    /// The exit in use (`vv_exit_in_use`), nil while none is.
    static func exitInUse(handle: OpaquePointer) throws -> ExitInUse? {
        let json = try string { vv_exit_in_use(handle, $0) }
        return json == "null" ? nil : try decode(json)
    }

    /// The settings of all `networks` in one tunnel; the first is the one whose address resolves.
    static func tunnelSettings(networks: [NetworkConfig]) throws -> TunnelSettings {
        try decode(try string { err in
            withCStrings(networks.map(\.name)) { names in
                withCStrings(networks.map(\.config)) { configs in
                    vv_tunnel_settings_networks(names, configs, networks.count, err)
                }
            }
        })
    }
}

/// The result of `vv_validate_config`.
struct ConfigSummary: Decodable, Equatable {
    struct Addrs: Decodable, Equatable {
        let ula: String
        let linkLocal: String
    }

    struct Peer: Decodable, Equatable, Identifiable {
        let publicKey: String
        let name: String?
        let addr: String
        var id: String { publicKey }
    }

    /// A `[[switch]]` entry: `host:port` as the `switch` event names it, and "pinned" or "web".
    struct Switch: Decodable, Equatable, Identifiable {
        let address: String
        let auth: String
        var id: String { address }
    }

    /// A `[[service]]` entry (vve-14).
    struct Service: Decodable, Equatable, Identifiable {
        let name: String
        let port: Int
        let proto: String
        var id: String { "\(name)/\(proto)" }
    }

    let publicKey: String
    let networkId: String
    let name: String?
    let addrs: Addrs
    let domain: String
    let mtu: Int
    let listenPort: Int
    let mdns: Bool
    let stunServers: Int
    let switches: [Switch]
    /// Whether the file names upstream resolvers, so that an exit in use does not receive the DNS.
    let forward: Bool
    /// The IPv4 address an exit gives this node when it is free.
    let ipv4Home: String
    let services: [Service]
    let peers: [Peer]
}

/// The result of `vv_tunnel_settings` and `vv_tunnel_settings_networks`.
struct TunnelSettings: Decodable {
    struct Addr: Decodable {
        let addr: String
        let prefix: Int
    }

    struct DNS: Decodable {
        let servers: [String]
        let matchDomains: [String]
    }

    let addrs: [Addr]
    let routes: [Addr]
    let mtu: Int
    let dns: DNS
}

/// The result of `vv_exit_in_use`: the exit that carries the device's traffic.
struct ExitInUse: Decodable, Equatable {
    let network: String
    let site: String
    /// The exit's node key.
    let via: String
    /// This node's address in the site.
    let addr: String
    /// The IPv4 address the exit gave this node; nil when it carries no IPv4.
    let ipv4: String?
}
