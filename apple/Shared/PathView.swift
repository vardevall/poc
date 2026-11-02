import Foundation

/// The engine's `view` event (vardevall.h): what the node believes about its paths, inferred locally.
struct PathView: Codable, Equatable {
    struct Nat: Codable, Equatable {
        /// "unknown", "punchable", "symmetric" or "udp_blocked".
        var nat: String
        var addr: String?
    }

    struct Relay: Codable, Equatable {
        var addr: String
        var server: String
        /// "udp" or "tls".
        var transport: String
    }

    struct Switch: Codable, Equatable, Identifiable {
        var index: Int
        var address: String
        /// "pinned" for an address known by its key, "web" for a web address (vv-04 §2.1).
        var auth: String?
        var state: String
        var reason: String?
        var transport: String?
        /// While disconnected, the milliseconds from the view to the next attempt.
        var retryIn: Int?
        var id: Int { index }

        enum CodingKeys: String, CodingKey {
            case index, address, auth, state, reason, transport
            case retryIn = "retry_in_ms"
        }
    }

    /// Bytes counted on a transport or on a peer's routes.
    struct Meter: Codable, Equatable {
        var sent: UInt64
        var received: UInt64
    }

    /// The volume a switch or TURN server lets a transport carry.
    struct Budget: Codable, Equatable {
        var total: UInt64
        var remaining: UInt64
        /// "switch" or "turn".
        var source: String
        /// "plenty", "half", "low" or "exhausted".
        var level: String
    }

    struct Transport: Codable, Equatable, Identifiable {
        /// "udp", "turn" or the `host:port` of a switch.
        var name: String
        /// False once the budget is exhausted, or while the transport is not ready.
        var usable: Bool
        var meter: Meter
        var budget: Budget?
        var id: String { name }
    }

    struct Local: Codable, Equatable {
        var ipv6: Nat
        var ipv4: Nat
        var relay: Relay?
        var switches: [Switch]
        var transports: [Transport]
    }

    struct Route: Codable, Equatable {
        /// "lan", "internet", "peer_relay", "own_relay" or "switch".
        var kind: String
        var metered: Bool
        /// The route does not meet the delivery class of tunnel traffic (vv-05 §4.7).
        var degraded: Bool?
        var addr: String?
        var `switch`: Int?
    }

    /// One route of a link, from the trace the node keeps: the active one carries data.
    struct TraceRoute: Codable, Equatable, Identifiable {
        /// "lan", "internet", "peer_relay", "own_relay" or "switch".
        var kind: String
        var addr: String?
        var `switch`: Int?
        /// "dormant", "candidate", "verified", "suspect" or "failed".
        var status: String
        /// The smoothed round trip in milliseconds, once a ping on the route was answered.
        var rtt: Int?
        var active: Bool
        var metered: Bool
        /// A failed route that could still win: the milliseconds from the view to its next ping.
        var retryIn: Int?
        /// A failed route learned from the peer's frames: the milliseconds until it is dropped.
        var forgetIn: Int?
        var id: String { "\(kind)/\(addr ?? "")/\(`switch`.map(String.init) ?? "")" }

        enum CodingKeys: String, CodingKey {
            case kind, addr, `switch`, status, active, metered
            case rtt = "rtt_ms"
            case retryIn = "retry_in_ms"
            case forgetIn = "forget_in_ms"
        }
    }

    struct Candidate: Codable, Equatable, Hashable {
        var kind: String
        var addr: String
        /// Whether the provider found it on this link or host; nil from an older engine.
        var local: Bool?
        /// Whether it was gathered on an expensive or constrained interface, or is a relay.
        var metered: Bool?
    }

    struct Peer: Codable, Equatable, Identifiable {
        var key: String
        var addr: String
        var name: String?
        /// "idle", "connecting", "up" or "down".
        var state: String
        /// Nil while the link is not up or has no route.
        var route: Route?
        /// "unknown", "punchable" or "relay_only".
        var nat: String
        var candidates: [Candidate]
        var switches: [Int]
        var probing: Bool
        var fallback: Bool
        /// Nil while the link has no session.
        var meter: Meter?
        /// The smoothed round trip of the active route in milliseconds; nil from an older engine.
        var rtt: Int?
        /// Every route of the link, best first; nil from an older engine, empty while the link is
        /// not up.
        var routes: [TraceRoute]?
        var id: String { key }

        enum CodingKeys: String, CodingKey {
            case key, addr, name, state, route, nat, candidates, switches, probing, fallback, meter, routes
            case rtt = "rtt_ms"
        }
    }

    /// A site some peer offered an exit for, live or not.
    struct Site: Codable, Equatable, Identifiable {
        /// A country code and an optional name: "it" or "it/home".
        var site: String
        var id: String { site }
    }

    var local: Local
    var peers: [Peer]
    var sites: [Site]?
}

extension PathView.Nat {
    /// "Open", "Symmetric", "No UDP" or "Unknown".
    var word: String {
        switch nat {
        case "punchable": "Open"
        case "symmetric": "Symmetric"
        case "udp_blocked": "No UDP"
        default: "Unknown"
        }
    }
}

extension PathView.Meter {
    /// "↑ 1.2 MB  ↓ 340 KB".
    var summary: String {
        "↑ \(Self.bytes(sent))  ↓ \(Self.bytes(received))"
    }

    static func bytes(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: n), countStyle: .file)
    }
}

extension PathView.Transport {
    /// What the user knows the transport as.
    var title: String {
        switch name {
        case "udp": return "Direct (UDP)"
        case "turn": return "TURN relay"
        default: return "Switch \(name)"
        }
    }
}
