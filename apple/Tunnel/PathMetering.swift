import Foundation
import Network

/// Which interfaces of a path are expensive or constrained, for `vv_path_changed` (vv-05 §2.2).
///
/// `NWPath` reports `isExpensive` and `isConstrained` for the path as a whole. An interface counts
/// as metered when it is cellular, or when the monitor restricted to its type reports the path
/// expensive or constrained (a Wi-Fi link to a Personal Hotspot, Low Data Mode). Without such a
/// monitor, the default path stands in when it uses the interface's type.
struct PathMetering: Equatable {
    /// The path in use is expensive or constrained.
    var metered: Bool
    /// Interface name to metered, without the tunnel interface.
    var interfaces: [String: Bool]

    init(path: NWPath, perType: [NWInterface.InterfaceType: NWPath] = [:], excluding tunnel: String?) {
        metered = path.isExpensive || path.isConstrained
        interfaces = [:]
        for interface in path.availableInterfaces where interface.name != tunnel {
            let own = perType[interface.type].flatMap { $0.status == .satisfied ? $0 : nil }
            let byType = own.map { $0.isExpensive || $0.isConstrained }
                ?? (metered && path.usesInterfaceType(interface.type))
            interfaces[interface.name] = interface.type == .cellular || byType
        }
    }

    /// The JSON argument of `vv_path_changed`; `families` is `"v4"` and `"v6"` as far as known.
    func json(changed: Bool, families: [String]? = nil) -> String? {
        let list = interfaces.sorted { $0.key < $1.key }.map { ["name": $0.key, "metered": $0.value] as [String: Any] }
        var object: [String: Any] = ["changed": changed, "metered": metered, "interfaces": list]
        if let families { object["families"] = families }
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// A one-line description for the log.
    var summary: String {
        let names = interfaces.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value ? "metered" : "free")" }
        return "metered \(metered) [\(names.joined(separator: " "))]"
    }
}
