import Darwin
import Foundation
import Network

/// Watches the default path and one path per interface type, and reports changes through
/// `vv_path_changed` (vv-05 §4.6).
///
/// `NWPathMonitor` reports `isExpensive` for the default path only, so a monitor restricted to each
/// interface type supplies the metering of the interfaces the default path does not use.
final class PathWatcher {
    /// One report for `Engine.pathChanged`.
    struct Report {
        let json: String?
        let note: String
    }

    private static let types: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet]

    private let queue = DispatchQueue(label: "net.vardevall.path")
    private let tunnel: String?
    private let deliver: (Report) -> Void
    private var monitors: [NWPathMonitor] = []
    private var defaultPath: NWPath?
    private var perType: [NWInterface.InterfaceType: NWPath] = [:]
    private var lastSignature: String?
    private var lastMetering: PathMetering?
    private var lastAddresses: [String: Set<String>] = [:]

    /// `tunnel` is the tunnel's own interface, which is ignored.
    init(excluding tunnel: String?, deliver: @escaping (Report) -> Void) {
        self.tunnel = tunnel
        self.deliver = deliver
    }

    func start() {
        let main = NWPathMonitor()
        main.pathUpdateHandler = { [weak self] path in
            self?.defaultPath = path
            self?.evaluate()
        }
        main.start(queue: queue)
        monitors.append(main)
        for type in Self.types {
            let monitor = NWPathMonitor(requiredInterfaceType: type)
            monitor.pathUpdateHandler = { [weak self] path in
                self?.perType[type] = path
                self?.evaluate()
            }
            monitor.start(queue: queue)
            monitors.append(monitor)
        }
    }

    func stop() {
        monitors.forEach { $0.cancel() }
        monitors.removeAll()
    }

    private func evaluate() {
        guard let path = defaultPath else { return }
        let names = path.availableInterfaces.map(\.name).filter { $0 != tunnel }.sorted()
        let signature = "\(path.status) \(names.joined(separator: ",")) v4=\(path.supportsIPv4) v6=\(path.supportsIPv6)"
        let metering = PathMetering(path: path, perType: perType, excluding: tunnel)
        let changed = lastSignature != nil && lastSignature != signature
        let previous = lastMetering
        let first = lastSignature == nil
        lastSignature = signature
        lastMetering = metering
        guard changed || metering != previous else { return }

        let addresses = localAddresses()
        let families = changed ? Self.changedFamilies(from: lastAddresses, to: addresses) : nil
        if changed || first { lastAddresses = addresses }
        var note = "metering: \(metering.summary)"
        if changed { note = "path changed: \(signature); \(note)" }
        deliver(Report(json: metering.json(changed: changed, families: families), note: note))
    }

    /// The families whose address sets differ; `nil` when none does or nothing was known before.
    private static func changedFamilies(from old: [String: Set<String>], to new: [String: Set<String>]) -> [String]? {
        guard !old.isEmpty else { return nil }
        let families = ["v4", "v6"].filter { old[$0] != new[$0] }
        return families.isEmpty ? nil : families
    }

    /// Addresses of the running interfaces except loopback and the tunnel, by family.
    private func localAddresses() -> [String: Set<String>] {
        var out: [String: Set<String>] = ["v4": [], "v6": []]
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return out }
        defer { freeifaddrs(list) }
        for ifa in sequence(first: list, next: { $0?.pointee.ifa_next }) {
            guard let entry = ifa?.pointee, let sa = entry.ifa_addr else { continue }
            let flags = Int32(entry.ifa_flags)
            let name = String(cString: entry.ifa_name)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, name != tunnel else { continue }
            let family: String
            switch Int32(sa.pointee.sa_family) {
            case AF_INET: family = "v4"
            case AF_INET6: family = "v6"
            default: continue
            }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            out[family, default: []].insert("\(name)/\(String(cString: host))")
        }
        return out
    }
}
