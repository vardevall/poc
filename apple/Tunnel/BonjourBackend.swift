import Darwin
import Foundation
import OSLog
import dnssd

/// Carries out the engine's mDNS requests (vv-09 §2.1) with `dns_sd`: registration with the
/// engine's own UDP port, and browsing with resolution to addresses.
final class BonjourBackend {
    private let queue = DispatchQueue(label: "net.vardevall.bonjour")
    private let log = Logger(subsystem: Shared.subsystem, category: "bonjour")
    private let deliver: (String) -> Void
    private let excludedInterface: UInt32

    private struct Registration {
        let ref: DNSServiceRef
        let type: String
        let port: Int
        var txt: [UInt8]
    }

    private var registrations: [String: Registration] = [:]
    private var ownNames: Set<String> = []
    private var browse: DNSServiceRef?
    private var services: [String: [UInt32: Service]] = [:]
    private var closed = false

    /// `deliver` receives browse results as `vv_mdns_event` JSON; `excludedInterface` is the
    /// tunnel's own interface index, whose results are dropped.
    init(excludedInterface: UInt32, deliver: @escaping (String) -> Void) {
        self.excludedInterface = excludedInterface
        self.deliver = deliver
    }

    /// Handles one `vv_mdns_cb` request.
    func handle(_ json: String) {
        queue.async { [self] in
            guard !closed,
                  let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
                  let op = obj["op"] as? String
            else { return }
            switch op {
            case "register": register(obj)
            case "unregister": unregister(obj["instance"] as? String ?? "")
            case "browse": startBrowse()
            case "stop_browse": stopBrowse()
            default: log.error("unknown mDNS op \(op, privacy: .public)")
            }
        }
    }

    /// Releases every registration and browse.
    func shutdown() {
        queue.sync {
            closed = true
            registrations.values.forEach { DNSServiceRefDeallocate($0.ref) }
            registrations.removeAll()
            stopBrowse()
        }
    }

    private func register(_ obj: [String: Any]) {
        guard let instance = obj["instance"] as? String,
              let type = obj["type"] as? String,
              let port = obj["port"] as? Int, (0...65535).contains(port)
        else { return log.error("malformed register request") }
        let txt = Self.encodeTXT(obj["txt"] as? [String: String] ?? [:])
        if let current = registrations[instance], current.type == type, current.port == port,
           updateTXT(instance, current, txt) {
            return
        }
        unregister(instance)
        var ref: DNSServiceRef?
        let error = txt.withUnsafeBufferPointer { buf in
            DNSServiceRegister(
                &ref, 0, UInt32(kDNSServiceInterfaceIndexAny), instance, type, nil, nil,
                UInt16(port).bigEndian, UInt16(buf.count), buf.baseAddress,
                { _, flags, error, name, _, _, ctx in
                    guard let ctx else { return }
                    let backend = Unmanaged<BonjourBackend>.fromOpaque(ctx).takeUnretainedValue()
                    backend.registered(flags: flags, error: error, name: name.map { String(cString: $0) })
                },
                Unmanaged.passUnretained(self).toOpaque())
        }
        guard error == kDNSServiceErr_NoError, let ref else {
            return log.error("DNSServiceRegister failed: \(error)")
        }
        DNSServiceSetDispatchQueue(ref, queue)
        registrations[instance] = Registration(ref: ref, type: type, port: port, txt: txt)
        ownNames.insert(instance)
    }

    /// Replaces the TXT record of a live registration, so that the service is not withdrawn and
    /// announced again when only the sealed node key changes. Returns whether the record is current.
    private func updateTXT(_ instance: String, _ current: Registration, _ txt: [UInt8]) -> Bool {
        guard txt != current.txt else { return true }
        let error = txt.withUnsafeBufferPointer {
            DNSServiceUpdateRecord(current.ref, nil, 0, UInt16(txt.count), $0.baseAddress, 0)
        }
        guard error == kDNSServiceErr_NoError else {
            log.error("DNSServiceUpdateRecord failed: \(error)")
            return false
        }
        registrations[instance]?.txt = txt
        return true
    }

    private func registered(flags: DNSServiceFlags, error: DNSServiceErrorType, name: String?) {
        guard error == kDNSServiceErr_NoError, flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
              let name else {
            if error != kDNSServiceErr_NoError { log.error("registration error \(error)") }
            return
        }
        ownNames.insert(name)
        log.info("registered \(name, privacy: .public)")
    }

    private func unregister(_ instance: String) {
        if let registration = registrations.removeValue(forKey: instance) {
            DNSServiceRefDeallocate(registration.ref)
        }
        ownNames.remove(instance)
    }

    private func startBrowse() {
        guard browse == nil else { return }
        var ref: DNSServiceRef?
        let error = DNSServiceBrowse(
            &ref, 0, UInt32(kDNSServiceInterfaceIndexAny), "_vardevall._udp", nil,
            { _, flags, index, error, name, _, _, ctx in
                guard let ctx, error == kDNSServiceErr_NoError, let name else { return }
                let backend = Unmanaged<BonjourBackend>.fromOpaque(ctx).takeUnretainedValue()
                let added = flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0
                backend.browseResult(added: added, name: String(cString: name), index: index)
            },
            Unmanaged.passUnretained(self).toOpaque())
        guard error == kDNSServiceErr_NoError, let ref else {
            return log.error("DNSServiceBrowse failed: \(error)")
        }
        DNSServiceSetDispatchQueue(ref, queue)
        browse = ref
    }

    private func stopBrowse() {
        if let ref = browse { DNSServiceRefDeallocate(ref) }
        browse = nil
        services.values.forEach { $0.values.forEach { $0.stop() } }
        services.removeAll()
    }

    private func browseResult(added: Bool, name: String, index: UInt32) {
        if added {
            guard index != excludedInterface, !ownNames.contains(name), services[name]?[index] == nil
            else { return }
            let service = Service(owner: self, name: name, index: index)
            services[name, default: [:]][index] = service
            service.start()
        } else {
            services[name]?.removeValue(forKey: index)?.stop()
            if services[name]?.isEmpty == true {
                services.removeValue(forKey: name)
                emit(["op": "lost", "instance": name])
            }
        }
    }

    fileprivate func emit(_ event: [String: Any]) {
        guard !closed, let data = try? JSONSerialization.data(withJSONObject: event),
              let text = String(data: data, encoding: .utf8) else { return }
        deliver(text)
    }

    fileprivate func interfaceIsExcluded(_ index: UInt32) -> Bool { index == excludedInterface }

    static func encodeTXT(_ txt: [String: String]) -> [UInt8] {
        var out: [UInt8] = []
        for (key, value) in txt.sorted(by: { $0.key < $1.key }) {
            let entry = Array("\(key)=\(value)".utf8.prefix(255))
            out.append(UInt8(entry.count))
            out.append(contentsOf: entry)
        }
        return out.isEmpty ? [0] : out
    }

    static func decodeTXT(_ bytes: [UInt8]) -> [String: String] {
        var out: [String: String] = [:]
        var i = 0
        while i < bytes.count {
            let n = Int(bytes[i])
            let end = min(i + 1 + n, bytes.count)
            let text = String(decoding: bytes[(i + 1)..<end], as: UTF8.self)
            if let eq = text.firstIndex(of: "=") {
                out[String(text[..<eq])] = String(text[text.index(after: eq)...])
            } else if !text.isEmpty {
                out[text] = ""
            }
            i = end
        }
        return out
    }

    fileprivate static func numericHost(_ sa: UnsafePointer<sockaddr>) -> String? {
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var copy = sockaddr_storage()
        memcpy(&copy, sa, Int(sa.pointee.sa_len))
        let rc = withUnsafePointer(to: &copy) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t($0.pointee.sa_len), &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard rc == 0 else { return nil }
        let host = String(cString: buf)
        return host.split(separator: "%").first.map(String.init)
    }

    /// One discovered instance on one interface: resolves its target and tracks its addresses.
    private final class Service {
        unowned let owner: BonjourBackend
        let name: String
        let index: UInt32
        private var resolve: DNSServiceRef?
        private var addrInfo: DNSServiceRef?
        private var host: String?
        private var port = 0
        private var txt: [String: String] = [:]
        private var addrs: Set<String> = []

        init(owner: BonjourBackend, name: String, index: UInt32) {
            self.owner = owner
            self.name = name
            self.index = index
        }

        func start() {
            var ref: DNSServiceRef?
            let error = DNSServiceResolve(
                &ref, 0, index, name, "_vardevall._udp", "local.",
                { _, _, _, error, _, host, port, txtLen, txt, ctx in
                    guard let ctx, error == kDNSServiceErr_NoError, let host else { return }
                    let service = Unmanaged<Service>.fromOpaque(ctx).takeUnretainedValue()
                    let bytes = txt.map { Array(UnsafeBufferPointer(start: $0, count: Int(txtLen))) } ?? []
                    service.resolved(host: String(cString: host), port: Int(UInt16(bigEndian: port)), txt: bytes)
                },
                Unmanaged.passUnretained(self).toOpaque())
            guard error == kDNSServiceErr_NoError, let ref else {
                return owner.log.error("DNSServiceResolve failed: \(error)")
            }
            DNSServiceSetDispatchQueue(ref, owner.queue)
            resolve = ref
        }

        func stop() {
            if let ref = resolve { DNSServiceRefDeallocate(ref) }
            if let ref = addrInfo { DNSServiceRefDeallocate(ref) }
            resolve = nil
            addrInfo = nil
        }

        private func resolved(host: String, port: Int, txt: [UInt8]) {
            self.port = port
            self.txt = BonjourBackend.decodeTXT(txt)
            if host != self.host {
                self.host = host
                if let ref = addrInfo { DNSServiceRefDeallocate(ref) }
                addrs.removeAll()
                var ref: DNSServiceRef?
                let error = DNSServiceGetAddrInfo(
                    &ref, 0, index,
                    DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6), host,
                    { _, flags, ifindex, error, _, address, _, ctx in
                        guard let ctx, error == kDNSServiceErr_NoError, let address else { return }
                        let service = Unmanaged<Service>.fromOpaque(ctx).takeUnretainedValue()
                        let added = flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0
                        service.address(added: added, ifindex: ifindex, sa: address)
                    },
                    Unmanaged.passUnretained(self).toOpaque())
                guard error == kDNSServiceErr_NoError, let ref else {
                    return owner.log.error("DNSServiceGetAddrInfo failed: \(error)")
                }
                DNSServiceSetDispatchQueue(ref, owner.queue)
                addrInfo = ref
            }
            report()
        }

        private func address(added: Bool, ifindex: UInt32, sa: UnsafePointer<sockaddr>) {
            guard !owner.interfaceIsExcluded(ifindex), let text = BonjourBackend.numericHost(sa) else { return }
            if added { addrs.insert(text) } else { addrs.remove(text) }
            report()
        }

        private func report() {
            guard !addrs.isEmpty, port != 0 else { return }
            owner.emit([
                "op": "found", "instance": name, "txt": txt, "port": port,
                "addrs": addrs.sorted(), "ifindex": Int(index),
            ])
        }
    }
}
