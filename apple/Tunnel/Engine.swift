import Foundation
import Vardevall

/// Owns a `VvHandle` for all the networks of the tunnel and routes its callbacks to Swift closures.
final class Engine {
    struct Sinks {
        let packets: ([Data]) -> Void
        let event: (String) -> Void
        let mdns: (String) -> Void
    }

    private let sinks: Sinks
    private let lock = NSLock()
    private var handle: OpaquePointer?

    init(sinks: Sinks) {
        self.sinks = sinks
    }

    deinit { stop() }

    /// Starts the engine for `networks`, the first being the default one (`vv_start_networks`).
    func start(networks: [NetworkConfig]) throws {
        var err: UnsafeMutablePointer<CChar>?
        defer { vv_string_free(err) }
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        let h = VV.withCStrings(networks.map(\.name)) { names in
            VV.withCStrings(networks.map(\.config)) { configs in
                Self.startNetworks(names, configs, networks.count, ctx, &err)
            }
        }
        guard let h else {
            throw VVError(message: err.map { String(cString: $0) } ?? "engine failed to start")
        }
        lock.lock()
        handle = h
        lock.unlock()
    }

    private static func startNetworks(
        _ names: [UnsafePointer<CChar>?], _ configs: [UnsafePointer<CChar>?], _ count: Int,
        _ ctx: UnsafeMutableRawPointer, _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
    ) -> OpaquePointer? {
        vv_start_networks(
            names, configs, count,
            { ctx, packets, lens, n in
                guard let ctx, let packets, let lens else { return }
                let batch = (0..<n).compactMap { i in
                    packets[i].map { Data(bytes: $0, count: lens[i]) }
                }
                Unmanaged<Engine>.fromOpaque(ctx).takeUnretainedValue().sinks.packets(batch)
            },
            { ctx, json in
                guard let ctx, let json else { return }
                Unmanaged<Engine>.fromOpaque(ctx).takeUnretainedValue().sinks.event(String(cString: json))
            },
            { ctx, json in
                guard let ctx, let json else { return }
                Unmanaged<Engine>.fromOpaque(ctx).takeUnretainedValue().sinks.mdns(String(cString: json))
            },
            ctx,
            err
        )
    }

    /// Hands the engine the packets of one `readPackets` batch (`vv_packets_in`).
    func packetsIn(_ packets: [Data]) {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return }
        let lens = packets.map(\.count)
        let joined = packets.reduce(into: [UInt8]()) { $0.append(contentsOf: $1) }
        joined.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            var starts: [UnsafePointer<UInt8>?] = []
            var offset = 0
            for len in lens {
                starts.append(base + offset)
                offset += len
            }
            vv_packets_in(handle, starts, lens, packets.count)
        }
    }

    /// Reports a path update; `json` is the argument of `vv_path_changed`.
    func pathChanged(_ json: String?) {
        lock.lock()
        defer { lock.unlock() }
        if let handle { vv_path_changed(handle, json) }
    }

    /// Announces a service to the peers of `network`, nil for the first (`vv_announce`).
    func announce(network: String?, name: String, port: UInt16, proto: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        defer { vv_string_free(err) }
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw VVError(message: "engine is not running") }
        guard vv_announce(handle, network, name, port, proto, &err) == 0 else {
            throw VVError(message: err.map { String(cString: $0) } ?? "announce failed")
        }
    }

    /// Withdraws the services of that name in `network` (`vv_withdraw`); whether there were any.
    func withdraw(network: String?, name: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return false }
        return vv_withdraw(handle, network, name) == 1
    }

    /// The JSON list of providers of a service in `network` (`vv_providers`).
    func providers(network: String?, name: String) throws -> String {
        var err: UnsafeMutablePointer<CChar>?
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw VVError(message: "engine is not running") }
        let out = vv_providers(handle, network, name, &err)
        defer {
            vv_string_free(err)
            vv_string_free(out)
        }
        guard let out else { throw VVError(message: err.map { String(cString: $0) } ?? "providers failed") }
        return String(cString: out)
    }

    /// Makes `choice` carry the device's traffic outside the overlay, or none (`vv_set_exit`).
    func setExit(_ choice: ExitChoice?) throws {
        var err: UnsafeMutablePointer<CChar>?
        defer { vv_string_free(err) }
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw VVError(message: "engine is not running") }
        guard vv_set_exit(handle, choice?.network, choice?.site, &err) == 0 else {
            throw VVError(message: err.map { String(cString: $0) } ?? "choosing the exit failed")
        }
    }

    /// Gives `network` back the offers of an earlier `exits` event (`vv_remember_exits`).
    func rememberExits(network: String, offers json: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        defer { vv_string_free(err) }
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw VVError(message: "engine is not running") }
        guard vv_remember_exits(handle, network, json, &err) == 0 else {
            throw VVError(message: err.map { String(cString: $0) } ?? "remembering the exits failed")
        }
    }

    /// The exit that carries the traffic now, nil while none is chosen or live (`vv_exit_in_use`).
    func exitInUse() throws -> ExitInUse? {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return nil }
        return try VV.exitInUse(handle: handle)
    }

    func mdnsEvent(_ json: String) {
        lock.lock()
        defer { lock.unlock() }
        if let handle { vv_mdns_event(handle, json) }
    }

    /// Stops the engine; none of the sinks run afterwards.
    func stop() {
        lock.lock()
        defer { lock.unlock() }
        guard let h = handle else { return }
        handle = nil
        vv_stop(h)
    }
}
