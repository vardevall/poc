import Foundation
import Network
import NetworkExtension
import OSLog

/// Hosts the engine: applies the tunnel settings, pumps packets and runs the Bonjour backend.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: Shared.subsystem, category: "tunnel")
    private let stateLock = NSLock()
    private var state = TunnelState()
    /// The link state and the route of each peer, as the last events said, by network and key;
    /// guarded by `stateLock`.
    private var links: [PeerID: String] = [:]
    private var routes: [PeerID: String] = [:]
    private var engine: Engine?
    private var bonjour: BonjourBackend?
    private var watcher: PathWatcher?
    private let memory = MemoryProbe()

    /// The exit the user chose and what was applied for it; guarded by `exitLock`, which is never
    /// held together with `stateLock`.
    private let exitLock = NSLock()
    private var choice: ExitChoice?
    private var baseSettings: TunnelSettings?
    private var summaries: [String: ConfigSummary] = [:]
    private var applied: ExitRouting?
    private var refreshing = false
    private var refreshAgain = false

    private struct PeerID: Hashable {
        let network: String
        let key: String
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Task {
            do {
                try await start()
                completionHandler(nil)
            } catch {
                log.error("start failed: \(error.localizedDescription, privacy: .public)")
                shutdown()
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stop, reason \(reason.rawValue)")
        shutdown()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if messageData == Shared.stateRequest {
            return completionHandler?(try? JSONEncoder().encode(snapshot())) ?? ()
        }
        if let request = try? JSONDecoder().decode(ExitRequest.self, from: messageData), request.op == "exit" {
            return completionHandler?(try? JSONEncoder().encode(reply(to: request))) ?? ()
        }
        guard let request = try? JSONDecoder().decode(ServiceRequest.self, from: messageData) else {
            return completionHandler?(nil) ?? ()
        }
        completionHandler?(try? JSONEncoder().encode(reply(to: request)))
    }

    private func reply(to request: ExitRequest) -> ServiceReply {
        do {
            try choose(request.exit)
            return ServiceReply()
        } catch {
            return ServiceReply(error: error.localizedDescription)
        }
    }

    private func reply(to request: ServiceRequest) -> ServiceReply {
        guard let engine else { return ServiceReply(error: "engine is not running") }
        do {
            switch request.op {
            case "announce":
                guard let port = request.port.flatMap(UInt16.init(exactly:)) else {
                    return ServiceReply(error: "invalid port")
                }
                try engine.announce(network: request.network, name: request.name, port: port, proto: request.proto ?? "tcp")
                return ServiceReply()
            case "withdraw":
                return ServiceReply(withdrawn: engine.withdraw(network: request.network, name: request.name))
            case "providers":
                let json = try engine.providers(network: request.network, name: request.name)
                return ServiceReply(providers: try JSONDecoder().decode([ServiceProvider].self, from: Data(json.utf8)))
            default:
                return ServiceReply(error: "unknown operation \(request.op)")
            }
        } catch {
            return ServiceReply(error: error.localizedDescription)
        }
    }

    private func start() async throws {
        memory.start()
        let networks = try storedNetworks()
        let settings = try VV.tunnelSettings(networks: networks)
        seedState(networks)
        let stored = storedExit(among: networks)
        let summary = Dictionary(uniqueKeysWithValues: try networks.map { ($0.name, try VV.validate(config: $0.config)) })
        let routing = ExitRouting.wanted(stored, inUse: nil, network: stored.flatMap { summary[$0.network] })
        exitLock.withLock {
            choice = stored
            baseSettings = settings
            summaries = summary
            applied = routing
        }

        try await setTunnelNetworkSettings(try Self.networkSettings(settings, routing: routing))
        let tunnelInterface = Self.interface(holding: settings.addrs[0].addr)
        log.info("tunnel interface \(tunnelInterface?.name ?? "?", privacy: .public)")

        let bonjour = BonjourBackend(excludedInterface: tunnelInterface?.index ?? 0) { [weak self] json in
            self?.engine?.mdnsEvent(json)
        }
        let engine = Engine(sinks: .init(
            packets: { [weak self] batch in
                self?.packetFlow.writePackets(batch, withProtocols: batch.map(Self.family))
            },
            event: { [weak self] json in self?.engineEvent(json) },
            mdns: { [weak bonjour] json in bonjour?.handle(json) }))
        self.bonjour = bonjour
        self.engine = engine
        try engine.start(networks: networks)
        rememberExits(networks, engine)
        if let stored {
            do {
                try engine.setExit(stored)
            } catch {
                note("the exit \(stored.network) is not used: \(error.localizedDescription)")
                exitLock.withLock { choice = nil }
            }
            refreshExit()
        }

        monitorPaths(excluding: tunnelInterface?.name)
        readPackets()
    }

    private func seedState(_ networks: [NetworkConfig]) {
        stateLock.lock()
        defer { stateLock.unlock() }
        state.networks = networks.map { TunnelState.Network(name: $0.name) }
    }

    /// The networks the app saved, from the names and references in `providerConfiguration`. A
    /// configuration saved before networks had names holds one reference, the network `vardevall`.
    private func storedNetworks() throws -> [NetworkConfig] {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configuration = proto.providerConfiguration
        else { throw VVError(message: "missing tunnel configuration") }
        if let list = configuration[Shared.networksKey] as? [[String: Any]] {
            let networks = try list.map { entry -> NetworkConfig in
                guard let name = entry[Shared.networkNameKey] as? String,
                      let reference = entry[Shared.networkReferenceKey] as? Data
                else { throw VVError(message: "malformed network list") }
                return NetworkConfig(name: name, config: try ConfigStore.load(reference: reference))
            }
            if !networks.isEmpty { return networks }
        }
        if let reference = configuration[Shared.legacyConfigReferenceKey] as? Data {
            return [NetworkConfig(name: Shared.defaultNetwork, config: try ConfigStore.load(reference: reference))]
        }
        throw VVError(message: "no networks configured")
    }

    /// The exit saved in `providerConfiguration`, if it names a network of the tunnel.
    private func storedExit(among networks: [NetworkConfig]) -> ExitChoice? {
        let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let saved = ExitChoice(configuration: configuration?[Shared.exitKey]),
              networks.contains(where: { $0.name == saved.network })
        else { return nil }
        return saved
    }

    /// Gives each network the exits it remembered at its last run, so that a use reaches them
    /// first.
    private func rememberExits(_ networks: [NetworkConfig], _ engine: Engine) {
        for network in networks {
            guard let json = UserDefaults.standard.string(forKey: Shared.exitsDefaultsKey(network.name)) else {
                continue
            }
            do {
                try engine.rememberExits(network: network.name, offers: json)
            } catch {
                note("\(network.name): the remembered exits are ignored: \(error.localizedDescription)")
            }
        }
    }

    /// Makes `choice` carry the traffic, or none, and brings the tunnel settings along.
    private func choose(_ choice: ExitChoice?) throws {
        guard let engine else { throw VVError(message: "engine is not running") }
        try engine.setExit(choice)
        exitLock.withLock { self.choice = choice }
        refreshExit()
    }

    /// Applies the tunnel settings the exit calls for, now or once the one running is done. The
    /// engine's events ask for it, and so does a change of the choice.
    private func refreshExit() {
        let start = exitLock.withLock {
            if choice == nil && applied == nil { return false }
            if refreshing {
                refreshAgain = true
                return false
            }
            refreshing = true
            return true
        }
        guard start else { return }
        Task {
            var again = true
            while again {
                await applyExit()
                again = exitLock.withLock {
                    let more = refreshAgain
                    refreshAgain = false
                    if !more { refreshing = false }
                    return more
                }
            }
        }
    }

    private func applyExit() async {
        let (choice, base, current, summary) = exitLock.withLock {
            (self.choice, baseSettings, applied, self.choice.flatMap { summaries[$0.network] })
        }
        guard let base, let engine else { return }
        let inUse = choice == nil ? nil : (try? engine.exitInUse())
        publish(choice, inUse)
        let routing = ExitRouting.wanted(choice, inUse: inUse, network: summary)
        guard routing != current else { return }
        do {
            try await setTunnelNetworkSettings(try Self.networkSettings(base, routing: routing))
            exitLock.withLock { applied = routing }
            note(Self.describe(choice, inUse))
        } catch {
            note("the exit settings were not applied: \(error.localizedDescription)")
        }
    }

    private static func describe(_ choice: ExitChoice?, _ inUse: ExitInUse?) -> String {
        guard let choice else { return "no exit in use" }
        guard let inUse else { return "exit \(choice.network): none is live, traffic outside the overlay is dropped" }
        return "exit \(inUse.network) \(inUse.site) via \(inUse.via)"
    }

    /// Keeps what the app shows of the exit.
    private func publish(_ choice: ExitChoice?, _ inUse: ExitInUse?) {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard let choice else {
            state.exit = nil
            return
        }
        let name = inUse.flatMap { used in
            state.networks.first { $0.name == choice.network }?.peers.first { $0.key == used.via }?.name
        }
        state.exit = TunnelState.Exit(
            network: choice.network, site: inUse?.site ?? choice.site, via: inUse.map { name ?? $0.via })
    }

    /// The address family of an IP packet, from its version nibble.
    private static func family(_ packet: Data) -> NSNumber {
        NSNumber(value: packet.first.map { $0 >> 4 } == 4 ? AF_INET : AF_INET6)
    }

    private func shutdown() {
        memory.stop()
        watcher?.stop()
        watcher = nil
        engine?.stop()
        bonjour?.shutdown()
        engine = nil
        bonjour = nil
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let engine = self.engine else { return }
            engine.packetsIn(packets)
            self.readPackets()
        }
    }

    private func monitorPaths(excluding tunnel: String?) {
        let watcher = PathWatcher(excluding: tunnel) { [weak self] report in
            self?.note(report.note)
            self?.engine?.pathChanged(report.json)
        }
        watcher.start()
        self.watcher = watcher
    }

    /// The settings of the networks, with what an exit in use adds: the default
    /// routes of both families less the private IPv4 ranges, the addresses in the site and from the
    /// exit, and every name sent to the resolver.
    private static func networkSettings(
        _ s: TunnelSettings, routing: ExitRouting?
    ) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "::1")
        settings.mtu = NSNumber(value: s.mtu)
        let addrs = s.addrs.filter { !$0.addr.lowercased().hasPrefix("fe80:") }
        var addresses = addrs.map(\.addr)
        var prefixes = addrs.map { NSNumber(value: $0.prefix) }
        if let site = routing?.siteAddress {
            addresses.append(site)
            prefixes.append(128)
        }
        let ipv6 = NEIPv6Settings(addresses: addresses, networkPrefixLengths: prefixes)
        ipv6.includedRoutes = s.routes.map {
            NEIPv6Route(destinationAddress: $0.addr, networkPrefixLength: NSNumber(value: $0.prefix))
        }
        if let routing {
            ipv6.includedRoutes?.append(NEIPv6Route.default())
            let ipv4 = NEIPv4Settings(addresses: [routing.ipv4Address], subnetMasks: ["255.255.255.255"])
            ipv4.includedRoutes = [NEIPv4Route.default()]
            ipv4.excludedRoutes = ExitRouting.privateIPv4.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask)
            }
            settings.ipv4Settings = ipv4
        }
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: s.dns.servers)
        dns.matchDomains = routing?.dnsAll == true ? [""] : s.dns.matchDomains
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        return settings
    }

    private static func interface(holding address: String) -> (name: String, index: UInt32)? {
        var wanted = in6_addr()
        guard inet_pton(AF_INET6, address, &wanted) == 1 else { return nil }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        for ifa in sequence(first: list, next: { $0?.pointee.ifa_next }) {
            guard let ifa = ifa?.pointee, let sa = ifa.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET6)
            else { continue }
            let found = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                var a = $0.pointee.sin6_addr
                return memcmp(&a, &wanted, 16) == 0
            }
            if found {
                let name = String(cString: ifa.ifa_name)
                return (name, if_nametoindex(name))
            }
        }
        return nil
    }

    /// Logs a line and keeps it in the state the app shows.
    private func note(_ line: String) {
        log.notice("\(line, privacy: .public)")
        stateLock.lock()
        defer { stateLock.unlock() }
        appendLog(TunnelState.Line(network: nil, text: "[tunnel] \(line)"))
    }

    /// Adds a line to the log, which keeps the last hundred; the caller holds `stateLock`.
    private func appendLog(_ line: TunnelState.Line) {
        state.log.append(line)
        if state.log.count > 100 { state.log.removeFirst(state.log.count - 100) }
    }

    private func snapshot() -> TunnelState {
        stateLock.lock()
        defer { stateLock.unlock() }
        return state
    }

    /// A short text for the `route` object of a `route` event; nil for `null`.
    private static func describe(route: [String: Any]?) -> String? {
        guard let kind = route?["kind"] as? String else { return nil }
        if let index = route?["switch"] as? Int { return "\(kind) \(index)" }
        if let addr = route?["addr"] as? String { return "\(kind) \(addr)" }
        return kind
    }

    /// Files an event under the network it names.
    private func engineEvent(_ json: String) {
        guard let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
              let type = obj["type"] as? String,
              let network = obj["network"] as? String else { return }
        stateLock.lock()
        defer { stateLock.unlock() }
        guard let n = state.networks.firstIndex(where: { $0.name == network }) else { return }
        switch type {
        case "status":
            state.networks[n].engine = obj["state"] as? String ?? state.networks[n].engine
            state.networks[n].port = obj["listen_port"] as? Int ?? state.networks[n].port
            log.info("\(network, privacy: .public) engine \(self.state.networks[n].engine, privacy: .public)")
        case "added", "peer", "route":
            guard let key = obj["key"] as? String, let addr = obj["addr"] as? String else { return }
            let id = PeerID(network: network, key: key)
            var link = links[id] ?? "idle"
            if type == "peer", let peerState = obj["state"] as? String {
                link = peerState
                if let reason = obj["reason"] as? String { link += " (\(reason))" }
            }
            links[id] = link
            if type == "route" { routes[id] = Self.describe(route: obj["route"] as? [String: Any]) }
            var detail = link
            if let route = routes[id] { detail += " via \(route)" }
            let peer = TunnelState.Peer(key: key, addr: addr, name: obj["name"] as? String, state: detail)
            if let i = state.networks[n].peers.firstIndex(where: { $0.key == key }) {
                state.networks[n].peers[i] = peer
            } else {
                state.networks[n].peers.append(peer)
            }
            log.info("\(network, privacy: .public) peer \(key, privacy: .public) \(detail, privacy: .public)")
        case "removed":
            guard let key = obj["key"] as? String else { return }
            let id = PeerID(network: network, key: key)
            links[id] = nil
            routes[id] = nil
            state.networks[n].peers.removeAll { $0.key == key }
            log.info("\(network, privacy: .public) peer \(key, privacy: .public) removed")
        case "switch":
            guard let address = obj["address"] as? String, let switchState = obj["state"] as? String
            else { return }
            let entry = TunnelState.Switch(
                address: address, auth: obj["auth"] as? String, state: switchState, reason: obj["reason"] as? String)
            if let i = state.networks[n].switches.firstIndex(where: { $0.address == address }) {
                state.networks[n].switches[i] = entry
            } else {
                state.networks[n].switches.append(entry)
            }
            log.info("\(network, privacy: .public) switch \(address, privacy: .public) \(switchState, privacy: .public)")
        case "exit":
            refreshExit()
        case "exits":
            if let offers = obj["offers"], let data = try? JSONSerialization.data(withJSONObject: offers) {
                UserDefaults.standard.set(String(decoding: data, as: UTF8.self), forKey: Shared.exitsDefaultsKey(network))
            }
        case "view":
            if let view = try? JSONDecoder().decode(PathView.self, from: Data(json.utf8)) {
                state.networks[n].view = view
                state.networks[n].viewAt = Date()
            }
            refreshExit()
        case "log":
            let level = obj["level"] as? String ?? "info"
            let line = obj["message"] as? String ?? ""
            appendLog(TunnelState.Line(network: network, text: "[\(level)] \(line)"))
            // iOS keeps neither debug nor info lines once they leave memory; notice and up persist.
            switch level {
            case "debug": log.debug("\(network, privacy: .public): \(line, privacy: .public)")
            case "info": log.notice("\(network, privacy: .public): \(line, privacy: .public)")
            default: log.error("\(network, privacy: .public): \(line, privacy: .public)")
            }
        default:
            break
        }
    }
}
