import Foundation
import NetworkExtension
import OSLog

/// A network as the app edits it: the name it was given and its interface file.
struct NetworkDraft: Identifiable, Equatable {
    var name: String
    var configText: String
    var summary: ConfigSummary?
    var id: String { name }
}

/// App-side owner of the networks, the connection and the extension's reported state.
@MainActor
final class TunnelController: ObservableObject {
    /// In order; the first is the one whose address the system resolves through.
    @Published var networks: [NetworkDraft] = []
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var state: TunnelState?
    @Published private(set) var message: String?
    /// The exit the user chose for the device's traffic; nil is off, the default.
    @Published private(set) var exit: ExitChoice?

    private let log = Logger(subsystem: Shared.subsystem, category: "app")
    private var manager: NETunnelProviderManager?
    private var poll: Task<Void, Never>?
    private var observer: NSObjectProtocol?

    private var providerBundleID: String { (Bundle.main.bundleIdentifier ?? "") + ".tunnel" }

    init() {
        networks = ConfigStore.list().map {
            NetworkDraft(name: $0.name, configText: $0.text, summary: try? VV.validate(config: $0.text))
        }
        Task { await loadManager() }
    }

    var isConnected: Bool { status == .connected || status == .connecting || status == .reasserting }

    /// Whether `name` can name a network: a DNS label of at most 51 characters, which the engine
    /// checks again when the networks are saved.
    static func isValid(name: String) -> Bool {
        name.range(of: "^[a-z0-9]([a-z0-9-]{0,49}[a-z0-9])?$", options: .regularExpression) != nil
    }

    /// A config with fresh keys.
    static func newConfig() throws -> String {
        """
        [interface]
        private_key = "\(try VV.generateNodeKey())"
        network_secret = "\(try VV.generateNetworkSecret())"
        """
    }

    /// Throws unless `name` can name a network that is not there yet.
    func checkNewName(_ name: String) throws {
        guard Self.isValid(name: name) else {
            throw VVError(message: "A name is lowercase letters, digits and dashes, up to 51 characters.")
        }
        guard !networks.contains(where: { $0.name == name }) else {
            throw VVError(message: "There is a network called \(name) already.")
        }
    }

    /// Saves `text` as the interface file of network `name`, adding the network if it is not there.
    /// With `original`, the network of that name is renamed to `name`, and an exit chosen on it
    /// follows. `networks` changes only if the whole set was saved; otherwise the message says why.
    func commit(name: String, text: String, renaming original: String? = nil) async -> Bool {
        let before = networks
        let exitBefore = exit
        do {
            message = nil
            let summary = try VV.validate(config: text)
            if let original, original != name, let i = networks.firstIndex(where: { $0.name == original }) {
                try checkNewName(name)
                networks[i].name = name
                networks[i].configText = text
                networks[i].summary = summary
                if let choice = exit, choice.network == original {
                    exit = ExitChoice(network: name, site: choice.site)
                }
            } else if let i = networks.firstIndex(where: { $0.name == name }) {
                networks[i].configText = text
                networks[i].summary = summary
            } else {
                try checkNewName(name)
                networks.append(NetworkDraft(name: name, configText: text, summary: summary))
            }
        } catch {
            networks = before
            exit = exitBefore
            fail(error)
            return false
        }
        if await save() { return true }
        networks = before
        exit = exitBefore
        return false
    }

    /// Removes network `name` and saves the rest at once; the last network takes the tunnel
    /// configuration with it.
    @discardableResult
    func remove(_ name: String) async -> Bool {
        let before = networks
        networks.removeAll { $0.name == name }
        guard networks.isEmpty else {
            if await save() { return true }
            networks = before
            return false
        }
        do {
            if let manager {
                manager.connection.stopVPNTunnel()
                try await manager.removeFromPreferences()
            }
            _ = try ConfigStore.replace(with: [])
            if let observer { NotificationCenter.default.removeObserver(observer) }
            observer = nil
            manager = nil
            exit = nil
            poll?.cancel()
            state = nil
            status = .invalid
            message = "Saved."
            return true
        } catch {
            networks = before
            fail(error)
            return false
        }
    }

    /// Checks every network and the set, writes them to the keychain once and saves the tunnel
    /// configuration, which carries the names and references only.
    @discardableResult
    func save() async -> Bool {
        do {
            guard !networks.isEmpty else { throw VVError(message: "Add a network first.") }
            var checked = networks
            for i in checked.indices {
                do {
                    checked[i].summary = try VV.validate(config: checked[i].configText)
                } catch {
                    throw VVError(message: "\(checked[i].name): \(error.localizedDescription)")
                }
            }
            _ = try VV.tunnelSettings(networks: checked.map { NetworkConfig(name: $0.name, config: $0.configText) })
            let stored = try ConfigStore.replace(with: checked.map { ($0.name, $0.configText) })
            let manager = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleID
            proto.serverAddress = "vardevall"
            var configuration: [String: Any] = [
                Shared.networksKey: stored.map {
                    [Shared.networkNameKey: $0.name, Shared.networkReferenceKey: $0.reference] as [String: Any]
                },
            ]
            let choice = exit.flatMap { choice in checked.contains { $0.name == choice.network } ? choice : nil }
            configuration[Shared.exitKey] = choice?.configuration
            proto.providerConfiguration = configuration
            manager.protocolConfiguration = proto
            manager.localizedDescription = "vardevall"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            attach(manager)
            networks = checked
            message = "Saved."
            return true
        } catch {
            fail(error)
            return false
        }
    }

    func setConnected(_ on: Bool) async {
        guard let manager else { return fail(VVError(message: "Save the networks first.")) }
        do {
            if on {
                if !manager.isEnabled {
                    manager.isEnabled = true
                    try await manager.saveToPreferences()
                    try await manager.loadFromPreferences()
                }
                try manager.connection.startVPNTunnel()
            } else {
                manager.connection.stopVPNTunnel()
            }
        } catch {
            fail(error)
        }
    }

    private func loadManager() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            let mine = all.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
            }
            if let mine { attach(mine) }
        } catch {
            fail(error)
        }
    }

    private func attach(_ manager: NETunnelProviderManager) {
        self.manager = manager
        let saved = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        exit = ExitChoice(configuration: saved?[Shared.exitKey])
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.statusChanged() }
        }
        statusChanged()
    }

    private func statusChanged() {
        status = manager?.connection.status ?? .invalid
        log.info("status \(self.status.rawValue)")
        poll?.cancel()
        guard isConnected else {
            state = nil
            if status == .disconnected { showLastDisconnectError() }
            return
        }
        poll = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshState()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    /// Sends the traffic outside the overlay through `choice`, or not. The running
    /// tunnel takes it at once, and it is saved in the tunnel configuration for the next start.
    func setExit(_ choice: ExitChoice?) async {
        let before = exit
        exit = choice
        do {
            if isConnected { _ = try await request(ExitRequest(exit: choice)) }
            try await saveExit(choice)
        } catch {
            exit = before
            fail(error)
        }
    }

    private func saveExit(_ choice: ExitChoice?) async throws {
        try await save(key: Shared.exitKey, value: choice?.configuration)
    }

    private func save(key: String, value: Any?) async throws {
        guard let manager, let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var configuration = proto.providerConfiguration ?? [:]
        configuration[key] = value
        proto.providerConfiguration = configuration
        manager.protocolConfiguration = proto
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
    }

    /// What the user can pick: each network, and each of its sites when it offers several.
    var exitOptions: [ExitChoice] {
        var options = networks.flatMap { network -> [ExitChoice] in
            let sites = state?.networks.first { $0.name == network.name }?.view?.sites?.map(\.site) ?? []
            return sites.count > 1
                ? sites.map { ExitChoice(network: network.name, site: $0) }
                : [ExitChoice(network: network.name)]
        }
        if let exit, !options.contains(exit) { options.append(exit) }
        return options
    }

    /// The exit and what stands behind it, for the status.
    var exitText: String? {
        guard let exit else { return nil }
        let name = exit.site.map { "\(exit.network) · \($0)" } ?? exit.network
        guard isConnected else { return "Exit \(name), used once connected" }
        guard let used = state?.exit, used.network == exit.network else { return "Exit \(name), starting" }
        guard let via = used.via else { return "Exit \(name): none is live, traffic is dropped" }
        return "Exit \(used.site.map { "\(exit.network) · \($0)" } ?? exit.network) via \(via)"
    }

    private func send(_ message: Data) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { continuation.resume(returning: $0) }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    /// Shows why the extension failed to start, such as a rejected config.
    private func showLastDisconnectError() {
        manager?.connection.fetchLastDisconnectError { [weak self] error in
            guard let error else { return }
            Task { @MainActor in self?.fail(error) }
        }
    }

    private func refreshState() async {
        if let data = await send(Shared.stateRequest),
           let decoded = try? JSONDecoder().decode(TunnelState.self, from: data) {
            state = decoded
        }
    }

    private func request(_ request: some Encodable) async throws -> ServiceReply {
        guard let data = await send(try JSONEncoder().encode(request)),
              let reply = try? JSONDecoder().decode(ServiceReply.self, from: data)
        else { throw VVError(message: "The tunnel did not answer.") }
        if let error = reply.error { throw VVError(message: error) }
        return reply
    }

    /// Announces a service of this node in `network`, nil for the first, to its peers (vve-14 §2.1)
    /// while connected.
    func announce(network: String? = nil, name: String, port: Int, proto: String = "tcp") async {
        do {
            _ = try await request(ServiceRequest(op: "announce", network: network, name: name, port: port, proto: proto))
        } catch {
            fail(error)
        }
    }

    /// Withdraws the services of that name; whether there were any.
    @discardableResult
    func withdraw(network: String? = nil, name: String) async -> Bool {
        do {
            return try await request(ServiceRequest(op: "withdraw", network: network, name: name)).withdrawn ?? false
        } catch {
            fail(error)
            return false
        }
    }

    /// The providers of a service among the peers (vve-14 §3).
    func providers(network: String? = nil, name: String) async -> [ServiceProvider] {
        do {
            return try await request(ServiceRequest(op: "providers", network: network, name: name)).providers ?? []
        } catch {
            fail(error)
            return []
        }
    }

    private func fail(_ error: Error) {
        log.error("\(error.localizedDescription, privacy: .public)")
        message = error.localizedDescription
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "Not configured"
        case .disconnected: "Disconnected"
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .reasserting: "Reconnecting"
        case .disconnecting: "Disconnecting"
        @unknown default: "Unknown"
        }
    }
}
