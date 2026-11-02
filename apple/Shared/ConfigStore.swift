import Foundation
import Security

/// A network's interface file as the keychain holds it.
struct StoredNetwork: Equatable {
    let name: String
    let text: String
    /// The persistent reference to the item, which the tunnel extension reads it by.
    let reference: Data
}

/// The interface files in the keychain access group shared by the app and the extension: one item
/// per network, the account being the network's name.
enum ConfigStore {
    private static var service: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Shared.keychainService,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static func fail(_ what: String, _ status: OSStatus) -> VVError {
        let text = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
        return VVError(message: "\(what): \(text)")
    }

    /// Every stored network in the order the user gave them. The item stored before networks had
    /// names (account `default`) is the network `vardevall`; it is not rewritten.
    static func list() -> [StoredNetwork] {
        var query = service
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true
        query[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]]
        else { return [] }
        let accounts = Set(items.compactMap { $0[kSecAttrAccount as String] as? String })
        let found: [(order: Int, network: StoredNetwork)] = items.compactMap { item in
            guard var name = item[kSecAttrAccount as String] as? String,
                  let data = item[kSecValueData as String] as? Data,
                  let text = String(data: data, encoding: .utf8),
                  let reference = item[kSecValuePersistentRef as String] as? Data
            else { return nil }
            if name == Shared.legacyKeychainAccount {
                guard !accounts.contains(Shared.defaultNetwork) else { return nil }
                name = Shared.defaultNetwork
            }
            let order = (item[kSecAttrGeneric as String] as? Data)
                .flatMap { String(data: $0, encoding: .utf8) }.flatMap(Int.init) ?? 0
            return (order, StoredNetwork(name: name, text: text, reference: reference))
        }
        return found.sorted { ($0.order, $0.network.name) < ($1.order, $1.network.name) }.map(\.network)
    }

    /// Stores the config of network `name`, `position` being its place in the list, and returns a
    /// persistent reference to the item.
    static func save(name: String, position: Int, text: String) throws -> Data {
        delete(name: name)
        var item = service
        item[kSecAttrAccount as String] = name
        item[kSecAttrGeneric as String] = Data("\(position)".utf8)
        item[kSecValueData as String] = Data(text.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        item[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        guard status == errSecSuccess, let ref = result as? Data else {
            throw fail("keychain write", status)
        }
        return ref
    }

    /// Removes the item of network `name`, and the one stored before networks had names if `name`
    /// is the network it stands for.
    static func delete(name: String) {
        var accounts = [name]
        if name == Shared.defaultNetwork { accounts.append(Shared.legacyKeychainAccount) }
        for account in accounts {
            var query = service
            query[kSecAttrAccount as String] = account
            SecItemDelete(query as CFDictionary)
        }
    }

    /// Makes the keychain hold exactly `networks`, in order, and returns each one's reference.
    static func replace(with networks: [(name: String, text: String)]) throws -> [(name: String, reference: Data)] {
        let kept = Set(networks.map(\.name))
        for old in list() where !kept.contains(old.name) { delete(name: old.name) }
        return try networks.enumerated().map { position, network in
            (network.name, try save(name: network.name, position: position, text: network.text))
        }
    }

    /// Reads the item behind a persistent reference.
    static func load(reference: Data) throws -> String {
        let query: [String: Any] = [
            kSecValuePersistentRef as String: reference,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let text = String(data: data, encoding: .utf8)
        else { throw fail("keychain read", status) }
        return text
    }
}
