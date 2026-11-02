import Foundation

/// Names shared by the app and the tunnel extension.
enum Shared {
    static let subsystem = "net.vardevall"
    static let keychainService = "net.vardevall.interface"
    /// The network of `vv_start`, and the name given to the config stored before networks had names.
    static let defaultNetwork = "vardevall"
    /// The keychain account of the config stored before networks had names.
    static let legacyKeychainAccount = "default"
    /// `providerConfiguration` key of the list `[{name, ref}]`: names and persistent references.
    static let networksKey = "networks"
    static let networkNameKey = "name"
    static let networkReferenceKey = "ref"
    /// `providerConfiguration` key of the single reference stored before networks had names.
    static let legacyConfigReferenceKey = "configRef"
    /// `providerConfiguration` key of the exit the user chose, `{name, site}`; absent while off.
    static let exitKey = "exit"
    static let exitSiteKey = "site"
    /// The extension's `UserDefaults` key of a network's last `exits` event, `exits.<name>`
    ///: the offers it gives back at the next start.
    static func exitsDefaultsKey(_ network: String) -> String { "exits.\(network)" }
    static let stateRequest = Data("state".utf8)
}
