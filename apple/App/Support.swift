import SwiftUI

/// The colours of the app beyond the accent: orange for a helper in use.
extension Color {
    static let helper = Color.orange
}

extension View {
    /// No automatic capitals or corrections, for names and keys.
    func autocorrectionDisabledCompat() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        self.autocorrectionDisabled()
        #endif
    }
}

enum FileText {
    /// The text of a file picked with the file importer.
    static func read(_ url: URL) -> String? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try? String(contentsOf: url, encoding: .utf8)
    }
}
