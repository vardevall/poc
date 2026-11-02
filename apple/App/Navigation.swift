import SwiftUI

#if os(macOS)
/// What the sidebar of the window selects; the detail column shows it.
enum MacSelection: Hashable {
    case status, connectivity
    case network(String)
    case device(DeviceID)
}

/// The window's selection, shared with the menu bar so that it can open the window on a device.
@MainActor
final class MacNavigator: ObservableObject {
    @Published var selection: MacSelection? = .status
}
#endif

/// A row that opens a device: a push on iOS, the selection of the sidebar on macOS.
struct DeviceLink<Label: View>: View {
    let id: DeviceID
    @ViewBuilder let label: () -> Label
    #if os(macOS)
    @EnvironmentObject private var navigator: MacNavigator
    #endif

    var body: some View {
        #if os(macOS)
        Button { navigator.selection = .device(id) } label: {
            HStack(spacing: 0) {
                label()
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        #else
        NavigationLink(value: id, label: label)
        #endif
    }
}
