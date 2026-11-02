import SwiftUI

@main
struct VardevallApp: App {
    @StateObject private var controller = TunnelController()
    #if os(macOS)
    @StateObject private var navigator = MacNavigator()
    #endif

    var body: some Scene {
        #if os(macOS)
        Window("vardevall", id: "main") {
            RootView()
                .environmentObject(controller)
                .environmentObject(navigator)
        }
        MenuBarExtra {
            MenuBarView()
                .environmentObject(controller)
                .environmentObject(navigator)
        } label: {
            Image(systemName: controller.isConnected
                ? "point.3.filled.connected.trianglepath.dotted" : "point.3.connected.trianglepath.dotted")
        }
        .menuBarExtraStyle(.window)
        #else
        WindowGroup {
            RootView()
                .environmentObject(controller)
        }
        #endif
    }
}
