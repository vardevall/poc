#if os(macOS)
import AppKit
import SwiftUI

/// The menu bar item: the connection, the exit choice and a summary of devices and servers. It
/// shares the controller with the window.
struct MenuBarView: View {
    @EnvironmentObject private var controller: TunnelController
    @EnvironmentObject private var navigator: MacNavigator
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            connect.padding(.horizontal, 6)
            Divider()
            exit.padding(.horizontal, 6)
            Divider()
            devices
            Divider()
            summary.padding(.horizontal, 6)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                Button("Open vardevall…", action: openWindowRaised)
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            .buttonStyle(MenuRowStyle())
        }
        .padding(8)
        .frame(width: 320)
    }

    private func openWindowRaised() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }

    private var connect: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(controller.isConnected ? controller.status.label : "Not connected").font(.headline)
                Text(note).font(.footnote).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("Connect", isOn: Binding(get: { controller.isConnected }, set: { on in Task { await controller.setConnected(on) } }))
                .labelsHidden()
                .toggleStyle(.switch)
        }
    }

    private var note: String {
        if let message = controller.message, !controller.isConnected { return message }
        guard controller.isConnected else { return "Turn on to reach your devices" }
        return controller.exitText ?? "Internet is not rerouted"
    }

    private var exit: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Send my internet through").font(.caption).foregroundStyle(.secondary)
            Picker("Send my internet through", selection: Binding(
                get: { controller.exit }, set: { choice in Task { await controller.setExit(choice) } })
            ) {
                Text("Overlay only").tag(ExitChoice?.none)
                ForEach(controller.exitOptions, id: \.self) { option in
                    Text("\(option.title) · \(option.note)").tag(Optional(option))
                }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            .disabled(controller.networks.isEmpty)
        }
    }

    private var devices: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Devices").font(.caption).foregroundStyle(.secondary).padding(.horizontal, 6)
            let devices = controller.devices
            if devices.isEmpty {
                Text(controller.state == nil ? "Not connected" : "None yet")
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
            }
            ForEach(devices) { device in
                Button {
                    navigator.selection = .device(device.id)
                    openWindowRaised()
                } label: {
                    DeviceDotRow(name: device.name, device: device)
                }
                .buttonStyle(MenuRowStyle())
            }
        }
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent("Servers") {
                Text(controller.serversSummary).font(.footnote).multilineTextAlignment(.trailing)
            }
            if let data = controller.helperData {
                LabeledContent("Helper data") { Text(data.text).font(.footnote) }
            }
        }
    }
}

/// A row of the menu bar window that lights up under the pointer, as a menu item does.
private struct MenuRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        Row(configuration: configuration)
    }

    private struct Row: View {
        let configuration: Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
                .background(
                    RoundedRectangle(cornerRadius: 5)
                        .fill(Color.accentColor.opacity(configuration.isPressed ? 0.3 : hovering ? 0.18 : 0))
                )
                .contentShape(Rectangle())
                .onHover { hovering = $0 }
        }
    }
}
#endif
