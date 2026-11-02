import SwiftUI

struct StatusScreen: View {
    @EnvironmentObject private var controller: TunnelController
    let showConnectivity: () -> Void

    var body: some View {
        Form {
            connectSection
            if let data = controller.helperData {
                helperDataSection(data)
            }
            ExitSection()
            serversSection
            devicesSection
        }
        .formStyle(.grouped)
        .navigationTitle("vardevall")
    }

    private var connectSection: some View {
        Section {
            Toggle(isOn: Binding(get: { controller.isConnected }, set: { on in Task { await controller.setConnected(on) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.title2.weight(.semibold))
                    Text(subtitle).foregroundStyle(.secondary)
                }
            }
            if let message = controller.message {
                Text(message).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private var title: String {
        switch controller.status {
        case .connected: "Connected"
        case .connecting, .reasserting, .disconnecting: controller.status.label
        default: "Not connected"
        }
    }

    private var subtitle: String {
        if controller.state != nil { return controller.onlineSummary }
        return controller.networks.isEmpty ? "Add a network to start" : "Turn on to reach your devices"
    }

    private func helperDataSection(_ data: HelperData) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Helper data")
                    Spacer()
                    Text(data.text).foregroundStyle(.secondary)
                }
                ProgressView(value: Double(data.remaining), total: Double(max(data.total, 1)))
            }
        } footer: {
            Text("Direct connections use none of it.")
        }
    }

    private var serversSection: some View {
        Section {
            Button(action: showConnectivity) {
                HStack {
                    Text("Servers")
                    Spacer()
                    if controller.relayInUse {
                        Text("Relay in use").foregroundStyle(Color.helper)
                        Text("·").foregroundStyle(.secondary)
                    }
                    Text(serversValue).foregroundStyle(.secondary)
                    Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }

    /// "1 of 2 online".
    private var serversValue: String {
        guard controller.state != nil else { return "Not connected" }
        let switches = controller.switchesOnline
        return switches.total == 0 ? "None" : "\(switches.online) of \(switches.total) online"
    }

    private var devicesSection: some View {
        Section("Devices") {
            let devices = controller.devices
            if devices.isEmpty {
                Text(controller.state == nil ? "Connect to see your devices." : "None yet.")
                    .foregroundStyle(.secondary)
            }
            ForEach(devices) { device in
                DeviceLink(id: device.id) { DeviceRow(device: device, showNetwork: true) }
            }
        }
    }
}

/// "Send my internet through": Overlay only, or the exit of a network.
struct ExitSection: View {
    @EnvironmentObject private var controller: TunnelController

    var body: some View {
        Section {
            Picker("Send my internet through", selection: choice) {
                ExitLabel(title: "Overlay only", note: "Only traffic between your devices uses vardevall")
                    .tag(ExitChoice?.none)
                ForEach(controller.exitOptions, id: \.self) { option in
                    ExitLabel(title: option.title, note: option.note).tag(Optional(option))
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
            .disabled(controller.networks.isEmpty)
        } header: {
            Text("Send my internet through")
        } footer: {
            Text(controller.exitText ?? "Your normal internet connection is not changed.")
        }
    }

    private var choice: Binding<ExitChoice?> {
        Binding(get: { controller.exit }, set: { choice in Task { await controller.setExit(choice) } })
    }
}

struct ExitLabel: View {
    let title: String
    let note: String

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
            Text(note).font(.footnote).foregroundStyle(.secondary)
        }
    }
}

/// A device with its network and the line to it.
struct DeviceRow: View {
    let device: Device
    let showNetwork: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(device.name).font(.headline)
                Spacer()
                if showNetwork {
                    Text(device.network)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.15), in: Capsule())
                }
            }
            PathLine(device: device)
        }
        .padding(.vertical, 2)
    }
}

/// A device as the menu bar lists it: a dot in the colour of its route, its name and the RTT.
struct DeviceDotRow: View {
    let name: String
    let device: Device?

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(device?.route.color ?? .secondary).frame(width: 8, height: 8)
            Text(name)
            Spacer()
            if let device, let rtt = PathLineModel(device).rttText {
                Text(rtt).monospacedDigit().foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(device.map { PathLineModel($0).summary } ?? "\(name): not connected")
    }
}
