import SwiftUI

/// One network: what its interface file says, its devices, switches and relay.
struct NetworkScreen: View {
    @EnvironmentObject private var controller: TunnelController
    #if os(macOS)
    @EnvironmentObject private var navigator: MacNavigator
    #else
    @Environment(\.dismiss) private var dismiss
    #endif
    let name: String
    @State private var editor: EditorTarget?
    @State private var confirmingRemoval = false
    @State private var failure: String?

    private var draft: NetworkDraft? { controller.networks.first { $0.name == name } }

    var body: some View {
        Form {
            if let draft {
                thisNetwork(draft)
                devices(draft)
                switches(draft)
                relay
                Section {
                    HStack {
                        Button("Edit…") { editor = EditorTarget(name: name, text: draft.configText, isNew: false) }
                        Spacer()
                        Button("Remove", role: .destructive) { confirmingRemoval = true }
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                } footer: {
                    if let failure { Text(failure).foregroundStyle(.red) }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(name)
        .sheet(item: $editor) { NetworkEditorSheet(target: $0, saved: renamed) }
        .confirmationDialog("Remove \(name)?", isPresented: $confirmingRemoval, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { Task { await remove() } }
        } message: {
            Text("Its keys are deleted from this device.")
        }
    }

    /// Follows a new name: the sidebar selects it on macOS; on iOS the screen goes back to the list.
    private func renamed(_ new: String) {
        guard new != name else { return }
        #if os(macOS)
        navigator.selection = .network(new)
        #else
        dismiss()
        #endif
    }

    private func remove() async {
        guard await controller.remove(name) else {
            failure = controller.message
            return
        }
        #if os(macOS)
        navigator.selection = .status
        #else
        dismiss()
        #endif
    }

    private func thisNetwork(_ draft: NetworkDraft) -> some View {
        Section {
            LabeledContent("Name", value: draft.name)
            if let s = draft.summary {
                LabeledContent("Domain", value: s.domain)
                LabeledContent("Overlay address") { Text(s.addrs.ula).font(.system(.footnote, design: .monospaced)).textSelection(.enabled) }
                LabeledContent("Public key") {
                    Text(s.publicKey).font(.system(.footnote, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                }
                if s.listenPort != 0 {
                    LabeledContent("Port", value: "\(s.listenPort)")
                }
                LabeledContent("Find devices on my Wi-Fi", value: s.mdns ? "On" : "Off")
                if s.stunServers > 0 {
                    LabeledContent("STUN servers", value: "\(s.stunServers)")
                }
                if !s.services.isEmpty {
                    LabeledContent("Services", value: s.services.map { "\($0.name)  \($0.port)/\($0.proto)" }.joined(separator: "\n"))
                }
            } else {
                Text("The text of the network is not valid; use Edit… to fix it.").foregroundStyle(.secondary)
            }
        } header: {
            Text("This network")
        } footer: {
            Text("These are set in the text of the network; use Edit… to change them.")
        }
    }

    private func devices(_ draft: NetworkDraft) -> some View {
        Section("Devices") {
            if let s = draft.summary {
                LabeledContent("This device") {
                    Text(s.publicKey)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                ForEach(s.peers) { peer in
                    let id = DeviceID(network: name, key: peer.publicKey)
                    DeviceLink(id: id) {
                        DeviceDotRow(name: peer.name ?? peer.addr, device: controller.device(id))
                    }
                }
                if s.peers.isEmpty {
                    Text("No other devices in the text.").foregroundStyle(.secondary)
                }
            } else {
                Text("The text of the network is not valid.").foregroundStyle(.secondary)
            }
        }
    }

    /// The switches of the file, with their registration while connected.
    private func switches(_ draft: NetworkDraft) -> some View {
        Section("Switches") {
            let configured = draft.summary?.switches ?? []
            if configured.isEmpty {
                Text("None configured.").foregroundStyle(.secondary)
            }
            ForEach(configured) { SwitchRow(configured: $0, network: controller.network(name)) }
        }
    }

    private var relay: some View {
        Section {
            if let live = controller.network(name), let relay = live.view?.local.relay {
                RelayRow(relay: relay, inUse: controller.devices.contains { $0.network == name && $0.paths?.route?.kind == "own_relay" })
            } else {
                Text(controller.state == nil ? "Set up once connected." : "None.").foregroundStyle(.secondary)
            }
        } header: {
            Text("Relays")
        } footer: {
            Text("A relay is used only when two devices cannot connect directly.")
        }
    }
}
