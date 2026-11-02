import SwiftUI
import UniformTypeIdentifiers

/// What the editing sheet opens on: the saved text of a network, or the text of one not added yet.
struct EditorTarget: Identifiable {
    let name: String
    let text: String
    let isNew: Bool
    let id = UUID()
}

/// The text being edited in the sheet; the saved networks do not change until it is saved.
@MainActor
final class ConfigDraft: ObservableObject {
    enum Check: Equatable {
        case pending
        case valid(String)
        case invalid(String)
    }

    @Published private(set) var text: String
    @Published private(set) var check = Check.pending
    private let original: String
    private let isNew: Bool
    private var pending: Task<Void, Never>?

    init(_ target: EditorTarget) {
        text = target.text
        original = target.text
        isNew = target.isNew
        validate()
    }

    /// How long the text rests before it is checked, in nanoseconds.
    static let delay: UInt64 = 800_000_000

    /// A keystroke: checks the text once it has rested for 0.8 s.
    func edit(_ new: String) {
        guard new != text else { return }
        text = new
        check = .pending
        pending?.cancel()
        pending = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.delay)
            guard !Task.isCancelled else { return }
            self?.validate()
        }
    }

    /// New text that is checked at once, such as a file or fresh keys.
    func replace(_ new: String) {
        pending?.cancel()
        text = new
        validate()
    }

    func fail(_ message: String) {
        check = .invalid(message)
    }

    private func validate() {
        do {
            let summary = try VV.validate(config: text)
            let n = summary.peers.count
            check = .valid("Valid: \(summary.domain), \(n) \(n == 1 ? "device" : "devices")")
        } catch {
            check = .invalid(error.localizedDescription)
        }
    }

    var isInvalid: Bool {
        if case .invalid = check { return true }
        return false
    }

    var canSave: Bool {
        if case .invalid = check { return false }
        return isNew || text != original
    }
}

/// The interface file of a network in a sheet: Cancel throws the text away, Save validates, saves
/// and closes.
struct NetworkEditorSheet: View {
    @EnvironmentObject private var controller: TunnelController
    @Environment(\.dismiss) private var dismiss
    let target: EditorTarget
    /// Called with the network's name once it is saved.
    let saved: (String) -> Void
    @StateObject private var draft: ConfigDraft
    @State private var importing = false
    @State private var saving = false
    @State private var name = ""
    @FocusState private var focused: Bool

    init(target: EditorTarget, saved: @escaping (String) -> Void = { _ in }) {
        self.target = target
        self.saved = saved
        _draft = StateObject(wrappedValue: ConfigDraft(target))
        _name = State(initialValue: target.name)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("home"))
                        .autocorrectionDisabledCompat()
                        .focused($focused)
                } header: {
                    Text("Name")
                } footer: {
                    Text(target.isNew ? "Lowercase letters, digits and dashes." : "Lowercase letters, digits and dashes. A new name applies when you connect again.")
                }
                Section {
                    TextEditor(text: Binding(get: { draft.text }, set: { draft.edit($0) }))
                        .font(.system(.footnote, design: .monospaced))
                        .autocorrectionDisabledCompat()
                        .focused($focused)
                        .frame(minHeight: 240)
                } footer: {
                    checkLine
                }
                Section {
                    HStack {
                        Button("New keys", action: newKeys)
                        Button("Import") { importing = true }
                    }
                    .buttonStyle(.bordered)
                }
            }
            .formStyle(.grouped)
            .navigationTitle(target.isNew ? "New Network" : "Edit \(target.name)")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            .scrollDismissesKeyboard(.interactively)
            .background(TapOutsideEndsEditing())
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(draft.isInvalid || !(draft.canSave || name != target.name) || saving || name.isEmpty)
                }
                #if os(iOS)
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { focused = false }
                }
                #endif
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .data]) { result in
                guard let url = try? result.get(), let text = FileText.read(url) else { return }
                draft.replace(text)
            }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 460)
        #endif
    }

    @ViewBuilder
    private var checkLine: some View {
        switch draft.check {
        case .pending: Text("Checking…").foregroundStyle(.secondary)
        case .valid(let text): Text(text).foregroundStyle(.secondary)
        case .invalid(let error): Text(error).foregroundStyle(.red)
        }
    }

    private func newKeys() {
        do {
            draft.replace(try TunnelController.newConfig())
        } catch {
            draft.fail(error.localizedDescription)
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        if await controller.commit(name: name, text: draft.text, renaming: target.isNew ? nil : target.name) {
            saved(name)
            dismiss()
        } else {
            draft.fail(controller.message ?? "The network could not be saved.")
        }
    }
}

/// The start of a new network: fresh keys in the editing sheet, where it is named and saved.
@MainActor
final class AddNetworkModel: ObservableObject {
    @Published var editor: EditorTarget?
    @Published var error: String?

    func begin() {
        do {
            editor = EditorTarget(name: "", text: try TunnelController.newConfig(), isNew: true)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// "Add Network…", a row of a list.
struct AddNetworkButton: View {
    @ObservedObject var model: AddNetworkModel

    var body: some View {
        Button { model.begin() } label: {
            Label("Add Network…", systemImage: "plus")
        }
        if let error = model.error {
            Text(error).font(.footnote).foregroundStyle(.red)
        }
    }
}

extension View {
    /// The editing sheet of `AddNetworkModel`.
    func addingNetworks(_ model: AddNetworkModel) -> some View {
        sheet(item: Binding(get: { model.editor }, set: { model.editor = $0 })) { NetworkEditorSheet(target: $0) }
    }
}

#if os(iOS)
/// Ends text editing when a tap lands outside every text field and text view of the window. The
/// tap still reaches what it landed on.
private struct TapOutsideEndsEditing: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView { Anchor() }
    func updateUIView(_ view: UIView, context: Context) {}

    private final class Anchor: UIView, UIGestureRecognizerDelegate {
        private var tap: UITapGestureRecognizer?

        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let tap { tap.view?.removeGestureRecognizer(tap) }
            tap = nil
            guard let window else { return }
            let tap = UITapGestureRecognizer(target: self, action: #selector(ended))
            tap.cancelsTouchesInView = false
            tap.delegate = self
            window.addGestureRecognizer(tap)
            self.tap = tap
        }

        @objc private func ended() {
            window?.endEditing(true)
        }

        func gestureRecognizer(_ g: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
            var view = touch.view
            while let v = view {
                if v is UITextView || v is UITextField { return false }
                view = v.superview
            }
            return true
        }

        func gestureRecognizer(_ g: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
            true
        }
    }
}
#endif
