import AppKit
import SwiftUI
import TermiuxCore

/// The user's SSH keys: generate, import, hardware-bound keys, export and install.
struct KeysView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var selection: String?
    @State private var sheet: Sheet?
    @State private var message: (title: String, text: String)?

    enum Sheet: Identifiable {
        case generate, securityKey, smartcard
        case install(KeyRecord)
        var id: String {
            switch self {
            case .generate: "generate"
            case .securityKey: "securityKey"
            case .smartcard: "smartcard"
            case .install(let key): "install-\(key.id)"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            List(selection: $selection) {
                ForEach(app.keys, id: \.id) { key in
                    KeyRow(key: key)
                        .tag(key.id)
                        .contextMenu { menu(for: key) }
                }
            }
            .overlay {
                if app.keys.isEmpty {
                    ContentUnavailableView(
                        "No Keys", systemImage: "key",
                        description: Text("Generate a key, import one from ~/.ssh, or use a YubiKey."))
                }
            }
            HStack {
                Menu("New Key") {
                    Button("Software Key…") { sheet = .generate }
                    Button("Security Key (YubiKey FIDO2)…") { sheet = .securityKey }
                    if HardwareKeys.secureEnclaveAvailable {
                        Button("Touch ID Key (Secure Enclave)…", action: createSecureEnclaveKey)
                    }
                    Divider()
                    Button("Smartcard (PIV) Key…") { sheet = .smartcard }
                }
                .fixedSize()
                Button("Import…", action: importKey)
                Spacer()
                if let key = selectedKey {
                    Menu("Actions") { menu(for: key) }.fixedSize()
                }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 600, height: 420)
        .sheet(item: $sheet) { sheet in
            switch sheet {
            case .generate: GenerateKeySheet()
            case .securityKey: SecurityKeySheet()
            case .smartcard: SmartcardSheet()
            case .install(let key): InstallKeySheet(key: key)
            }
        }
        .alert(message?.title ?? "", isPresented: .constant(message != nil)) {
            Button("OK") { message = nil }
        } message: {
            Text(message?.text ?? "")
        }
    }

    private var selectedKey: KeyRecord? { app.keys.first { $0.id == selection } }

    @ViewBuilder private func menu(for key: KeyRecord) -> some View {
        Button("Copy Public Key") { copy(key.publicKey) }
        Button("Install on Host…") { sheet = .install(key) }
        if key.kind == .software || key.kind == .securityKey {
            Button("Export Private Key…") { export(key) }
        }
        Divider()
        Button("Delete…", role: .destructive) { confirmDelete(key) }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func importKey() {
        let panel = NSOpenPanel()
        panel.message = "Choose an OpenSSH private key"
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let contents = try String(contentsOf: url, encoding: .utf8)
            let label = url.lastPathComponent
            do {
                _ = try app.importKey(label: label, contents: contents, passphrase: nil)
            } catch CoreError.InvalidKey(let text) where text == "key is encrypted" {
                guard let passphrase = Prompts.form(
                    title: "Key passphrase", message: "“\(label)” is protected by a passphrase.",
                    fields: [("", true)])?.first
                else { return }
                _ = try app.importKey(label: label, contents: contents, passphrase: passphrase)
            }
        } catch {
            message = ("Import failed", error.localizedDescription)
        }
    }

    private func createSecureEnclaveKey() {
        guard let name = Prompts.form(
            title: "New Touch ID Key",
            message: "The key is created in this Mac's Secure Enclave and can never be exported. "
                + "Each login asks for Touch ID.",
            fields: [("Name", false)])?.first, !name.isEmpty
        else { return }
        do {
            let (tag, publicKey) = try app.hardwareKeys.createSecureEnclaveKey(label: name)
            _ = try app.core?.addPlatformKey(label: name, publicKey: publicKey, key: .secureEnclave(tag: tag))
            app.reload()
        } catch {
            message = ("Could not create the key", error.localizedDescription)
        }
    }

    private func export(_ key: KeyRecord) {
        let alert = NSAlert()
        alert.messageText = "Export private key “\(key.label)”?"
        alert.informativeText = key.kind == .securityKey
            ? "This exports the key handle file. It only works together with your security key."
            : "Anyone with this file can log in as you. Protect it with a passphrase unless you know you don't need one."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        var passphrase: String?
        if key.kind == .software {
            guard let fields = Prompts.form(
                title: "Passphrase for the exported file", message: "Leave empty for no passphrase.",
                fields: [("Passphrase", true), ("Repeat", true)])
            else { return }
            guard fields[0] == fields[1] else {
                message = ("Export cancelled", "The passphrases did not match.")
                return
            }
            passphrase = fields[0].isEmpty ? nil : fields[0]
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = key.label.replacingOccurrences(of: " ", with: "_")
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let contents = try app.core?.exportPrivateKey(id: key.id, passphrase: passphrase) ?? ""
            FileManager.default.createFile(atPath: url.path, contents: Data(contents.utf8), attributes: [.posixPermissions: 0o600])
        } catch {
            message = ("Export failed", error.localizedDescription)
        }
    }

    private func confirmDelete(_ key: KeyRecord) {
        let alert = NSAlert()
        alert.messageText = "Delete “\(key.label)”?"
        alert.informativeText = switch key.kind {
        case .securityKey: "The key handle is removed from Termiux. The credential stays on your security key."
        case .piv: "The key is removed from Termiux. It stays on the smartcard."
        case .secureEnclave: "The Touch ID key is destroyed. Servers that trust it will no longer accept this Mac."
        case .software: "The private key is deleted from this Mac. Export it first if you still need it."
        }
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            app.delete(key: key)
            selection = nil
        }
    }
}

private struct KeyRow: View {
    let key: KeyRecord

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).frame(width: 18).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(key.label)
                    Text(kindLabel).font(.caption2).padding(.horizontal, 5).background(.tint.opacity(0.18), in: Capsule())
                }
                Text(key.publicKey).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
        .padding(.vertical, 2)
    }

    private var icon: String {
        switch key.kind {
        case .software: "key"
        case .securityKey: "key.radiowaves.forward"
        case .piv: "creditcard"
        case .secureEnclave: "touchid"
        }
    }

    private var kindLabel: String {
        let type = key.publicKey.split(separator: " ").first.map(String.init) ?? ""
        let short = type.replacingOccurrences(of: "@openssh.com", with: "").replacingOccurrences(of: "ecdsa-sha2-", with: "")
        switch key.kind {
        case .software: return short
        case .securityKey: return "FIDO2"
        case .piv: return "PIV · \(short)"
        case .secureEnclave: return "Touch ID"
        }
    }
}

private struct GenerateKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var algorithm = KeyAlgorithm.ed25519
    @State private var passphrase = ""
    @State private var repeatPassphrase = ""
    @State private var error: String?
    @State private var working = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                TextField("Name", text: $name, prompt: Text("e.g. laptop-2026"))
                Picker("Type", selection: $algorithm) {
                    Text("Ed25519 (recommended)").tag(KeyAlgorithm.ed25519)
                    Text("ECDSA P-256").tag(KeyAlgorithm.ecdsaP256)
                    Text("ECDSA P-384").tag(KeyAlgorithm.ecdsaP384)
                    Text("RSA 3072").tag(KeyAlgorithm.rsa3072)
                    Text("RSA 4096").tag(KeyAlgorithm.rsa4096)
                }
                SecureField("Passphrase", text: $passphrase, prompt: Text("Optional"))
                SecureField("Repeat", text: $repeatPassphrase)
                Text("The key is kept in your Keychain. With a passphrase it is also encrypted when exported.")
                    .font(.caption).foregroundStyle(.secondary)
                if let error { Text(error).foregroundStyle(.red) }
            }
            .formStyle(.grouped)
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Generate", action: generate).keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || passphrase != repeatPassphrase || working)
            }
            .padding()
        }
        .frame(width: 440, height: 360)
    }

    private func generate() {
        guard let core = app.core else { return }
        working = true
        let (name, algorithm, passphrase) = (name, algorithm, passphrase)
        // RSA generation takes a moment; keep the UI responsive.
        Task.detached {
            do {
                _ = try core.generateKey(label: name, algorithm: algorithm, passphrase: passphrase.isEmpty ? nil : passphrase)
                await MainActor.run {
                    app.reload()
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    working = false
                }
            }
        }
    }
}

private struct SecurityKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var name = "YubiKey"
    @State private var pin = ""
    @State private var needsPin = false
    @State private var status: String?
    @State private var error: String?
    @State private var working = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                TextField("Name", text: $name)
                if needsPin {
                    SecureField("Security key PIN", text: $pin)
                }
                Text("Creates an ed25519-sk key. The private key never leaves the security key; every login needs a touch.")
                    .font(.caption).foregroundStyle(.secondary)
                if let status { Label(status, systemImage: "hand.tap").foregroundStyle(.blue) }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .formStyle(.grouped)
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                Button("Create", action: create).keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || working || (needsPin && pin.isEmpty))
            }
            .padding()
        }
        .frame(width: 440, height: 300)
    }

    private func create() {
        guard let core = app.core else { return }
        working = true
        error = nil
        status = "Touch your security key when it blinks"
        let (name, pin) = (name, needsPin ? pin : nil)
        // Blocks until the key is touched.
        Task.detached {
            do {
                _ = try core.generateSecurityKey(label: name, pin: pin)
                await MainActor.run {
                    app.reload()
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    working = false
                    status = nil
                    switch error {
                    case CoreError.PinRequired:
                        needsPin = true
                        self.error = "This security key needs its PIN."
                    case CoreError.PinInvalid:
                        needsPin = true
                        self.pin = ""
                        self.error = "Wrong PIN. Careful: the key locks after several wrong attempts."
                    default:
                        self.error = error.localizedDescription
                    }
                }
            }
        }
    }
}

private struct SmartcardSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var keys: [HardwareKeys.SmartcardKey] = []
    @State private var selection: HardwareKeys.SmartcardKey.ID?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            List(keys, selection: $selection) { key in
                VStack(alignment: .leading) {
                    Text(key.label)
                    Text(key.publicKey).font(.caption.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            .overlay {
                if keys.isEmpty {
                    ContentUnavailableView(
                        "No Smartcard Keys", systemImage: "creditcard",
                        description: Text("Insert a smartcard or YubiKey with a key and certificate in a PIV slot "
                            + "(macOS only shows slots with a certificate: `ykman piv keys generate` and "
                            + "`ykman piv certificates generate`), then refresh."))
                }
            }
            if let error { Text(error).foregroundStyle(.red).padding(.horizontal) }
            HStack {
                Button("Refresh", action: refresh)
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add", action: add).keyboardShortcut(.defaultAction).disabled(selection == nil)
            }
            .padding()
        }
        .frame(width: 520, height: 340)
        .onAppear(perform: refresh)
    }

    private func refresh() { keys = app.hardwareKeys.smartcardKeys() }

    private func add() {
        guard let key = keys.first(where: { $0.id == selection }) else { return }
        do {
            _ = try app.core?.addPlatformKey(
                label: key.label, publicKey: key.publicKey, key: .piv(tokenId: key.tokenID, slot: key.slot))
            app.reload()
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

private struct InstallKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let key: KeyRecord
    @State private var hostID = ""
    @State private var switchAuth = true
    @State private var state: (working: Bool, result: String?, failed: Bool) = (false, nil, false)

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Picker("Host", selection: $hostID) {
                    Text("Choose…").tag("")
                    ForEach(app.hosts, id: \.id) { host in
                        Text(host.label.isEmpty ? host.hostname : host.label).tag(host.id)
                    }
                }
                Toggle("Then use this key to log in to the host", isOn: $switchAuth)
                Text("Termiux logs in with the host's current settings and adds “\(key.label)” to ~/.ssh/authorized_keys.")
                    .font(.caption).foregroundStyle(.secondary)
                if let result = state.result {
                    Text(result).foregroundStyle(state.failed ? .red : .green)
                }
            }
            .formStyle(.grouped)
            HStack {
                if state.working { ProgressView().controlSize(.small) }
                Spacer()
                Button(state.result != nil && !state.failed ? "Done" : "Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Install", action: install).keyboardShortcut(.defaultAction)
                    .disabled(hostID.isEmpty || state.working)
            }
            .padding()
        }
        .frame(width: 440, height: 280)
    }

    private func install() {
        guard let core = app.core, let host = app.hosts.first(where: { $0.id == hostID }) else { return }
        state = (true, nil, false)
        let prompts = Prompts { _ in }
        Task {
            do {
                try await core.installPublicKey(hostId: host.id, keyId: key.id, ui: prompts)
                if switchAuth {
                    var updated = host
                    updated.auth = .key(keyId: key.id)
                    app.save(host: updated, password: .keep)
                }
                state = (false, "Installed on \(host.hostname).", false)
            } catch {
                state = (false, error.localizedDescription, true)
            }
        }
    }
}
