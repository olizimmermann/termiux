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
