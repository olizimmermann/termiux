import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

/// The user's SSH keys on iPhone and iPad.
struct MobileKeysView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var sheet: Sheet?
    @State private var importing = false
    @State private var exportFile: ExportFile?
    @State private var deleting: KeyRecord?
    @State private var message: (title: String, text: String)?

    enum Sheet: Identifiable {
        case generate, smartcard
        case install(KeyRecord)
        var id: String {
            switch self {
            case .generate: "generate"
            case .smartcard: "smartcard"
            case .install(let key): "install-\(key.id)"
            }
        }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(app.keys, id: \.id) { key in
                    Menu {
                        menu(for: key)
                    } label: {
                        KeyRow(key: key).tint(.primary)
                    }
                    .swipeActions {
                        Button("Delete", role: .destructive) { deleting = key }
                    }
                }
                if app.keys.contains(where: { $0.kind == .securityKey }) {
                    Text("FIDO2 security keys (ed25519-sk) synced from a Mac cannot sign on iPhone or iPad yet.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .overlay {
                if app.keys.isEmpty {
                    ContentUnavailableView(
                        "No Keys", systemImage: "key",
                        description: Text("Generate a key, import one from Files, or create a Face ID key."))
                }
            }
            .navigationTitle("Keys")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Menu("Add", systemImage: "plus") {
                        Button("Generate Key…", systemImage: "key") { sheet = .generate }
                        if HardwareKeys.secureEnclaveAvailable {
                            Button("Face ID / Touch ID Key…", systemImage: "faceid") {
                                Task { await createSecureEnclaveKey() }
                            }
                        }
                        Button("Smartcard (PIV) Key…", systemImage: "creditcard") { sheet = .smartcard }
                        Divider()
                        Button("Import from Files…", systemImage: "folder") { importing = true }
                        Button("Paste Private Key", systemImage: "doc.on.clipboard") {
                            guard let text = UIPasteboard.general.string else { return }
                            Task { await importKey(label: "Pasted key", contents: text) }
                        }
                    }
                }
            }
            .sheet(item: $sheet) { sheet in
                switch sheet {
                case .generate: GenerateKeySheet()
                case .smartcard: SmartcardSheet()
                case .install(let key): InstallKeySheet(key: key)
                }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
                guard case .success(let url) = result else { return }
                Task { await importFile(url) }
            }
            .fileExporter(
                isPresented: .constant(exportFile != nil), document: exportFile, contentType: .plainText,
                defaultFilename: exportFile?.name
            ) { _ in
                exportFile = nil
            }
            .confirmationDialog(
                "Delete “\(deleting?.label ?? "")”?", isPresented: .constant(deleting != nil), titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let key = deleting { app.delete(key: key) }
                    deleting = nil
                }
                Button("Cancel", role: .cancel) { deleting = nil }
            } message: {
                Text(deleting.map(deleteWarning) ?? "")
            }
            .alert(message?.title ?? "", isPresented: .constant(message != nil)) {
                Button("OK") { message = nil }
            } message: {
                Text(message?.text ?? "")
            }
        }
    }

    @ViewBuilder private func menu(for key: KeyRecord) -> some View {
        Button("Copy Public Key", systemImage: "doc.on.doc") { Clipboard.copy(key.publicKey) }
        ShareLink("Share Public Key", item: key.publicKey)
        Button("Install on Host…", systemImage: "server.rack") { sheet = .install(key) }
        if key.kind == .software || key.kind == .securityKey {
            Button("Export Private Key…", systemImage: "square.and.arrow.up") { Task { await export(key) } }
        }
        Divider()
        Button("Delete…", systemImage: "trash", role: .destructive) { deleting = key }
    }

    private func deleteWarning(_ key: KeyRecord) -> String {
        switch key.kind {
        case .securityKey: "The key handle is removed from Termiux. The credential stays on your security key."
        case .piv: "The key is removed from Termiux. It stays on the smartcard."
        case .secureEnclave: "The key is destroyed. Servers that trust it will no longer accept \(Device.thisDevice)."
        case .software: "The private key is deleted from \(Device.thisDevice). Export it first if you still need it."
        }
    }

    private func importFile(_ url: URL) async {
        do {
            _ = try await app.importKeyFile(url)
        } catch {
            message = ("Import failed", error.localizedDescription)
        }
    }

    private func importKey(label: String, contents: String) async {
        do {
            _ = try await app.importKeyAskingPassphrase(label: label, contents: contents)
        } catch {
            message = ("Import failed", error.localizedDescription)
        }
    }

    private func createSecureEnclaveKey() async {
        guard let name = await Prompts.ask(.form(
            title: "New Face ID / Touch ID Key",
            message: "The key is created in the Secure Enclave of \(Device.thisDevice) and can never be exported. "
                + "Each login asks for Face ID or Touch ID.",
            fields: [PromptField(label: "Name", secure: false)]))?.first, !name.isEmpty
        else { return }
        do {
            let (tag, publicKey) = try app.hardwareKeys.createSecureEnclaveKey(label: name)
            _ = try app.core?.addPlatformKey(label: name, publicKey: publicKey, key: .secureEnclave(tag: tag))
            app.reload()
        } catch {
            message = ("Could not create the key", error.localizedDescription)
        }
    }

    private func export(_ key: KeyRecord) async {
        var passphrase: String?
        if key.kind == .software {
            guard let fields = await Prompts.ask(.form(
                title: "Export “\(key.label)”",
                message: "Anyone with this file can log in as you. Protect it with a passphrase unless you know "
                    + "you don't need one.",
                fields: [PromptField(label: "Passphrase (optional)", secure: true), PromptField(label: "Repeat", secure: true)]))
            else { return }
            guard fields[0] == fields[1] else {
                message = ("Export cancelled", "The passphrases did not match.")
                return
            }
            passphrase = fields[0].isEmpty ? nil : fields[0]
        }
        do {
            let contents = try app.core?.exportPrivateKey(id: key.id, passphrase: passphrase) ?? ""
            exportFile = ExportFile(name: key.label.replacingOccurrences(of: " ", with: "_"), text: contents)
        } catch {
            message = ("Export failed", error.localizedDescription)
        }
    }
}

/// A private key file handed to the system file exporter.
struct ExportFile: FileDocument {
    static let readableContentTypes: [UTType] = [.plainText]
    let name: String
    let text: String

    init(name: String, text: String) {
        self.name = name
        self.text = text
    }

    init(configuration: ReadConfiguration) throws {
        name = ""
        text = String(decoding: configuration.file.regularFileContents ?? Data(), as: UTF8.self)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
