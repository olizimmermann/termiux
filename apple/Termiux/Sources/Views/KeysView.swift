import AppKit
import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

/// Imported SSH keys. Generation, export and PIV come later.
struct KeysView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var selection: String?
    @State private var importError: String?

    var body: some View {
        VStack(spacing: 0) {
            List(selection: $selection) {
                ForEach(app.keys, id: \.id) { key in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(key.label)
                            if key.kind == .securityKey {
                                Text("Security key").font(.caption2).padding(.horizontal, 5)
                                    .background(.tint.opacity(0.2), in: Capsule())
                            }
                        }
                        Text(key.publicKey).font(.caption.monospaced()).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    .tag(key.id)
                    .contextMenu {
                        Button("Copy Public Key") { copy(key.publicKey) }
                        Button("Delete", role: .destructive) { app.delete(key: key) }
                    }
                }
            }
            .overlay {
                if app.keys.isEmpty {
                    Text("No keys. Import an OpenSSH private key, e.g. ~/.ssh/id_ed25519.")
                        .foregroundStyle(.secondary).multilineTextAlignment(.center).padding()
                }
            }
            HStack {
                Button("Import…", action: importKey)
                Button("Copy Public Key") {
                    if let key = selectedKey { copy(key.publicKey) }
                }
                .disabled(selectedKey == nil)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 520, height: 380)
        .alert("Import failed", isPresented: .constant(importError != nil)) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
        }
    }

    private var selectedKey: KeyRecord? { app.keys.first { $0.id == selection } }

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
            } catch CoreError.InvalidKey(let message) where message == "key is encrypted" {
                guard let passphrase = Prompts.form(
                    title: "Key passphrase", message: "“\(label)” is protected by a passphrase.",
                    fields: [("", true)])?.first
                else { return }
                _ = try app.importKey(label: label, contents: contents, passphrase: passphrase)
            }
        } catch {
            importError = error.localizedDescription
        }
    }
}
