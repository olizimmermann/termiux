import AppKit
import SwiftUI
import TermiuxCore

struct SyncSettingsView: View {
    @Environment(AppModel.self) private var app
    @State private var showingCode: String?
    @State private var joining = false
    @State private var error: String?

    private var sync: SyncController { app.sync }

    var body: some View {
        Form {
            if sync.isEnabled {
                enabled
            } else {
                setup
            }
            if let error {
                Text(error).foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .sheet(item: Binding(get: { showingCode.map(CodeItem.init) }, set: { showingCode = $0?.code })) { item in
            SyncCodeSheet(code: item.code)
        }
        .sheet(isPresented: $joining) {
            JoinSheet { folder, code in
                do {
                    try sync.joinVault(folder: folder, code: code)
                    joining = false
                } catch {
                    self.error = error.localizedDescription
                }
            }
        }
    }

    @ViewBuilder private var setup: some View {
        Section {
            Text("""
                Sync keeps hosts, keys, themes and trusted host keys in step across your devices. \
                Everything is end-to-end encrypted with a sync code only your devices know, and stored in \
                a folder you choose (iCloud Drive, Dropbox, Syncthing). There is no Termiux server.
                """)
            .foregroundStyle(.secondary)
        }
        Section {
            Button("Start Syncing on This Mac…") {
                guard let folder = sync.chooseFolder() else { return }
                do {
                    showingCode = try sync.createVault(folder: folder)
                } catch {
                    self.error = error.localizedDescription
                }
            }
            Button("Join with a Sync Code from Another Device…") { joining = true }
        }
    }

    @ViewBuilder private var enabled: some View {
        Section("Status") {
            LabeledContent("Folder") {
                Text(sync.folder?.path(percentEncoded: false) ?? "").lineLimit(1).truncationMode(.middle)
            }
            LabeledContent("Last sync") {
                if sync.syncing {
                    ProgressView().controlSize(.small)
                } else if let error = sync.lastError {
                    Text(error).foregroundStyle(.red)
                } else if let date = sync.lastSync {
                    Text("\(date.formatted(date: .omitted, time: .shortened)) · \(devices)")
                } else {
                    Text("Not yet")
                }
            }
            Button("Sync Now") { Task { await sync.syncNow() } }.disabled(sync.syncing)
        }
        Section {
            Toggle("Include passwords and private keys", isOn: Binding(
                get: { sync.settings?.includeSecrets ?? false },
                set: { sync.setIncludeSecrets($0) }))
        } footer: {
            Text("""
                Off: only hosts, public keys and settings sync; passwords and private keys stay on each \
                device. YubiKey keys always sync (they only work with the YubiKey); Touch ID keys never do.
                """)
            .font(.caption).foregroundStyle(.secondary)
        }
        Section {
            Button("Show Sync Code…") {
                let alert = NSAlert()
                alert.messageText = "Show the sync code?"
                alert.informativeText = "Anyone with this code and access to the sync folder can read your synced data."
                alert.addButton(withTitle: "Show")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() == .alertFirstButtonReturn { showingCode = sync.syncCode() }
            }
            Button("Stop Syncing on This Mac", role: .destructive) { sync.leave() }
        } footer: {
            Text("Stopping keeps everything on this Mac; it just no longer exchanges changes.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var devices: String {
        let n = Int(sync.lastReport?.devices ?? 0)
        return n == 1 ? "1 other device" : "\(n) other devices"
    }
}

private struct CodeItem: Identifiable {
    let code: String
    var id: String { code }
}

private struct SyncCodeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let code: String

    var body: some View {
        VStack(spacing: 16) {
            Text("Sync Code").font(.title2.bold())
            Text("Enter or scan this code on your other devices. Keep it secret, and store a copy in your password manager: without it, a new device cannot read your synced data.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            if let qr = SyncController.qrCode(for: code) {
                Image(nsImage: qr).interpolation(.none)
            }
            Text(code).font(.system(.body, design: .monospaced)).textSelection(.enabled).multilineTextAlignment(.center)
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(code, forType: .string)
                }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}

private struct JoinSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppModel.self) private var app
    let onJoin: (URL, String) -> Void
    @State private var code = ""
    @State private var folder: URL?

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Text("On your other device, open Settings › Sync › Show Sync Code.").foregroundStyle(.secondary)
                TextField("Sync code", text: $code, prompt: Text("ABCD-EFGH-…"), axis: .vertical)
                    .font(.body.monospaced())
                LabeledContent("Folder") {
                    HStack {
                        Text(folder?.path(percentEncoded: false) ?? "Not chosen").lineLimit(1).truncationMode(.middle)
                        Button("Choose…") { folder = app.sync.chooseFolder() }
                    }
                }
                Text("Choose the same synced folder the other device uses.").font(.caption).foregroundStyle(.secondary)
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Join") { if let folder { onJoin(folder, code) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(folder == nil || code.count < 20)
            }
            .padding()
        }
        .frame(width: 480, height: 330)
    }
}
