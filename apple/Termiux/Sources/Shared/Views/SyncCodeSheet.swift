import SwiftUI

struct CodeItem: Identifiable {
    let code: String
    var id: String { code }
}

/// Shows the sync code as text and QR code for joining other devices.
struct SyncCodeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let code: String

    var body: some View {
        VStack(spacing: 16) {
            Text("Sync Code").font(.title2.bold())
            Text("Enter or scan this code on your other devices. Keep it secret, and store a copy in your password manager: without it, a new device cannot read your synced data.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            if let qr = SyncController.qrCode(for: code) {
                Image(decorative: qr, scale: 1).interpolation(.none)
            }
            Text(code).font(.system(.body, design: .monospaced)).textSelection(.enabled).multilineTextAlignment(.center)
            HStack {
                Button("Copy") { Clipboard.copy(code) }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .buttonStyle(.bordered)
        }
        .padding(24)
        #if os(macOS)
        .frame(width: 460)
        #endif
    }
}
