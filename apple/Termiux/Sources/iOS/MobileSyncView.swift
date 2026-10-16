import SwiftUI
import TermiuxCore
import VisionKit

struct MobileSyncView: View {
    @Environment(AppModel.self) private var app
    @State private var showingCode: String?
    @State private var choosingFolder = false
    @State private var joining = false
    @State private var confirmShowCode = false
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
        .navigationTitle("Sync")
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
        .fileImporter(isPresented: $choosingFolder, allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let folder):
                do {
                    showingCode = try sync.createVault(folder: folder)
                } catch {
                    self.error = error.localizedDescription
                }
            case .failure(let failure):
                error = failure.localizedDescription
            }
        }
        .confirmationDialog("Show the sync code?", isPresented: $confirmShowCode, titleVisibility: .visible) {
            Button("Show") { showingCode = sync.syncCode() }
        } message: {
            Text("Anyone with this code and access to the sync folder can read your synced data.")
        }
    }

    @ViewBuilder private var setup: some View {
        Section {
            Text("""
                Sync keeps hosts, keys, themes and trusted host keys in step across your devices. \
                Everything is end-to-end encrypted with a sync code only your devices know, and stored in \
                a folder you choose (iCloud Drive, Dropbox). There is no Termiux server.
                """)
            .foregroundStyle(.secondary)
        }
        Section {
            Button("Join with a Sync Code from Another Device…") { joining = true }
            Button("Start Syncing on \(Device.thisDevice.replacingOccurrences(of: "this ", with: "This "))…") {
                choosingFolder = true
            }
        } footer: {
            Text("Already syncing on your Mac? Join with its code and choose the same folder in iCloud Drive.")
        }
    }

    @ViewBuilder private var enabled: some View {
        Section("Status") {
            LabeledContent("Folder") {
                Text(sync.folder?.lastPathComponent ?? "").lineLimit(1).truncationMode(.middle)
            }
            LabeledContent("Last sync") {
                if sync.syncing {
                    ProgressView()
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
                device. YubiKey keys always sync (they only work with the YubiKey); Face ID and Touch ID keys never do.
                """)
        }
        Section {
            Button("Show Sync Code…") { confirmShowCode = true }
            Button("Stop Syncing", role: .destructive) { sync.leave() }
        } footer: {
            Text("Stopping keeps everything on \(Device.thisDevice); it just no longer exchanges changes.")
        }
    }

    private var devices: String {
        let n = Int(sync.lastReport?.devices ?? 0)
        return n == 1 ? "1 other device" : "\(n) other devices"
    }
}

private struct JoinSheet: View {
    let onJoin: (URL, String) -> Void
    @State private var code = ""
    @State private var folder: URL?
    @State private var choosingFolder = false
    @State private var scanning = false

    var body: some View {
        EditorSheet(title: "Join Sync", confirmTitle: "Join", canConfirm: folder != nil && code.count >= 20) {
            if let folder { onJoin(folder, code) }
        } content: {
            Form {
                Section {
                    TextField("Sync code", text: $code, prompt: Text("ABCD-EFGH-…"), axis: .vertical)
                        .font(.body.monospaced())
                        .technicalInput()
                        .textInputAutocapitalization(.characters)
                    if QRScanner.isAvailable {
                        Button("Scan QR Code", systemImage: "qrcode.viewfinder") { scanning = true }
                    }
                } footer: {
                    Text("On your other device, open Settings › Sync › Show Sync Code.")
                }
                Section {
                    Button(folder?.lastPathComponent ?? "Choose Folder…") { choosingFolder = true }
                } header: {
                    Text("Folder")
                } footer: {
                    Text("Choose the same synced folder the other device uses, e.g. iCloud Drive › Termiux.")
                }
            }
        }
        .fileImporter(isPresented: $choosingFolder, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result { folder = url }
        }
        .sheet(isPresented: $scanning) {
            QRScanner { value in
                code = value
                scanning = false
            }
            .ignoresSafeArea()
        }
    }
}

/// Camera QR code reader (VisionKit).
private struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    @MainActor static var isAvailable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var done = false

        init(onCode: @escaping (String) -> Void) {
            self.onCode = onCode
        }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let barcode) in items {
                guard !done, let value = barcode.payloadStringValue else { continue }
                done = true
                scanner.stopScanning()
                onCode(value)
            }
        }
    }
}
