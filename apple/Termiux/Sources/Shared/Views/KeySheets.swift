import SwiftUI
import TermiuxCore

// Key sheets shared by the macOS Keys window and the iOS Keys screen.

struct KeyRow: View {
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

struct GenerateKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var algorithm = KeyAlgorithm.ed25519
    @State private var passphrase = ""
    @State private var repeatPassphrase = ""
    @State private var error: String?
    @State private var working = false

    var body: some View {
        EditorSheet(
            title: "New Key", confirmTitle: "Generate",
            canConfirm: !name.isEmpty && passphrase == repeatPassphrase && !working,
            height: 360, onConfirm: generate
        ) {
            Form {
                TextField("Name", text: $name, prompt: Text("e.g. laptop-2026")).technicalInput()
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
                if working { ProgressView() }
                if let error { Text(error).foregroundStyle(.red) }
            }
        }
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

struct SecurityKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var name = "YubiKey"
    @State private var pin = ""
    @State private var needsPin = false
    @State private var status: String?
    @State private var error: String?
    @State private var working = false

    var body: some View {
        EditorSheet(
            title: "New Security Key", confirmTitle: "Create",
            canConfirm: !name.isEmpty && !working && (!needsPin || !pin.isEmpty), height: 300, onConfirm: create
        ) {
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
        }
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

struct SmartcardSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var keys: [HardwareKeys.SmartcardKey] = []
    @State private var selection: HardwareKeys.SmartcardKey.ID?
    @State private var error: String?

    var body: some View {
        EditorSheet(
            title: "Smartcard Key", confirmTitle: "Add", canConfirm: selection != nil, width: 520, height: 360,
            onConfirm: add
        ) {
            List {
                ForEach(keys) { key in
                    Button { selection = key.id } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(key.label)
                                Text(key.publicKey).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            if selection == key.id { Image(systemName: "checkmark").foregroundStyle(.tint) }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                if let error { Text(error).foregroundStyle(.red) }
                Button("Refresh", action: refresh)
            }
            .overlay {
                if keys.isEmpty {
                    ContentUnavailableView(
                        "No Smartcard Keys", systemImage: "creditcard",
                        description: Text(Self.emptyHint))
                }
            }
        }
        .onAppear(perform: refresh)
    }

    #if os(macOS)
    private static let emptyHint = "Insert a smartcard or YubiKey with a key and certificate in a PIV slot "
        + "(macOS only shows slots with a certificate: `ykman piv keys generate` and "
        + "`ykman piv certificates generate`), then refresh."
    #else
    private static let emptyHint = "Connect a YubiKey with a key and certificate in a PIV slot and turn on its "
        + "smart card extension in the Yubico Authenticator app, then refresh."
    #endif

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

struct InstallKeySheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    let key: KeyRecord
    @State private var hostID = ""
    @State private var switchAuth = true
    @State private var state: (working: Bool, result: String?, failed: Bool) = (false, nil, false)

    var body: some View {
        EditorSheet(
            title: "Install Key", confirmTitle: "Install", cancelTitle: state.result != nil && !state.failed ? "Done" : "Cancel",
            canConfirm: !hostID.isEmpty && !state.working, height: 280, onConfirm: install
        ) {
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
                if state.working { ProgressView() }
                if let result = state.result {
                    Text(result).foregroundStyle(state.failed ? .red : .green)
                }
            }
        }
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
