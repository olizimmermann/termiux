import SwiftUI
import TermiuxCore

struct HostEditor: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss

    private enum AuthChoice: Hashable { case password, key, keyboardInteractive }

    let original: HostRecord
    @State private var label: String
    @State private var hostname: String
    @State private var port: String
    @State private var username: String
    @State private var auth: AuthChoice
    @State private var keyId: String
    @State private var password = ""
    @State private var clearPassword = false
    @State private var keepalive: String
    @State private var term: String
    @State private var startupCommand: String

    init(host: HostRecord) {
        original = host
        _label = State(initialValue: host.label)
        _hostname = State(initialValue: host.hostname)
        _port = State(initialValue: String(host.port))
        _username = State(initialValue: host.username)
        _keepalive = State(initialValue: String(host.keepaliveSecs))
        _term = State(initialValue: host.term)
        _startupCommand = State(initialValue: host.startupCommand ?? "")
        switch host.auth {
        case .password:
            _auth = State(initialValue: .password)
            _keyId = State(initialValue: "")
        case .key(let id):
            _auth = State(initialValue: .key)
            _keyId = State(initialValue: id)
        case .keyboardInteractive:
            _auth = State(initialValue: .keyboardInteractive)
            _keyId = State(initialValue: "")
        }
    }

    private var isNew: Bool { original.id.isEmpty }
    private var hasSavedPassword: Bool {
        if case .password(saved: true) = original.auth { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Label", text: $label, prompt: Text(hostname.isEmpty ? "My Server" : hostname))
                    TextField("Hostname", text: $hostname, prompt: Text("example.com or 192.168.1.10"))
                    TextField("Port", text: $port)
                    TextField("Username", text: $username)
                }
                Section("Authentication") {
                    Picker("Method", selection: $auth) {
                        Text("Password").tag(AuthChoice.password)
                        Text("Key").tag(AuthChoice.key)
                        Text("Keyboard-interactive").tag(AuthChoice.keyboardInteractive)
                    }
                    switch auth {
                    case .password:
                        SecureField(
                            "Password", text: $password,
                            prompt: Text(hasSavedPassword && !clearPassword ? "Saved (unchanged)" : "Ask when connecting"))
                        if hasSavedPassword {
                            Toggle("Forget saved password", isOn: $clearPassword)
                        }
                    case .key:
                        Picker("Key", selection: $keyId) {
                            Text("Choose…").tag("")
                            ForEach(app.keys, id: \.id) { key in
                                Text(key.label).tag(key.id)
                            }
                        }
                        if app.keys.isEmpty {
                            Text("Import a key in the Keys window first.").font(.caption).foregroundStyle(.secondary)
                        }
                    case .keyboardInteractive:
                        Text("The server's prompts (password, one-time codes) are shown when connecting.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Section("Advanced") {
                    TextField("Keepalive (seconds)", text: $keepalive)
                    TextField("Terminal type", text: $term)
                    TextField("Startup command", text: $startupCommand, prompt: Text("Optional, e.g. tmux attach"))
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(isNew ? "Add" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid)
            }
            .padding()
        }
        .frame(width: 460, height: 560)
    }

    private var isValid: Bool {
        !hostname.trimmingCharacters(in: .whitespaces).isEmpty && UInt16(port) != nil
            && !username.trimmingCharacters(in: .whitespaces).isEmpty && (auth != .key || !keyId.isEmpty)
    }

    private func save() {
        let hostAuth: HostAuth
        switch auth {
        case .password: hostAuth = .password(saved: hasSavedPassword)
        case .key: hostAuth = .key(keyId: keyId)
        case .keyboardInteractive: hostAuth = .keyboardInteractive
        }
        let passwordChange: PasswordChange =
            if auth != .password { .keep }
            else if !password.isEmpty { .set(password: password) }
            else if clearPassword { .clear }
            else { .keep }
        let host = HostRecord(
            id: original.id,
            label: label.trimmingCharacters(in: .whitespaces),
            groupId: original.groupId,
            hostname: hostname.trimmingCharacters(in: .whitespaces),
            port: UInt16(port) ?? 22,
            username: username.trimmingCharacters(in: .whitespaces),
            auth: hostAuth,
            keepaliveSecs: UInt32(keepalive) ?? 30,
            term: term.trimmingCharacters(in: .whitespaces),
            startupCommand: startupCommand.isEmpty ? nil : startupCommand)
        if app.save(host: host, password: passwordChange) != nil {
            dismiss()
        }
    }
}
