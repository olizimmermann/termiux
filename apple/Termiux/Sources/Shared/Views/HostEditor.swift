import SwiftUI
import TermiuxCore

struct HostEditor: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss

    private enum AuthChoice: Hashable { case password, key, keyboardInteractive, agent }

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
    @State private var themeID: String
    @State private var jumpHostIDs: [String]
    @State private var forwards: [PortForwardRecord]
    @State private var editingForward: PortForwardRecord?

    init(host: HostRecord) {
        original = host
        _label = State(initialValue: host.label)
        _hostname = State(initialValue: host.hostname)
        _port = State(initialValue: String(host.port))
        _username = State(initialValue: host.username)
        _keepalive = State(initialValue: String(host.keepaliveSecs))
        _term = State(initialValue: host.term)
        _startupCommand = State(initialValue: host.startupCommand ?? "")
        _themeID = State(initialValue: host.themeId ?? "")
        _jumpHostIDs = State(initialValue: host.jumpHostIds)
        _forwards = State(initialValue: host.forwards)
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
        case .agent:
            _auth = State(initialValue: .agent)
            _keyId = State(initialValue: "")
        }
    }

    private var isNew: Bool { original.id.isEmpty }
    private var hasSavedPassword: Bool {
        if case .password(saved: true) = original.auth { return true }
        return false
    }

    var body: some View {
        EditorSheet(
            title: isNew ? "New Host" : "Edit Host", confirmTitle: isNew ? "Add" : "Save", canConfirm: isValid,
            width: 500, height: 680, onConfirm: save
        ) {
            Form {
                Section {
                    TextField("Label", text: $label, prompt: Text(hostname.isEmpty ? "My Server" : hostname))
                    TextField("Hostname", text: $hostname, prompt: Text("example.com or 192.168.1.10"))
                        .technicalInput()
                    TextField("Port", text: $port).numericInput()
                    TextField("Username", text: $username).technicalInput()
                }
                Section("Authentication") {
                    Picker("Method", selection: $auth) {
                        Text("Password").tag(AuthChoice.password)
                        Text("Key").tag(AuthChoice.key)
                        Text("Keyboard-interactive").tag(AuthChoice.keyboardInteractive)
                        if BuildFlavor.hasAgent || auth == .agent {
                            Text("SSH agent").tag(AuthChoice.agent)
                        }
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
                            Text("Add a key under Keys first.").font(.caption).foregroundStyle(.secondary)
                        }
                    case .keyboardInteractive:
                        Text("The server's prompts (password, one-time codes) are shown when connecting.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    case .agent:
                        Text("Uses the keys of your running ssh-agent (or the socket set in Settings › SSH).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    ForEach(Array(jumpHostIDs.enumerated()), id: \.offset) { index, id in
                        HStack {
                            Text("\(index + 1).").foregroundStyle(.secondary).monospacedDigit()
                            Text(hostName(id))
                            Spacer()
                            Button { jumpHostIDs.remove(at: index) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless)
                        }
                    }
                    Menu("Add Jump Host") {
                        ForEach(jumpCandidates, id: \.id) { host in
                            Button(host.label.isEmpty ? host.hostname : host.label) { jumpHostIDs.append(host.id) }
                        }
                    }
                    .disabled(jumpCandidates.isEmpty)
                } header: {
                    Text("Jump Hosts")
                } footer: {
                    Text("Connects through these hosts in order, like ssh -J. Each uses its own saved login.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Port Forwarding") {
                    ForEach(forwards, id: \.id) { forward in
                        HStack {
                            Text(forward.summary).font(.callout.monospaced())
                            if forward.autoStart {
                                Text("auto").font(.caption2).padding(.horizontal, 4).background(.tint.opacity(0.2), in: Capsule())
                            }
                            Spacer()
                            Button { editingForward = forward } label: { Image(systemName: "pencil") }
                                .buttonStyle(.borderless)
                            Button { forwards.removeAll { $0.id == forward.id } } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless)
                        }
                    }
                    Button("Add Forward…") { editingForward = .new }
                }
                Section("Appearance") {
                    Picker("Theme", selection: $themeID) {
                        Text("Default").tag("")
                        ForEach(app.themes, id: \.id) { theme in
                            Text(theme.name).tag(theme.id)
                        }
                    }
                }
                Section("Advanced") {
                    TextField("Keepalive (seconds)", text: $keepalive).numericInput()
                    TextField("Terminal type", text: $term).technicalInput()
                    TextField("Startup command", text: $startupCommand, prompt: Text("Optional, e.g. tmux attach"))
                        .technicalInput()
                }
            }
        }
        .sheet(item: $editingForward) { forward in
            ForwardEditor(forward: forward) { edited in
                if let index = forwards.firstIndex(where: { $0.id == edited.id }) {
                    forwards[index] = edited
                } else {
                    forwards.append(edited)
                }
            }
        }
    }

    private func hostName(_ id: String) -> String {
        guard let host = app.hosts.first(where: { $0.id == id }) else { return "Missing host" }
        return host.label.isEmpty ? host.hostname : host.label
    }

    /// Other saved hosts not already in the chain.
    private var jumpCandidates: [HostRecord] {
        app.hosts.filter { $0.id != original.id && !jumpHostIDs.contains($0.id) }
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
        case .agent: hostAuth = .agent
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
            startupCommand: startupCommand.isEmpty ? nil : startupCommand,
            themeId: themeID.isEmpty ? nil : themeID,
            jumpHostIds: jumpHostIDs,
            // Temporary ids of new forwards are dropped; the core assigns real ones.
            forwards: forwards.map { f in
                var f = f
                if f.id.hasPrefix("new-") { f.id = "" }
                return f
            })
        if app.save(host: host, password: passwordChange) != nil {
            dismiss()
        }
    }
}

extension PortForwardRecord: @retroactive Identifiable {
    /// Blank local forward; the temporary id lets the sheet tell new from existing ones.
    static var new: PortForwardRecord {
        PortForwardRecord(
            id: "new-" + UUID().uuidString, kind: .local, bindHost: "127.0.0.1", bindPort: 8080,
            targetHost: "localhost", targetPort: 80, autoStart: true)
    }

    var summary: String {
        let bind = "\(bindHost):\(bindPort)"
        switch kind {
        case .local: return "L \(bind) → \(targetHost):\(targetPort)"
        case .remote: return "R \(bind) → \(targetHost):\(targetPort)"
        case .dynamic: return "D \(bind) (SOCKS)"
        }
    }
}

private struct ForwardEditor: View {
    @Environment(\.dismiss) private var dismiss
    let original: PortForwardRecord
    let onSave: (PortForwardRecord) -> Void
    @State private var kind: ForwardKind
    @State private var bindHost: String
    @State private var bindPort: String
    @State private var targetHost: String
    @State private var targetPort: String
    @State private var autoStart: Bool

    init(forward: PortForwardRecord, onSave: @escaping (PortForwardRecord) -> Void) {
        original = forward
        self.onSave = onSave
        _kind = State(initialValue: forward.kind)
        _bindHost = State(initialValue: forward.bindHost)
        _bindPort = State(initialValue: String(forward.bindPort))
        _targetHost = State(initialValue: forward.targetHost)
        _targetPort = State(initialValue: String(forward.targetPort))
        _autoStart = State(initialValue: forward.autoStart)
    }

    var body: some View {
        EditorSheet(title: "Port Forward", confirmTitle: "Save", canConfirm: isValid, onConfirm: save) {
            Form {
                Picker("Type", selection: $kind) {
                    Text("Local (-L)").tag(ForwardKind.local)
                    Text("Remote (-R)").tag(ForwardKind.remote)
                    Text("Dynamic SOCKS (-D)").tag(ForwardKind.dynamic)
                }
                .pickerStyle(.segmented)
                Text(explanation).font(.caption).foregroundStyle(.secondary)
                TextField(kind == .remote ? "Server listens on" : "Listen on", text: $bindHost).technicalInput()
                TextField("Port", text: $bindPort).numericInput()
                if kind != .dynamic {
                    TextField(
                        kind == .local ? "Destination (from the server)" : "Destination (from \(Device.thisDevice))",
                        text: $targetHost
                    )
                    .technicalInput()
                    TextField("Destination port", text: $targetPort).numericInput()
                }
                Toggle("Start when connecting", isOn: $autoStart)
            }
        }
    }

    @MainActor private var explanation: String {
        switch kind {
        case .local: "Connections to \(Device.thisDevice) are carried to the destination as seen from the server, e.g. a database only the server can reach."
        case .remote: "The server listens and carries connections back to a destination reachable from \(Device.thisDevice)."
        case .dynamic: "A SOCKS5 proxy on \(Device.thisDevice); apps using it browse from the server's network."
        }
    }

    private var isValid: Bool {
        guard UInt16(bindPort) != nil, !bindHost.isEmpty else { return false }
        return kind == .dynamic || (!targetHost.isEmpty && UInt16(targetPort).map { $0 > 0 } == true)
    }

    private func save() {
        onSave(PortForwardRecord(
            id: original.id, kind: kind, bindHost: bindHost,
            bindPort: UInt16(bindPort) ?? 0, targetHost: kind == .dynamic ? "" : targetHost,
            targetPort: kind == .dynamic ? 0 : UInt16(targetPort) ?? 0, autoStart: autoStart))
        dismiss()
    }
}

extension HostRecord: @retroactive Identifiable {
    /// A blank record for the "new host" sheet; each call is a distinct sheet item.
    static var new: HostRecord {
        HostRecord(
            id: "", label: "", groupId: nil, hostname: "", port: 22, username: Self.defaultUsername,
            auth: .password(saved: false), keepaliveSecs: 30, term: "xterm-256color", startupCommand: nil,
            themeId: nil, jumpHostIds: [], forwards: [])
    }

    #if os(macOS)
    private static var defaultUsername: String { NSUserName() }
    #else
    private static var defaultUsername: String { "" }
    #endif
}

