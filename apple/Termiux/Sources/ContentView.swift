import SwiftUI
import TermiuxCore

/// Spike UI: quick-connect form, then a single terminal pane.
struct ContentView: View {
    @State private var hostname = "127.0.0.1"
    @State private var port = "2222"
    @State private var username = "termiux"
    @State private var password = ""
    @State private var connection: TerminalConnection?
    @State private var error: String?
    @State private var connecting = false

    var body: some View {
        if let connection {
            TerminalPane(connection: connection)
                .ignoresSafeArea()
        } else {
            Form {
                TextField("Host", text: $hostname)
                TextField("Port", text: $port)
                TextField("User", text: $username)
                SecureField("Password", text: $password)
                if let error {
                    Text(error).foregroundStyle(.red)
                }
                Button(connecting ? "Connecting…" : "Connect", action: connect)
                    .keyboardShortcut(.defaultAction)
                    .disabled(connecting)
            }
            .formStyle(.grouped)
            .frame(maxWidth: 420)
            .padding()
        }
    }

    private func connect() {
        connecting = true
        error = nil
        let conn = TerminalConnection()
        let params = ConnectParams(
            hostname: hostname, port: UInt16(port) ?? 22, username: username,
            password: password, privateKey: nil, passphrase: nil, cols: 80, rows: 24)
        Task {
            do {
                try await conn.connect(params)
                connection = conn
            } catch {
                self.error = "\(error)"
            }
            connecting = false
        }
    }
}
