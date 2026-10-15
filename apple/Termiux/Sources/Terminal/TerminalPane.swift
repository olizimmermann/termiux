import SwiftTerm
import SwiftUI
import TermiuxCore

/// Hosts a session's terminal view plus its connection state overlay.
struct TerminalPane: View {
    @Environment(AppModel.self) private var app
    let session: TerminalSessionModel

    var body: some View {
        TerminalViewHost(view: session.terminalView)
            .overlay { overlay }
    }

    @ViewBuilder private var overlay: some View {
        switch session.state {
        case .running:
            EmptyView()
        case .connecting(let status):
            Banner {
                ProgressView().controlSize(.small)
                Text(status ?? "Connecting…")
            }
        case .ended(let end):
            Banner {
                Text(endMessage(end))
                Button("Reconnect") { session.reconnect() }.keyboardShortcut(.defaultAction)
                Button("Close") { app.close(session) }
            }
        case .failed(let message):
            Banner {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
                Text(message).lineLimit(3)
                Button("Retry") { session.reconnect() }.keyboardShortcut(.defaultAction)
                Button("Close") { app.close(session) }
            }
        case .hostKeyChanged(let host, let port, let fingerprint, let previous):
            HostKeyChangedView(host: host, port: port, fingerprint: fingerprint, previous: previous) {
                app.forgetHostKey(host: host, port: port)
                session.reconnect()
            } onClose: {
                app.close(session)
            }
        }
    }

    private func endMessage(_ end: SessionEnd) -> String {
        switch end.reason {
        case .connectionLost: "Connection lost"
        case .exited: end.exitStatus.map { "Session ended (exit \($0))" } ?? "Session ended"
        case .userClosed: "Closed"
        }
    }
}

private struct Banner<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack {
            Spacer()
            HStack(spacing: 10) { content }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
                .padding()
        }
    }
}

private struct HostKeyChangedView: View {
    let host: String
    let port: UInt16
    let fingerprint: String
    let previous: String
    let onAccept: () -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Host key changed", systemImage: "exclamationmark.shield.fill")
                .font(.title2.bold())
                .foregroundStyle(.red)
            Text("""
                The server at \(host):\(port) presented a different key than before. This happens when \
                the server was reinstalled, but it can also mean someone is intercepting the connection. \
                Only continue if you know why the key changed.
                """)
            Grid(alignment: .leading) {
                GridRow { Text("Previous").foregroundStyle(.secondary); Text(previous).textSelection(.enabled) }
                GridRow { Text("Now").foregroundStyle(.secondary); Text(fingerprint).textSelection(.enabled) }
            }
            .font(.system(.body, design: .monospaced))
            HStack {
                Spacer()
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                Button("Trust New Key and Connect", role: .destructive, action: onAccept)
            }
        }
        .padding(20)
        .frame(maxWidth: 560)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .padding()
    }
}

/// Embeds an existing (model-owned) AppKit terminal view.
private struct TerminalViewHost: NSViewRepresentable {
    let view: TerminalView

    func makeNSView(context: Context) -> NSView {
        let container = NSView()
        attach(to: container)
        return container
    }

    func updateNSView(_ container: NSView, context: Context) {
        if view.superview !== container { attach(to: container) }
    }

    private func attach(to container: NSView) {
        view.removeFromSuperview()
        view.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(view)
        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            view.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            view.topAnchor.constraint(equalTo: container.topAnchor),
            view.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        DispatchQueue.main.async { [view] in view.window?.makeFirstResponder(view) }
    }
}
