import SwiftUI
import TermiuxCore

/// Hosts a session's terminal surface plus its connection state overlay.
struct TerminalPane: View {
    @Environment(AppModel.self) private var app
    let session: TerminalSessionModel
    let tab: WorkspaceTab

    private var isFocused: Bool { tab.focusedID == session.id }

    var body: some View {
        TerminalViewHost(view: session.surface.view)
            .background(Color(hex: app.theme(for: session)?.background ?? "", fallback: .black))
            .overlay { SessionOverlay(session: session) { app.close(session, in: tab) } }
            .overlay(alignment: .topTrailing) { ForwardsButton(session: session) }
            .overlay {
                // Dim unfocused panes when the tab is split.
                if !isFocused && tab.sessions.count > 1 {
                    Color.black.opacity(0.18).allowsHitTesting(false)
                }
            }
            .onChange(of: isFocused, initial: true) { _, focused in
                if focused { DispatchQueue.main.async { session.surface.focus() } }
            }
    }
}

/// Embeds an existing (model-owned) AppKit terminal view.
private struct TerminalViewHost: NSViewRepresentable {
    let view: NSView

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
    }
}
