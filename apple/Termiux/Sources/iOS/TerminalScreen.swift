import SwiftUI
import TermiuxCore
import UIKit

/// One session tab: a single terminal, or on iPad a tree of split panes. SwiftTerm supplies the
/// keyboard accessory row (Esc, Ctrl, Tab, arrows and more) above the software keyboard.
struct TerminalScreen: View {
    @Environment(AppModel.self) private var app
    @Environment(\.horizontalSizeClass) private var sizeClass
    let tab: WorkspaceTab

    var body: some View {
        PaneTreeView(node: tab.root, tab: tab) { session in
            TerminalPaneView(session: session, tab: tab)
        }
        .background(background)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(background, for: .navigationBar)
        .toolbarColorScheme(isDark ? .dark : .light, for: .navigationBar)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if sizeClass == .regular {
                    Menu("Split", systemImage: "rectangle.split.2x1") {
                        Button("Split Right", systemImage: "rectangle.split.2x1") { app.splitFocused(.horizontal) }
                        Button("Split Down", systemImage: "rectangle.split.1x2") { app.splitFocused(.vertical) }
                    }
                }
                Button("Keyboard", systemImage: "keyboard") { toggleKeyboard() }
                Menu("Session", systemImage: "ellipsis.circle") {
                    if let session = tab.focused {
                        Button("Reconnect", systemImage: "arrow.clockwise") { session.reconnect() }
                        Button("Paste", systemImage: "doc.on.clipboard") { session.surface.paste() }
                        Divider()
                        if tab.sessions.count > 1 {
                            Button("Close Pane", systemImage: "xmark.square") { app.close(session, in: tab) }
                        }
                    }
                    Button("Close Session", systemImage: "xmark", role: .destructive) { app.close(tab) }
                }
            }
        }
    }

    private var title: String {
        guard let session = tab.focused else { return tab.title }
        return session.terminalTitle ?? session.name
    }

    private var background: Color {
        Color(hex: tab.focused.flatMap { app.theme(for: $0)?.background } ?? "", fallback: .black)
    }

    /// Light or dark bar text to match the theme background.
    private var isDark: Bool {
        guard let hex = tab.focused.flatMap({ app.theme(for: $0)?.background }), let color = UIColor(hex: hex)
        else { return true }
        var (r, g, b, a): (CGFloat, CGFloat, CGFloat, CGFloat) = (0, 0, 0, 0)
        color.getRed(&r, green: &g, blue: &b, alpha: &a)
        return 0.299 * r + 0.587 * g + 0.114 * b < 0.5
    }

    private func toggleKeyboard() {
        guard let session = tab.focused else { return }
        let view = session.surface.view
        if view.isFirstResponder {
            view.resignFirstResponder()
        } else {
            session.surface.focus()
        }
    }
}

/// One pane: the terminal with its connection state overlay. Tapping a pane focuses it.
private struct TerminalPaneView: View {
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
                    Color.black.opacity(0.25).allowsHitTesting(false)
                }
            }
            .onChange(of: isFocused, initial: true) { _, focused in
                if focused { DispatchQueue.main.async { session.surface.focus() } }
            }
    }
}

/// Embeds the model-owned UIKit terminal view.
private struct TerminalViewHost: UIViewRepresentable {
    let view: UIView

    func makeUIView(context: Context) -> UIView {
        let container = UIView()
        attach(to: container)
        return container
    }

    func updateUIView(_ container: UIView, context: Context) {
        if view.superview !== container { attach(to: container) }
    }

    private func attach(to container: UIView) {
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
