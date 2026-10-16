import SwiftUI
import TermiuxCore
import UIKit

/// Full-screen terminal for one session. SwiftTerm supplies the keyboard accessory row
/// (Esc, Ctrl, Tab, arrows and more) above the software keyboard.
struct TerminalScreen: View {
    @Environment(AppModel.self) private var app
    @Environment(\.horizontalSizeClass) private var sizeClass
    let session: TerminalSessionModel
    let tab: WorkspaceTab

    var body: some View {
        TerminalViewHost(view: session.surface.view)
            .background(background)
            .overlay { SessionOverlay(session: session) { app.close(tab) } }
            .overlay(alignment: .topTrailing) { ForwardsButton(session: session) }
            .navigationTitle(session.terminalTitle ?? session.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(background, for: .navigationBar)
            .toolbarColorScheme(isDark ? .dark : .light, for: .navigationBar)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button("Keyboard", systemImage: "keyboard") { toggleKeyboard() }
                    Menu("Session", systemImage: "ellipsis.circle") {
                        Button("Reconnect", systemImage: "arrow.clockwise") { session.reconnect() }
                        Button("Paste", systemImage: "doc.on.clipboard") { session.surface.paste() }
                        Divider()
                        Button("Close Session", systemImage: "xmark", role: .destructive) { app.close(tab) }
                    }
                }
            }
            .onAppear { DispatchQueue.main.async { session.surface.focus() } }
    }

    private var background: Color {
        Color(hex: app.theme(for: session)?.background ?? "", fallback: .black)
    }

    /// Light or dark bar text to match the theme background.
    private var isDark: Bool {
        guard let color = UIColor(hex: app.theme(for: session)?.background ?? "") else { return true }
        var (r, g, b, a): (CGFloat, CGFloat, CGFloat, CGFloat) = (0, 0, 0, 0)
        color.getRed(&r, green: &g, blue: &b, alpha: &a)
        return 0.299 * r + 0.587 * g + 0.114 * b < 0.5
    }

    private func toggleKeyboard() {
        let view = session.surface.view
        if view.isFirstResponder {
            view.resignFirstResponder()
        } else {
            session.surface.focus()
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
