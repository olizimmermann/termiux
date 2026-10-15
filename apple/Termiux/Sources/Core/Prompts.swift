import AppKit
import TermiuxCore

/// Modal prompts for the core. The core calls these on its own threads and waits, so each
/// hops to the main thread synchronously. The main thread is never blocked by the core
/// (connect is async), so this cannot deadlock.
final class Prompts: Interaction, @unchecked Sendable {
    /// Receives status lines such as "Touch your security key".
    let onStatus: @Sendable (String) -> Void

    init(onStatus: @escaping @Sendable (String) -> Void) {
        self.onStatus = onStatus
    }

    func confirmNewHost(info: HostKeyInfo) -> Bool {
        onMain {
            let alert = NSAlert()
            alert.messageText = "Trust \(info.host)?"
            alert.informativeText = """
                This is the first connection to \(info.host):\(info.port). Check that the fingerprint \
                matches the server before trusting it.

                \(info.algorithm)
                \(info.fingerprint)
                """
            alert.addButton(withTitle: "Trust and Connect")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        }
    }

    func keyboardInteractive(name: String, instructions: String, prompts: [InteractivePrompt]) -> [String]? {
        let title = name.isEmpty ? "Authentication" : name
        return onMain {
            Self.form(title: title, message: instructions, fields: prompts.map { ($0.text, !$0.echo) })
        }
    }

    func askSecret(title: String, message: String) -> String? {
        onMain { Self.form(title: title, message: message, fields: [("", true)])?.first }
    }

    func status(message: String) {
        onStatus(message)
    }

    private func onMain<T: Sendable>(_ body: @MainActor () -> T) -> T {
        if Thread.isMainThread { return MainActor.assumeIsolated(body) }
        return DispatchQueue.main.sync { MainActor.assumeIsolated(body) }
    }

    /// Alert with one text field per prompt; `secure` hides input. Returns nil on cancel.
    @MainActor
    static func form(title: String, message: String, fields: [(label: String, secure: Bool)]) -> [String]? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        var inputs: [NSTextField] = []
        for field in fields {
            if !field.label.isEmpty {
                stack.addArrangedSubview(NSTextField(labelWithString: field.label))
            }
            let input = field.secure ? NSSecureTextField() : NSTextField()
            input.frame.size.width = 260
            input.widthAnchor.constraint(equalToConstant: 260).isActive = true
            stack.addArrangedSubview(input)
            inputs.append(input)
        }
        stack.layoutSubtreeIfNeeded()
        stack.frame.size = stack.fittingSize
        alert.accessoryView = stack
        alert.window.initialFirstResponder = inputs.first
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return inputs.map(\.stringValue)
    }
}
