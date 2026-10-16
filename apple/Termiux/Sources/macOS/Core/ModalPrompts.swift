import AppKit

/// Core prompts as application-modal alerts.
@MainActor
final class ModalPrompts: PromptPresenter {
    func present(_ request: PromptRequest, reply: @escaping @MainActor ([String]?) -> Void) {
        switch request {
        case .confirm(let title, let message, let action):
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = message
            alert.addButton(withTitle: action)
            alert.addButton(withTitle: "Cancel")
            reply(alert.runModal() == .alertFirstButtonReturn ? [] : nil)
        case .form(let title, let message, let fields):
            reply(Prompts.form(title: title, message: message, fields: fields.map { ($0.label, $0.secure) }))
        }
    }
}

extension Prompts {
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
