import UIKit

/// Core prompts as UIKit alerts on top of whatever is showing, so they work from any sheet.
@MainActor
final class AlertPrompts: PromptPresenter {
    func present(_ request: PromptRequest, reply: @escaping @MainActor ([String]?) -> Void) {
        guard let top = Self.topViewController() else { return reply(nil) }
        let alert: UIAlertController
        switch request {
        case .confirm(let title, let message, let action):
            #if DEBUG
            if UserDefaults.standard.bool(forKey: "debugAutoConfirm") { return reply([]) }
            #endif
            alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in reply(nil) })
            alert.addAction(UIAlertAction(title: action, style: .default) { _ in reply([]) })
        case .form(let title, let message, let fields):
            alert = UIAlertController(title: title, message: message.isEmpty ? nil : message, preferredStyle: .alert)
            for field in fields {
                alert.addTextField { input in
                    input.placeholder = field.label.isEmpty ? (field.secure ? "Password" : nil) : field.label
                    input.isSecureTextEntry = field.secure
                    input.autocapitalizationType = .none
                    input.autocorrectionType = .no
                }
            }
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in reply(nil) })
            alert.addAction(UIAlertAction(title: "Continue", style: .default) { [weak alert] _ in
                reply(alert?.textFields?.map { $0.text ?? "" } ?? [])
            })
        }
        top.present(alert, animated: true)
    }

    /// Asks from app code (not the core); nil when cancelled.
    static func ask(_ request: PromptRequest) async -> [String]? {
        guard let presenter = Prompts.presenter else { return nil }
        return await withCheckedContinuation { continuation in
            presenter.present(request) { continuation.resume(returning: $0) }
        }
    }

    private static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
        var top = scene?.keyWindow?.rootViewController
        while let presented = top?.presentedViewController, !presented.isBeingDismissed {
            top = presented
        }
        return top
    }
}
