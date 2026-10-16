import Foundation
import TermiuxCore

/// Something the core needs the user to answer while connecting.
enum PromptRequest {
    case confirm(title: String, message: String, action: String)
    case form(title: String, message: String, fields: [PromptField])
}

struct PromptField {
    let label: String
    /// Hides the input (passwords, PINs).
    let secure: Bool
}

/// Shows prompts on screen: modal alerts on macOS, sheets on iOS.
@MainActor
protocol PromptPresenter: AnyObject {
    /// `reply` receives the field values (empty for a confirmation), or nil when cancelled.
    func present(_ request: PromptRequest, reply: @escaping @MainActor ([String]?) -> Void)
}

/// The core's `Interaction` callbacks. The core calls these on its own (blocking) threads and
/// waits for the answer, so each one hands the prompt to the main thread and blocks until the
/// user replies. The main thread never waits on the core (connect is async), so this cannot
/// deadlock.
final class Prompts: Interaction, @unchecked Sendable {
    @MainActor static var presenter: PromptPresenter?

    /// Receives status lines such as "Touch your security key".
    let onStatus: @Sendable (String) -> Void

    init(onStatus: @escaping @Sendable (String) -> Void) {
        self.onStatus = onStatus
    }

    func confirmNewHost(info: HostKeyInfo) -> Bool {
        let message = """
            This is the first connection to \(info.host):\(info.port). Check that the fingerprint \
            matches the server before trusting it.

            \(info.algorithm)
            \(info.fingerprint)
            """
        return ask(.confirm(title: "Trust \(info.host)?", message: message, action: "Trust and Connect")) != nil
    }

    func keyboardInteractive(name: String, instructions: String, prompts: [InteractivePrompt]) -> [String]? {
        let title = name.isEmpty ? "Authentication" : name
        let fields = prompts.map { PromptField(label: $0.text, secure: !$0.echo) }
        return ask(.form(title: title, message: instructions, fields: fields))
    }

    func askSecret(title: String, message: String) -> String? {
        ask(.form(title: title, message: message, fields: [PromptField(label: "", secure: true)]))?.first
    }

    func status(message: String) {
        onStatus(message)
    }

    private func ask(_ request: PromptRequest) -> [String]? {
        // Blocking the main thread for its own reply would hang the app.
        guard !Thread.isMainThread else { return nil }
        let answer = Answer()
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                guard let presenter = Prompts.presenter else { return answer.set(nil) }
                presenter.present(request) { answer.set($0) }
            }
        }
        return answer.wait()
    }

    private final class Answer: @unchecked Sendable {
        private let done = DispatchSemaphore(value: 0)
        private var value: [String]?

        func set(_ value: [String]?) {
            self.value = value
            done.signal()
        }

        func wait() -> [String]? {
            done.wait()
            return value
        }
    }
}
