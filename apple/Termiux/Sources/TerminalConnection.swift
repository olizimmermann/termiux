import AppKit
import TermiuxCore

/// Bridges a Rust `TerminalSession` to a terminal view. Output arrives on core threads
/// and is hopped to the main thread before touching the view.
final class TerminalConnection: TerminalListener, HostKeyPrompt, @unchecked Sendable {
    private(set) var session: TerminalSession?
    /// Set by the view; receives output bytes on the main thread.
    var outputSink: (([UInt8]) -> Void)?
    var exitSink: ((UInt32?) -> Void)?
    private var pending: [UInt8] = []

    func connect(_ params: ConnectParams) async throws {
        session = try await connectSsh(params: params, prompt: self, listener: self)
    }

    func onOutput(data: Data) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let sink = self.outputSink {
                sink([UInt8](data))
            } else {
                self.pending.append(contentsOf: data)
            }
        }
    }

    /// Hands over bytes that arrived before the view attached.
    func drainPending() -> [UInt8] {
        defer { pending.removeAll() }
        return pending
    }

    func onExit(exitStatus: UInt32?) {
        DispatchQueue.main.async { [weak self] in self?.exitSink?(exitStatus) }
    }

    func trust(host: String, port: UInt16, algorithm: String, sha256Fingerprint: String) -> Bool {
        // Called on a core thread; the main thread is free because connect() is async.
        DispatchQueue.main.sync {
            let alert = NSAlert()
            alert.messageText = "Trust host \(host):\(port)?"
            alert.informativeText = "\(algorithm)\n\(sha256Fingerprint)"
            alert.addButton(withTitle: "Trust")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        }
    }
}
