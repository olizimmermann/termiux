import AppKit
import Observation
import SwiftTerm
import TermiuxCore

/// One terminal tab: owns the terminal view and the core session behind it.
/// The view exists from the start, so output can never arrive before it is attached.
@MainActor
@Observable
final class TerminalSessionModel: Identifiable {
    enum Kind {
        case ssh(HostRecord)
        case local
    }

    enum State: Equatable {
        case connecting(status: String?)
        case running
        case ended(SessionEnd)
        case failed(message: String)
        case hostKeyChanged(host: String, port: UInt16, fingerprint: String, previous: String)
    }

    let id = UUID()
    let kind: Kind
    private(set) var state: State = .connecting(status: nil)
    var title: String

    @ObservationIgnored let terminalView: TerminalView
    @ObservationIgnored private let core: TermiuxCore
    @ObservationIgnored private var session: TerminalSession?
    @ObservationIgnored private var delegate: Delegate?
    @ObservationIgnored private var listener: Listener?

    init(kind: Kind, core: TermiuxCore) {
        self.kind = kind
        self.core = core
        switch kind {
        case .ssh(let host): title = host.label.isEmpty ? host.hostname : host.label
        case .local: title = "Local Shell"
        }
        terminalView = TerminalView(frame: NSRect(x: 0, y: 0, width: 800, height: 500))
        terminalView.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        let delegate = Delegate(model: self)
        self.delegate = delegate
        terminalView.terminalDelegate = delegate
    }

    var canReconnect: Bool {
        switch state {
        case .ended, .failed: true
        default: false
        }
    }

    func start() {
        session = nil
        state = .connecting(status: nil)
        let listener = Listener(model: self)
        self.listener = listener
        let size = terminalView.terminalDimensions
        let (cols, rows) = (UInt32(size.cols), UInt32(size.rows))

        switch kind {
        case .local:
            do {
                session = try core.openLocalShell(cols: cols, rows: rows, listener: listener)
                state = .running
            } catch {
                state = .failed(message: error.localizedDescription)
            }
        case .ssh(let host):
            let prompts = Prompts { [weak self] status in
                Task { @MainActor in
                    guard let self, case .connecting = self.state else { return }
                    self.state = .connecting(status: status)
                }
            }
            let core = core
            Task {
                do {
                    let session = try await core.connect(
                        hostId: host.id, cols: cols, rows: rows, ui: prompts, listener: listener)
                    // The tab may have been closed while connecting.
                    guard self.listener === listener else {
                        await session.close()
                        return
                    }
                    self.session = session
                    self.state = .running
                    // Catch up with any resize that happened while connecting.
                    let t = self.terminalView.terminalDimensions
                    session.resize(cols: UInt32(t.cols), rows: UInt32(t.rows))
                    self.terminalView.window?.makeFirstResponder(self.terminalView)
                } catch let CoreError.HostKeyChanged(host, port, fingerprint, previous) {
                    self.state = .hostKeyChanged(host: host, port: port, fingerprint: fingerprint, previous: previous)
                } catch CoreError.Cancelled {
                    self.state = .failed(message: "Cancelled")
                } catch {
                    self.state = .failed(message: error.localizedDescription)
                }
            }
        }
    }

    func reconnect() {
        terminalView.feed(text: "\r\n")
        start()
    }

    func close() {
        listener = nil
        if let session {
            Task { await session.close() }
        }
        session = nil
    }

    fileprivate func received(_ data: Data) {
        terminalView.feed(byteArray: [UInt8](data)[...])
    }

    fileprivate func ended(_ end: SessionEnd) {
        session = nil
        if end.reason != .userClosed {
            state = .ended(end)
        }
    }

    fileprivate func send(_ data: ArraySlice<UInt8>) {
        session?.write(data: Data(data))
    }

    fileprivate func resized(cols: Int, rows: Int) {
        session?.resize(cols: UInt32(cols), rows: UInt32(rows))
    }

    /// Receives core callbacks on core threads and forwards them to the main thread.
    private final class Listener: TerminalListener, @unchecked Sendable {
        weak var model: TerminalSessionModel?

        init(model: TerminalSessionModel) {
            self.model = model
        }

        func onOutput(data: Data) {
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    guard let model = self?.model, model.listener === self else { return }
                    model.received(data)
                }
            }
        }

        func onEnd(end: SessionEnd) {
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    guard let model = self?.model, model.listener === self else { return }
                    model.ended(end)
                }
            }
        }
    }

    private final class Delegate: NSObject, TerminalViewDelegate {
        weak var model: TerminalSessionModel?

        init(model: TerminalSessionModel) {
            self.model = model
        }

        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            MainActor.assumeIsolated { model?.send(data) }
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            MainActor.assumeIsolated { model?.resized(cols: newCols, rows: newRows) }
        }

        func setTerminalTitle(source: TerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func scrolled(source: TerminalView, position: Double) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
        func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
        func bell(source: TerminalView) { NSSound.beep() }

        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
            if let url = URL(string: link), ["http", "https"].contains(url.scheme) {
                NSWorkspace.shared.open(url)
            }
        }

        func clipboardCopy(source: TerminalView, content: Data) {
            guard let text = String(data: content, encoding: .utf8) else { return }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
    }
}
