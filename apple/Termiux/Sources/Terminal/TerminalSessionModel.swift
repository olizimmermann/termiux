import AppKit
import Observation
import TermiuxCore

/// One terminal pane: owns the surface (emulator + view) and the core session behind it.
/// The surface exists from the start, so output can never arrive before it is attached.
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
    /// Title set by the remote program (OSC 0/2), if any.
    private(set) var terminalTitle: String?

    @ObservationIgnored let surface: TerminalSurface
    @ObservationIgnored private let core: TermiuxCore
    @ObservationIgnored private var session: TerminalSession?
    @ObservationIgnored private var listener: Listener?
    @ObservationIgnored var onFocus: (() -> Void)?

    init(kind: Kind, core: TermiuxCore, surface: TerminalSurface = SwiftTermSurface()) {
        self.kind = kind
        self.core = core
        self.surface = surface
        surface.onInput = { [weak self] data in self?.session?.write(data: data) }
        surface.onResize = { [weak self] cols, rows in
            self?.session?.resize(cols: UInt32(cols), rows: UInt32(rows))
        }
        surface.onTitle = { [weak self] title in self?.terminalTitle = title.isEmpty ? nil : title }
        surface.onFocus = { [weak self] in self?.onFocus?() }
    }

    var name: String {
        switch kind {
        case .ssh(let host): host.label.isEmpty ? host.hostname : host.label
        case .local: "Local Shell"
        }
    }

    var themeID: String? {
        if case .ssh(let host) = kind { return host.themeId }
        return nil
    }

    func start() {
        session = nil
        state = .connecting(status: nil)
        let listener = Listener(model: self)
        self.listener = listener
        let size = surface.dimensions
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
                    // The pane may have been closed while connecting.
                    guard self.listener === listener else {
                        await session.close()
                        return
                    }
                    self.session = session
                    self.state = .running
                    // Catch up with any resize that happened while connecting.
                    let size = self.surface.dimensions
                    session.resize(cols: UInt32(size.cols), rows: UInt32(size.rows))
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
        surface.feed(text: "\r\n")
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
        surface.feed(data)
    }

    fileprivate func ended(_ end: SessionEnd) {
        session = nil
        if end.reason != .userClosed {
            state = .ended(end)
        }
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
}
