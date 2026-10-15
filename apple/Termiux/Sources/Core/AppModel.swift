import AppKit
import Observation
import TermiuxCore

enum BuildFlavor {
    #if SANDBOXED
    static let sandboxed = true
    #else
    static let sandboxed = false
    #endif
    static var hasLocalShell: Bool { !sandboxed }
}

/// App-wide state: the core, saved hosts and keys, and open terminal sessions.
@MainActor
@Observable
final class AppModel {
    let core: TermiuxCore?
    let startupError: String?
    private(set) var hosts: [HostRecord] = []
    private(set) var keys: [KeyRecord] = []
    var sessions: [TerminalSessionModel] = []
    var selectedSessionID: TerminalSessionModel.ID?
    /// Shown as an alert by the root view.
    var errorMessage: String?

    init() {
        do {
            let support = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            let dir = support.appendingPathComponent(Bundle.main.bundleIdentifier ?? "Termiux", isDirectory: true)
            core = try TermiuxCore.open(dataDir: dir.path, secrets: KeychainSecretStore())
            startupError = nil
        } catch {
            core = nil
            startupError = "Could not open the Termiux database: \(error.localizedDescription)"
        }
        reload()
    }

    func reload() {
        guard let core else { return }
        do {
            hosts = try core.hosts()
            keys = try core.keys()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @discardableResult
    func save(host: HostRecord, password: PasswordChange) -> HostRecord? {
        guard let core else { return nil }
        do {
            let saved = try core.saveHost(record: host, password: password)
            reload()
            return saved
        } catch {
            errorMessage = error.localizedDescription
            return nil
        }
    }

    func delete(host: HostRecord) {
        do {
            try core?.deleteHost(id: host.id)
            reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func importKey(label: String, contents: String, passphrase: String?) throws -> KeyRecord? {
        let key = try core?.importKey(label: label, contents: contents, passphrase: passphrase)
        reload()
        return key
    }

    func delete(key: KeyRecord) {
        do {
            try core?.deleteKey(id: key.id)
            reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    var selectedSession: TerminalSessionModel? {
        sessions.first { $0.id == selectedSessionID }
    }

    func connect(_ host: HostRecord) {
        guard let core else { return }
        let session = TerminalSessionModel(kind: .ssh(host), core: core)
        open(session)
    }

    func openLocalShell() {
        guard let core, BuildFlavor.hasLocalShell else { return }
        open(TerminalSessionModel(kind: .local, core: core))
    }

    private func open(_ session: TerminalSessionModel) {
        sessions.append(session)
        selectedSessionID = session.id
        session.start()
    }

    func close(_ session: TerminalSessionModel) {
        session.close()
        sessions.removeAll { $0.id == session.id }
        if selectedSessionID == session.id { selectedSessionID = sessions.last?.id }
    }

    func forgetHostKey(host: String, port: UInt16) {
        do {
            try core?.forgetHostKey(host: host, port: port)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
