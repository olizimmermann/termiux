import Foundation
import Observation
import TermiuxCore

enum BuildFlavor {
    #if SANDBOXED
    static let sandboxed = true
    #else
    static let sandboxed = false
    #endif
    static var hasLocalShell: Bool { !sandboxed }
    /// Sandboxed apps cannot reach the ssh-agent socket.
    static var hasAgent: Bool { !sandboxed }
}

/// App-wide state: the core, saved hosts, keys and themes, and open tabs.
@MainActor
@Observable
final class AppModel {
    let core: TermiuxCore?
    let hardwareKeys: HardwareKeys
    let startupError: String?
    private(set) var hosts: [HostRecord] = []
    private(set) var keys: [KeyRecord] = []
    private(set) var themes: [ThemeRecord] = []
    private(set) var appearance = Appearance.load()
    var tabs: [WorkspaceTab] = []
    var selectedTabID: WorkspaceTab.ID?
    var showingQuickConnect = false
    /// Shown as an alert by the root view.
    var errorMessage: String?

    @ObservationIgnored private var defaultsObserver: NSObjectProtocol?
    /// Set once after init (it needs a reference back to the model).
    @ObservationIgnored private(set) var sync: SyncController!

    init() {
        let secrets = KeychainSecretStore()
        hardwareKeys = HardwareKeys(secrets: secrets)
        do {
            let support = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            let dir = support.appendingPathComponent(Bundle.main.bundleIdentifier ?? "Termiux", isDirectory: true)
            let agentSocket = BuildFlavor.sandboxed ? nil : UserDefaults.standard.string(forKey: "agent.socket")
            core = try TermiuxCore.open(
                dataDir: dir.path, secrets: secrets, platform: hardwareKeys,
                agentSocket: agentSocket.map { NSString(string: $0).expandingTildeInPath })
            startupError = nil
        } catch {
            core = nil
            startupError = "Could not open the Termiux database: \(error.localizedDescription)"
        }
        reload()
        sync = SyncController(app: self)
        // Settings window edits UserDefaults; restyle open terminals when they change.
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.appearanceChanged() }
        }
        #if DEBUG
        // Visual smoke test: `open Termiux.app --args -debugSplitDemo YES`
        if UserDefaults.standard.bool(forKey: "debugSplitDemo") {
            openLocalShell()
            splitFocused(.horizontal)
        }
        #endif
    }

    func reload() {
        guard let core else { return }
        do {
            hosts = try core.hosts()
            keys = try core.keys()
            themes = try core.themes()
        } catch {
            errorMessage = error.localizedDescription
        }
        restyleAll()
    }

    // MARK: hosts and keys

    @discardableResult
    func save(host: HostRecord, password: PasswordChange) -> HostRecord? {
        guard let core else { return nil }
        do {
            let saved = try core.saveHost(record: host, password: password)
            reload()
            sync?.syncSoon()
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
            sync?.syncSoon()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func importKey(label: String, contents: String, passphrase: String?) throws -> KeyRecord? {
        let key = try core?.importKey(label: label, contents: contents, passphrase: passphrase)
        reload()
        sync?.syncSoon()
        return key
    }

    func delete(key: KeyRecord) {
        do {
            try core?.deleteKey(id: key.id)
            sync?.syncSoon()
            if case .secureEnclave(let tag) = key.platform {
                hardwareKeys.deleteSecureEnclaveKey(tag: tag)
            }
            reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func forgetHostKey(host: String, port: UInt16) {
        do {
            try core?.forgetHostKey(host: host, port: port)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: themes and appearance

    func importTheme(name: String, contents: Data) throws {
        _ = try core?.importTheme(name: name, contents: contents)
        reload()
        sync?.syncSoon()
    }

    func delete(theme: ThemeRecord) {
        do {
            try core?.deleteTheme(id: theme.id)
            sync?.syncSoon()
            if appearance.defaultThemeID == theme.id {
                UserDefaults.standard.removeObject(forKey: Appearance.Key.defaultThemeID)
            }
            reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    var defaultTheme: ThemeRecord? {
        themes.first { $0.id == appearance.defaultThemeID } ?? themes.first { $0.id == defaultThemeId() }
            ?? themes.first
    }

    func theme(for session: TerminalSessionModel) -> ThemeRecord? {
        session.themeID.flatMap { id in themes.first { $0.id == id } } ?? defaultTheme
    }

    private func appearanceChanged() {
        let new = Appearance.load()
        guard new != appearance else { return }
        appearance = new
        restyleAll()
    }

    private func restyleAll() {
        for session in tabs.flatMap(\.sessions) { style(session) }
    }

    private func style(_ session: TerminalSessionModel) {
        if let theme = theme(for: session) {
            session.surface.apply(theme: theme, appearance: appearance)
        }
    }

    // MARK: tabs and panes

    var selectedTab: WorkspaceTab? { tabs.first { $0.id == selectedTabID } }
    var focusedSession: TerminalSessionModel? { selectedTab?.focused }

    /// The saved host behind the focused pane, if it is an SSH session.
    var focusedHost: HostRecord? {
        guard case .ssh(let host)? = focusedSession?.kind else { return nil }
        return host
    }

    private func makeSession(_ kind: TerminalSessionModel.Kind) -> TerminalSessionModel? {
        guard let core else { return nil }
        if case .local = kind, !BuildFlavor.hasLocalShell { return nil }
        let session = TerminalSessionModel(kind: kind, core: core)
        style(session)
        return session
    }

    func connect(_ host: HostRecord) {
        openTab(.ssh(host))
    }

    func openLocalShell() {
        openTab(.local)
    }

    private func openTab(_ kind: TerminalSessionModel.Kind) {
        guard let session = makeSession(kind) else { return }
        let tab = WorkspaceTab(session: session)
        wire(session, in: tab)
        tabs.append(tab)
        selectedTabID = tab.id
        session.start()
    }

    private func wire(_ session: TerminalSessionModel, in tab: WorkspaceTab) {
        session.onFocus = { [weak tab, weak session] in
            if let tab, let session { tab.focusedID = session.id }
        }
    }

    /// Splits the focused pane, opening the same kind of session (same host or local shell).
    func splitFocused(_ axis: SplitNode.Axis) {
        guard let tab = selectedTab, let focused = tab.focused, let session = makeSession(focused.kind) else { return }
        wire(session, in: tab)
        tab.split(focused.id, axis: axis, with: session)
        session.start()
    }

    func closeFocusedPane() {
        guard let tab = selectedTab, let focused = tab.focused else { return }
        close(focused, in: tab)
    }

    func close(_ session: TerminalSessionModel, in tab: WorkspaceTab) {
        session.close()
        if !tab.remove(session.id) { remove(tab) }
    }

    func close(_ tab: WorkspaceTab) {
        tab.sessions.forEach { $0.close() }
        remove(tab)
    }

    private func remove(_ tab: WorkspaceTab) {
        guard let index = tabs.firstIndex(where: { $0.id == tab.id }) else { return }
        tabs.remove(at: index)
        if selectedTabID == tab.id {
            selectedTabID = tabs.isEmpty ? nil : tabs[min(index, tabs.count - 1)].id
        }
    }

    func selectTab(offset: Int) {
        guard !tabs.isEmpty else { return }
        let current = tabs.firstIndex { $0.id == selectedTabID } ?? 0
        selectedTabID = tabs[(current + offset + tabs.count) % tabs.count].id
    }

    func selectTab(number: Int) {
        guard number >= 1 else { return }
        // ⌘9 always means the last tab, as in browsers.
        let index = number == 9 ? tabs.count - 1 : number - 1
        if tabs.indices.contains(index) { selectedTabID = tabs[index].id }
    }
}
