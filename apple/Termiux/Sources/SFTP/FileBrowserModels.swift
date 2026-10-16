import AppKit
import Observation
import TermiuxCore

/// What the SFTP window was opened for.
struct SFTPTarget: Codable, Hashable {
    let hostID: String
}

/// One row in either pane.
struct FileItem: Identifiable, Hashable {
    let name: String
    let path: String
    let isDirectory: Bool
    let isSymlink: Bool
    let size: UInt64
    let modified: Date?
    var id: String { path }
}

@MainActor
@Observable
final class RemotePaneModel {
    private(set) var browser: FileBrowser?
    private(set) var path = ""
    private(set) var items: [FileItem] = []
    private(set) var loading = false
    var error: String?

    func connect(app: AppModel, hostID: String) async {
        loading = true
        defer { loading = false }
        do {
            // Reuse an open terminal's connection to the host when there is one: no second
            // login, no second security-key touch.
            let running = app.tabs.flatMap(\.sessions).first { session in
                if case .ssh(let host) = session.kind, host.id == hostID, session.state == .running { return true }
                return false
            }
            if let running, let browser = try? await running.openSftp() {
                self.browser = browser
            } else if let core = app.core {
                browser = try await core.openSftp(hostId: hostID, ui: Prompts { _ in })
            }
            if let browser { await load(try await browser.home()) }
        } catch {
            self.error = error.localizedDescription
        }
    }

    func load(_ path: String) async {
        guard let browser else { return }
        do {
            let entries = try await browser.list(path: path)
            self.path = path
            items = entries.map {
                FileItem(
                    name: $0.name, path: $0.path, isDirectory: $0.isDir, isSymlink: $0.isSymlink, size: $0.size,
                    modified: $0.modified.map { Date(timeIntervalSince1970: TimeInterval($0)) })
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func refresh() async { await load(path) }

    func up() async {
        guard path != "/" else { return }
        let parent = (path as NSString).deletingLastPathComponent
        await load(parent.isEmpty ? "/" : parent)
    }

    func run(_ action: (FileBrowser) async throws -> Void) async {
        guard let browser else { return }
        do {
            try await action(browser)
        } catch {
            self.error = error.localizedDescription
        }
        await refresh()
    }

    func close() {
        guard let browser else { return }
        self.browser = nil
        Task { await browser.close() }
    }
}

@MainActor
@Observable
final class LocalPaneModel {
    private(set) var url: URL
    private(set) var items: [FileItem] = []
    var error: String?
    /// Sandboxed builds may only browse below this folder.
    let root: URL?

    init() {
        let fm = FileManager.default
        if BuildFlavor.sandboxed {
            root = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first
            url = root ?? fm.homeDirectoryForCurrentUser
        } else {
            root = nil
            url = fm.homeDirectoryForCurrentUser
        }
        load(url)
    }

    func load(_ url: URL) {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey]
        do {
            let urls = try FileManager.default.contentsOfDirectory(
                at: url, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])
            items = urls.compactMap { u in
                let v = try? u.resourceValues(forKeys: Set(keys))
                return FileItem(
                    name: u.lastPathComponent, path: u.path, isDirectory: v?.isDirectory ?? false,
                    isSymlink: v?.isSymbolicLink ?? false, size: UInt64(v?.fileSize ?? 0),
                    modified: v?.contentModificationDate)
            }
            .sorted { ($0.isDirectory ? 0 : 1, $0.name.lowercased()) < ($1.isDirectory ? 0 : 1, $1.name.lowercased()) }
            self.url = url
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func refresh() { load(url) }

    var canGoUp: Bool {
        guard url.path != "/" else { return false }
        if let root { return url.standardizedFileURL.path != root.standardizedFileURL.path }
        return true
    }

    func up() {
        if canGoUp { load(url.deletingLastPathComponent()) }
    }
}

@MainActor
@Observable
final class TransferItem: Identifiable {
    enum Direction { case upload, download }
    enum State: Equatable {
        case running
        case finished
        case failed(String)
        case cancelled
    }

    let id = UUID()
    let name: String
    let direction: Direction
    var done: UInt64 = 0
    var total: UInt64 = 0
    var state: State = .running
    @ObservationIgnored var transfer: Transfer?
    /// Called once on success so the destination pane can refresh.
    @ObservationIgnored var onSuccess: (() -> Void)?

    init(name: String, direction: Direction) {
        self.name = name
        self.direction = direction
    }

    var fraction: Double { total == 0 ? 0 : Double(done) / Double(total) }

    func cancel() { transfer?.cancel() }

    /// Bridges core callbacks (core threads) to this item on the main thread.
    final class Listener: TransferListener, @unchecked Sendable {
        weak var item: TransferItem?

        init(_ item: TransferItem) { self.item = item }

        func onProgress(done: UInt64, total: UInt64) {
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    self?.item?.done = done
                    self?.item?.total = total
                }
            }
        }

        func onFinished(error: String?) {
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    guard let item = self?.item else { return }
                    switch error {
                    case nil:
                        item.state = .finished
                        item.onSuccess?()
                    case "cancelled": item.state = .cancelled
                    case let message?: item.state = .failed(message)
                    }
                }
            }
        }
    }
}
