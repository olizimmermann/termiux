import CoreImage.CIFilterBuiltins
#if os(macOS)
import AppKit
#else
import UIKit
#endif
import Observation
import TermiuxCore

/// Runs folder sync: on launch, periodically, when the app becomes active, and shortly
/// after local changes. The folder is remembered as a security-scoped bookmark so the
/// sandboxed build can keep using it.
@MainActor
@Observable
final class SyncController {
    private(set) var settings: SyncSettings?
    private(set) var folder: URL?
    private(set) var syncing = false
    private(set) var lastSync: Date?
    private(set) var lastReport: SyncReport?
    private(set) var lastError: String?

    @ObservationIgnored private weak var app: AppModel?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var pending: Task<Void, Never>?
    @ObservationIgnored private var activeObserver: NSObjectProtocol?

    private static let bookmarkKey = "sync.folderBookmark"
    private static let interval: TimeInterval = 120

    init(app: AppModel) {
        self.app = app
        folder = Self.resolveBookmark()
        refreshSettings()
        timer = Timer.scheduledTimer(withTimeInterval: Self.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncSoon(delay: 0) }
        }
        activeObserver = NotificationCenter.default.addObserver(
            forName: Self.didBecomeActive, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncSoon(delay: 0) }
        }
        syncSoon(delay: 1)
    }

    var isEnabled: Bool { settings?.enabled == true && folder != nil }

    func refreshSettings() {
        settings = try? app?.core?.syncSettings()
    }

    // MARK: setup

    func setFolder(_ url: URL) throws {
        // Folders picked on iOS are only reachable while their security scope is open.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let bookmark = try url.bookmarkData(options: Self.bookmarkCreation, includingResourceValuesForKeys: nil, relativeTo: nil)
        UserDefaults.standard.set(bookmark, forKey: Self.bookmarkKey)
        folder = url
    }

    /// Creates a vault and returns the sync code to show the user.
    func createVault(folder: URL) throws -> String {
        try setFolder(folder)
        let code = try app?.core?.createVault() ?? ""
        refreshSettings()
        syncSoon(delay: 0)
        return code
    }

    func joinVault(folder: URL, code: String) throws {
        try app?.core?.joinVault(code: code)
        try setFolder(folder)
        refreshSettings()
        syncSoon(delay: 0)
    }

    func setIncludeSecrets(_ include: Bool) {
        try? app?.core?.setSyncIncludeSecrets(include: include)
        refreshSettings()
        syncSoon(delay: 0)
    }

    func syncCode() -> String? { (try? app?.core?.vaultCode()) ?? nil }

    func leave() {
        try? app?.core?.leaveVault()
        UserDefaults.standard.removeObject(forKey: Self.bookmarkKey)
        folder = nil
        lastSync = nil
        lastReport = nil
        lastError = nil
        refreshSettings()
    }

    // MARK: running

    /// Debounced sync; local edits call this so bursts of changes sync once.
    func syncSoon(delay: TimeInterval = 3) {
        guard isEnabled else { return }
        pending?.cancel()
        pending = Task { [weak self] in
            if delay > 0 { try? await Task.sleep(for: .seconds(delay)) }
            guard !Task.isCancelled else { return }
            await self?.syncNow()
        }
    }

    func syncNow() async {
        guard isEnabled, !syncing, let core = app?.core, let folder else { return }
        syncing = true
        defer { syncing = false }
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        await Self.downloadPlaceholders(in: folder)
        do {
            let report = try await core.syncFolder(folder: folder.path)
            lastReport = report
            lastSync = Date()
            lastError = nil
            if report.received > 0 { app?.reload() }
        } catch {
            lastError = error.localizedDescription
        }
    }

    #if os(macOS)
    private static let didBecomeActive = NSApplication.didBecomeActiveNotification
    private static let bookmarkCreation: URL.BookmarkCreationOptions = .withSecurityScope
    private static let bookmarkResolution: URL.BookmarkResolutionOptions = .withSecurityScope
    #else
    private static let didBecomeActive = UIApplication.didBecomeActiveNotification
    // iOS bookmarks to picked folders are implicitly security-scoped.
    private static let bookmarkCreation: URL.BookmarkCreationOptions = []
    private static let bookmarkResolution: URL.BookmarkResolutionOptions = []
    #endif

    /// iCloud Drive can leave other devices' files in the cloud (as `.name.icloud` placeholders)
    /// until something asks for them; fetch those before syncing, waiting a few seconds at most.
    private static func downloadPlaceholders(in folder: URL) async {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: folder.path) else { return }
        var pending: [URL] = []
        for name in names where name.hasPrefix(".") && name.hasSuffix(".termiux-sync.icloud") {
            let real = folder.appendingPathComponent(String(name.dropFirst().dropLast(".icloud".count)))
            if (try? fm.startDownloadingUbiquitousItem(at: real)) != nil { pending.append(real) }
        }
        for _ in 0..<20 where pending.contains(where: { !fm.fileExists(atPath: $0.path) }) {
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    private static func resolveBookmark() -> URL? {
        guard let data = UserDefaults.standard.data(forKey: bookmarkKey) else { return nil }
        var stale = false
        return try? URL(resolvingBookmarkData: data, options: bookmarkResolution, relativeTo: nil, bookmarkDataIsStale: &stale)
    }

    /// QR code image of a sync code, for scanning on the phone.
    static func qrCode(for text: String, size: CGFloat = 180) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scale = size / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        return CIContext().createCGImage(scaled, from: scaled.extent)
    }
}
