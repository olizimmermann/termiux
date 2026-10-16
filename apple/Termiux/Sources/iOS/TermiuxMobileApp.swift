import SwiftUI
import UIKit

@main
struct TermiuxMobileApp: App {
    @State private var app = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    private let prompts = AlertPrompts()
    private let background = BackgroundKeeper()

    init() {
        Prompts.presenter = prompts
    }

    var body: some Scene {
        WindowGroup {
            MobileRootView()
                .environment(app)
                #if DEBUG
                .task { app.debugConnectIfRequested() }
                #endif
                .onChange(of: scenePhase) { _, phase in
                    switch phase {
                    case .background: background.begin()
                    case .active:
                        background.end()
                        app.resumeAfterBackground()
                    default: break
                    }
                }
        }
        .commands { TermiuxCommands(app: app) }
    }
}

/// iOS suspends apps shortly after they leave the screen, which silently kills SSH connections.
/// Asking for background time keeps sessions alive through a quick app switch (about 30 seconds).
@MainActor
final class BackgroundKeeper {
    private var task: UIBackgroundTaskIdentifier = .invalid

    func begin() {
        guard task == .invalid else { return }
        task = UIApplication.shared.beginBackgroundTask(withName: "Keep SSH sessions") { [weak self] in
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard task != .invalid else { return }
        UIApplication.shared.endBackgroundTask(task)
        task = .invalid
    }
}

extension AppModel {
    /// Back on screen: sessions that died while suspended reconnect by themselves.
    func resumeAfterBackground() {
        for session in tabs.flatMap(\.sessions) {
            if case .ended(let end) = session.state, end.reason == .connectionLost {
                session.reconnect()
            }
        }
    }
}

#if DEBUG
extension AppModel {
    /// Simulator smoke test: `simctl launch <device> com.ozimmermann.termiux -debugConnect user:password@host:port`
    /// saves that host (once) and connects. `-debugAutoConfirm YES` accepts confirmation prompts,
    /// `-debugSplit YES` splits the pane.
    func debugConnectIfRequested() {
        guard let spec = UserDefaults.standard.string(forKey: "debugConnect"),
            let at = spec.lastIndex(of: "@"), let colon = spec[..<at].firstIndex(of: ":"),
            let portColon = spec[at...].lastIndex(of: ":"), let port = UInt16(spec[spec.index(after: portColon)...])
        else { return }
        let user = String(spec[..<colon])
        let password = String(spec[spec.index(after: colon)..<at])
        let hostname = String(spec[spec.index(after: at)..<portColon])
        var host = hosts.first { $0.hostname == hostname && $0.port == port && $0.username == user } ?? .new
        if host.id.isEmpty {
            host.label = "Debug \(hostname)"
            host.hostname = hostname
            host.port = port
            host.username = user
            guard let saved = save(host: host, password: .set(password: password)) else { return }
            host = saved
        }
        connect(host)
        if UserDefaults.standard.bool(forKey: "debugSplit") { splitFocused(.horizontal) }
    }
}
#endif
