import SwiftUI

@main
struct TermiuxApp: App {
    @State private var app = AppModel()
    private let prompts = ModalPrompts()

    init() {
        Prompts.presenter = prompts
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(app)
                .frame(minWidth: 760, minHeight: 440)
        }
        .commands { TermiuxCommands(app: app) }

        WindowGroup("Files", id: "sftp", for: SFTPTarget.self) { $target in
            if let target {
                SFTPWindow(target: target).environment(app)
            }
        }

        Settings {
            SettingsView().environment(app)
        }
    }
}
