import SwiftUI

@main
struct TermiuxApp: App {
    @State private var app = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(app)
                .frame(minWidth: 760, minHeight: 440)
        }
        .commands {
            CommandGroup(after: .newItem) {
                if BuildFlavor.hasLocalShell {
                    Button("New Local Shell") { app.openLocalShell() }
                        .keyboardShortcut("t", modifiers: [.command])
                }
                Button("Close Session") {
                    if let session = app.selectedSession { app.close(session) }
                }
                .keyboardShortcut("w", modifiers: [.command, .shift])
                .disabled(app.selectedSession == nil)
            }
        }
    }
}
