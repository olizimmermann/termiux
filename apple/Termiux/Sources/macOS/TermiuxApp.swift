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
        .commands {
            CommandGroup(after: .newItem) {
                Button("Quick Connect…") { app.showingQuickConnect = true }
                    .keyboardShortcut("k", modifiers: .command)
                if BuildFlavor.hasLocalShell {
                    Button("New Local Shell") { app.openLocalShell() }
                        .keyboardShortcut("t", modifiers: .command)
                }
                Divider()
                Button("Split Right") { app.splitFocused(.horizontal) }
                    .keyboardShortcut("d", modifiers: .command)
                    .disabled(app.focusedSession == nil)
                Button("Split Down") { app.splitFocused(.vertical) }
                    .keyboardShortcut("d", modifiers: [.command, .shift])
                    .disabled(app.focusedSession == nil)
                Divider()
                Button("Close Pane") { app.closeFocusedPane() }
                    .keyboardShortcut("w", modifiers: .command)
                    .disabled(app.focusedSession == nil)
                Button("Close Tab") { if let tab = app.selectedTab { app.close(tab) } }
                    .keyboardShortcut("w", modifiers: [.command, .shift])
                    .disabled(app.selectedTab == nil)
            }
            CommandMenu("Window Panes") {
                Button("Next Tab") { app.selectTab(offset: 1) }
                    .keyboardShortcut("]", modifiers: [.command, .shift])
                Button("Previous Tab") { app.selectTab(offset: -1) }
                    .keyboardShortcut("[", modifiers: [.command, .shift])
                Divider()
                Button("Focus Pane Left") { app.selectedTab?.moveFocus(.left) }
                    .keyboardShortcut(.leftArrow, modifiers: [.command, .option])
                Button("Focus Pane Right") { app.selectedTab?.moveFocus(.right) }
                    .keyboardShortcut(.rightArrow, modifiers: [.command, .option])
                Button("Focus Pane Above") { app.selectedTab?.moveFocus(.up) }
                    .keyboardShortcut(.upArrow, modifiers: [.command, .option])
                Button("Focus Pane Below") { app.selectedTab?.moveFocus(.down) }
                    .keyboardShortcut(.downArrow, modifiers: [.command, .option])
                Divider()
                ForEach(1..<10) { n in
                    Button(n == 9 ? "Last Tab" : "Tab \(n)") { app.selectTab(number: n) }
                        .keyboardShortcut(KeyEquivalent(Character(String(n))), modifiers: .command)
                }
            }
        }

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
