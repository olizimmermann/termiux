import AppKit
import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

struct SettingsView: View {
    var body: some View {
        TabView {
            AppearanceSettings().tabItem { Label("Appearance", systemImage: "textformat") }
            ThemeSettings().tabItem { Label("Themes", systemImage: "paintpalette") }
            if BuildFlavor.hasAgent {
                SSHSettings().tabItem { Label("SSH", systemImage: "network") }
            }
            SyncSettingsView().tabItem { Label("Sync", systemImage: "arrow.triangle.2.circlepath") }
        }
        .frame(width: 560, height: 440)
    }
}

private struct AppearanceSettings: View {
    @AppStorage(Appearance.Key.fontName) private var fontName = ""
    @AppStorage(Appearance.Key.fontSize) private var fontSize = 13.0
    @AppStorage(Appearance.Key.cursorShape) private var cursorShape = Appearance.CursorShape.block.rawValue
    @AppStorage(Appearance.Key.cursorBlink) private var cursorBlink = true
    @AppStorage(Appearance.Key.optionAsMeta) private var optionAsMeta = true
    @State private var families: [String] = []

    var body: some View {
        Form {
            Picker("Font", selection: $fontName) {
                Text("SF Mono (System)").tag("")
                ForEach(families, id: \.self) { Text($0).tag($0) }
            }
            Stepper(value: $fontSize, in: 8...40, step: 1) {
                Text("Size: \(Int(fontSize)) pt")
            }
            Picker("Cursor", selection: $cursorShape) {
                ForEach(Appearance.CursorShape.allCases) { Text($0.label).tag($0.rawValue) }
            }
            .pickerStyle(.segmented)
            Toggle("Blinking cursor", isOn: $cursorBlink)
            Toggle("Use Option as Meta key", isOn: $optionAsMeta)
            Text("Font settings stay on this Mac; themes can sync with your other devices later.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .onAppear { families = Appearance.monospacedFamilies }
    }
}

private struct ThemeSettings: View {
    @Environment(AppModel.self) private var app
    @AppStorage(Appearance.Key.defaultThemeID) private var defaultThemeID = ""
    @State private var selection: String?
    @State private var importError: String?

    var body: some View {
        HStack(spacing: 0) {
            List(selection: $selection) {
                Section("Built-in") {
                    ForEach(app.themes.filter(\.builtin), id: \.id) { row($0) }
                }
                let custom = app.themes.filter { !$0.builtin }
                if !custom.isEmpty {
                    Section("Imported") {
                        ForEach(custom, id: \.id) { theme in
                            row(theme).contextMenu {
                                Button("Delete", role: .destructive) { app.delete(theme: theme) }
                            }
                        }
                    }
                }
            }
            .frame(width: 210)

            VStack(alignment: .leading, spacing: 12) {
                if let theme = selectedTheme {
                    ThemePreview(theme: theme)
                    HStack {
                        Button("Use as Default") { defaultThemeID = theme.id }
                            .disabled(isDefault(theme))
                        if !theme.builtin {
                            Button("Delete", role: .destructive) { app.delete(theme: theme) }
                        }
                    }
                }
                Spacer()
                Button("Import iTerm2 or Ghostty Theme…", action: importTheme)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { selection = selection ?? app.defaultTheme?.id }
        .alert("Import failed", isPresented: .constant(importError != nil)) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
        }
    }

    private var selectedTheme: ThemeRecord? { app.themes.first { $0.id == selection } }

    private func isDefault(_ theme: ThemeRecord) -> Bool { app.defaultTheme?.id == theme.id }

    private func row(_ theme: ThemeRecord) -> some View {
        HStack {
            Swatch(theme: theme)
            Text(theme.name)
            Spacer()
            if isDefault(theme) {
                Image(systemName: "checkmark").foregroundStyle(.secondary)
            }
        }
        .tag(theme.id)
    }

    private func importTheme() {
        let panel = NSOpenPanel()
        panel.message = "Choose an .itermcolors or Ghostty theme file"
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            do {
                let name = url.deletingPathExtension().lastPathComponent
                try app.importTheme(name: name, contents: Data(contentsOf: url))
            } catch {
                importError = "\(url.lastPathComponent): \(error.localizedDescription)"
            }
        }
    }
}

private struct SSHSettings: View {
    @AppStorage("agent.socket") private var agentSocket = ""

    var body: some View {
        Form {
            TextField("ssh-agent socket", text: $agentSocket, prompt: Text("Default ($SSH_AUTH_SOCK)"))
            Text("""
                Set this to use another agent, e.g. 1Password                 (~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock) or Secretive.                 Takes effect after restarting Termiux.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
    }
}
