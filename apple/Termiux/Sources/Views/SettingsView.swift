import AppKit
import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

struct SettingsView: View {
    var body: some View {
        TabView {
            AppearanceSettings().tabItem { Label("Appearance", systemImage: "textformat") }
            ThemeSettings().tabItem { Label("Themes", systemImage: "paintpalette") }
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

/// Small background/foreground chip.
struct Swatch: View {
    let theme: ThemeRecord

    var body: some View {
        RoundedRectangle(cornerRadius: 3)
            .fill(color(theme.background))
            .overlay(Text("A").font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(color(theme.foreground)))
            .frame(width: 18, height: 14)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(.separator))
    }

    private func color(_ hex: String) -> Color { Color(nsColor: NSColor(hex: hex) ?? .gray) }
}

/// A fake prompt and listing rendered in the theme's colours.
private struct ThemePreview: View {
    let theme: ThemeRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            line([("me@server", 2), (":", nil), ("~/src", 4), ("$ ", nil), ("ls -la", nil)])
            line([("drwxr-xr-x ", nil), ("build", 4)])
            line([("-rwxr-xr-x ", nil), ("deploy.sh", 2)])
            line([("error: ", 1), ("connection refused", nil)])
            line([("warning: ", 3), ("disk 91% full", nil)])
            HStack(spacing: 0) {
                ForEach(0..<16, id: \.self) { i in
                    Rectangle().fill(color(theme.palette[safe: i] ?? "")).frame(width: 18, height: 14)
                }
            }
            .padding(.top, 6)
        }
        .font(.system(size: 12, design: .monospaced))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color(theme.background), in: RoundedRectangle(cornerRadius: 8))
    }

    private func line(_ parts: [(String, Int?)]) -> some View {
        parts.reduce(Text("")) { text, part in
            text + Text(part.0).foregroundColor(color(part.1.map { theme.palette[safe: $0] ?? "" } ?? theme.foreground))
        }
    }

    private func color(_ hex: String) -> Color { Color(nsColor: NSColor(hex: hex) ?? .gray) }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}
