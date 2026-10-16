import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

struct MobileSettingsView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @AppStorage(Appearance.Key.fontName) private var fontName = ""
    @AppStorage(Appearance.Key.fontSize) private var fontSize = 13.0
    @AppStorage(Appearance.Key.cursorShape) private var cursorShape = Appearance.CursorShape.block.rawValue
    @AppStorage(Appearance.Key.cursorBlink) private var cursorBlink = true

    var body: some View {
        NavigationStack {
            Form {
                Section("Terminal") {
                    NavigationLink {
                        ThemeList()
                    } label: {
                        LabeledContent("Theme") {
                            HStack {
                                if let theme = app.defaultTheme { Swatch(theme: theme) }
                                Text(app.defaultTheme?.name ?? "")
                            }
                        }
                    }
                    Picker("Font", selection: $fontName) {
                        Text("SF Mono").tag("")
                        ForEach(Appearance.monospacedFamilies, id: \.self) { Text($0).tag($0) }
                    }
                    Stepper("Size \(Int(fontSize)) pt", value: $fontSize, in: 8...32)
                    Picker("Cursor", selection: $cursorShape) {
                        ForEach(Appearance.CursorShape.allCases) { Text($0.label).tag($0.rawValue) }
                    }
                    Toggle("Blinking cursor", isOn: $cursorBlink)
                }
                Section {
                    NavigationLink("Sync") { MobileSyncView() }
                } footer: {
                    Text(app.sync.isEnabled ? "On" : "Bring your hosts and keys over from your other devices.")
                }
                Section("About") {
                    LabeledContent("Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
                    LabeledContent("License", value: "GPL-3.0")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}

private struct ThemeList: View {
    @Environment(AppModel.self) private var app
    @AppStorage(Appearance.Key.defaultThemeID) private var defaultThemeID = ""
    @State private var importing = false
    @State private var importError: String?

    var body: some View {
        List {
            if let theme = app.defaultTheme {
                Section { ThemePreview(theme: theme).listRowInsets(EdgeInsets()) }
            }
            Section("Built-in") {
                ForEach(app.themes.filter(\.builtin), id: \.id) { row($0) }
            }
            let custom = app.themes.filter { !$0.builtin }
            if !custom.isEmpty {
                Section("Imported") {
                    ForEach(custom, id: \.id) { theme in
                        row(theme).swipeActions {
                            Button("Delete", role: .destructive) { app.delete(theme: theme) }
                        }
                    }
                }
            }
        }
        .navigationTitle("Theme")
        .toolbar {
            Button("Import", systemImage: "square.and.arrow.down") { importing = true }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            guard case .success(let urls) = result else { return }
            for url in urls {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                do {
                    try app.importTheme(name: url.deletingPathExtension().lastPathComponent, contents: Data(contentsOf: url))
                } catch {
                    importError = "\(url.lastPathComponent): \(error.localizedDescription)"
                }
            }
        }
        .alert("Import failed", isPresented: .constant(importError != nil)) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
        }
    }

    private func row(_ theme: ThemeRecord) -> some View {
        Button { defaultThemeID = theme.id } label: {
            HStack {
                Swatch(theme: theme)
                Text(theme.name)
                Spacer()
                if app.defaultTheme?.id == theme.id {
                    Image(systemName: "checkmark").foregroundStyle(.tint)
                }
            }
            .contentShape(Rectangle())
        }
        .tint(.primary)
    }
}
