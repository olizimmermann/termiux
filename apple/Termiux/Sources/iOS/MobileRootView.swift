import SwiftUI
import TermiuxCore

/// Host list and open sessions in the sidebar, the selected session's terminal as detail.
/// On iPhone this collapses into a navigation stack.
struct MobileRootView: View {
    @Environment(AppModel.self) private var app
    @State private var editing: HostRecord?
    @State private var screen: Screen?
    @State private var search = ""
    @State private var deleting: HostRecord?
    @State private var columns = NavigationSplitViewVisibility.automatic
    @Environment(\.horizontalSizeClass) private var sizeClass

    enum Screen: String, Identifiable {
        case keys, settings
        var id: String { rawValue }
    }

    var body: some View {
        @Bindable var app = app
        NavigationSplitView(columnVisibility: $columns) {
            List(selection: $app.selectedTabID) {
                if !app.tabs.isEmpty {
                    Section("Sessions") {
                        ForEach(app.tabs) { tab in
                            NavigationLink(value: tab.id) { SessionRow(tab: tab) }
                                .swipeActions {
                                    Button("Close", role: .destructive) { app.close(tab) }
                                }
                        }
                    }
                }
                Section("Hosts") {
                    ForEach(filteredHosts) { host in
                        Button { app.connect(host) } label: { HostRow(host: host) }
                            .tint(.primary)
                            .swipeActions {
                                Button("Delete", role: .destructive) { deleting = host }
                                Button("Edit") { editing = host }.tint(.orange)
                            }
                            .contextMenu {
                                Button("Connect", systemImage: "play") { app.connect(host) }
                                Button("Edit", systemImage: "pencil") { editing = host }
                                Button("Delete", systemImage: "trash", role: .destructive) { deleting = host }
                            }
                    }
                }
            }
            .overlay {
                if app.hosts.isEmpty && app.tabs.isEmpty {
                    ContentUnavailableView {
                        Label("No Hosts", systemImage: "server.rack")
                    } description: {
                        Text("Add a server, or turn on Sync in Settings to bring your hosts over from your Mac.")
                    } actions: {
                        Button("New Host") { editing = .new }.buttonStyle(.borderedProminent)
                    }
                }
            }
            .searchable(text: $search, prompt: "Search hosts")
            .navigationTitle("Termiux")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("New Host", systemImage: "plus") { editing = .new }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Quick Connect", systemImage: "bolt") { app.showingQuickConnect = true }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Menu("More", systemImage: "ellipsis.circle") {
                        Button("Keys", systemImage: "key") { screen = .keys }
                        Button("Settings", systemImage: "gear") { screen = .settings }
                    }
                }
            }
        } detail: {
            if let tab = app.selectedTab {
                TerminalScreen(tab: tab).id(tab.id)
            } else {
                ContentUnavailableView("No Session", systemImage: "terminal", description: Text("Tap a host to connect."))
            }
        }
        // On iPad, give a newly opened session the whole screen; the sidebar button brings the list back.
        .onChange(of: app.selectedTabID) { _, id in
            if id != nil && sizeClass == .regular { columns = .detailOnly }
        }
        .sheet(item: $editing) { host in HostEditor(host: host) }
        .sheet(isPresented: $app.showingQuickConnect) { QuickConnect().presentationDetents([.medium, .large]) }
        .sheet(item: $screen) { screen in
            switch screen {
            case .keys: MobileKeysView()
            case .settings: MobileSettingsView()
            }
        }
        .confirmationDialog(
            "Delete “\(deleting.map(displayName) ?? "")”?", isPresented: .constant(deleting != nil),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let host = deleting { app.delete(host: host) }
                deleting = nil
            }
            Button("Cancel", role: .cancel) { deleting = nil }
        }
        .alert("Error", isPresented: .constant(app.errorMessage != nil || app.startupError != nil)) {
            Button("OK") { app.errorMessage = nil }
        } message: {
            Text(app.startupError ?? app.errorMessage ?? "")
        }
    }

    private var filteredHosts: [HostRecord] {
        guard !search.isEmpty else { return app.hosts }
        return app.hosts.filter {
            $0.label.localizedCaseInsensitiveContains(search) || $0.hostname.localizedCaseInsensitiveContains(search)
                || $0.username.localizedCaseInsensitiveContains(search)
        }
    }

    private func displayName(_ host: HostRecord) -> String { host.label.isEmpty ? host.hostname : host.label }
}

private struct HostRow: View {
    let host: HostRecord

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "server.rack").foregroundStyle(.tint).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.label.isEmpty ? host.hostname : host.label)
                Text(verbatim: "\(host.username)@\(host.hostname)\(host.port == 22 ? "" : ":\(host.port)")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

private struct SessionRow: View {
    let tab: WorkspaceTab

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "terminal").foregroundStyle(color).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(tab.title)
                Text(status).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var status: String {
        switch tab.focused?.state {
        case .running: "Connected"
        case .connecting: "Connecting…"
        case .ended: "Disconnected"
        case .failed: "Failed"
        case .hostKeyChanged: "Host key changed"
        case nil: ""
        }
    }

    private var color: Color {
        switch tab.focused?.state {
        case .running: .green
        case .connecting: .orange
        default: .secondary
        }
    }
}
