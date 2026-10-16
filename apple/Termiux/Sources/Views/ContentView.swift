import SwiftUI
import TermiuxCore

struct ContentView: View {
    @Environment(AppModel.self) private var app
    @State private var editing: HostRecord?
    @State private var showingKeys = false
    @State private var search = ""

    var body: some View {
        @Bindable var app = app
        NavigationSplitView {
            List(selection: $app.selectedTabID) {
                if !app.tabs.isEmpty {
                    Section("Open") {
                        ForEach(app.tabs) { tab in
                            SessionRow(tab: tab).tag(tab.id)
                        }
                    }
                }
                Section("Hosts") {
                    ForEach(filteredHosts, id: \.id) { host in
                        HostRow(host: host)
                            .contentShape(Rectangle())
                            .onTapGesture(count: 2) { app.connect(host) }
                            .contextMenu {
                                Button("Connect") { app.connect(host) }
                                Button("Edit…") { editing = host }
                                Divider()
                                Button("Delete", role: .destructive) { app.delete(host: host) }
                            }
                    }
                    if app.hosts.isEmpty {
                        Text("No hosts yet").foregroundStyle(.secondary)
                    }
                }
            }
            .searchable(text: $search, placement: .sidebar, prompt: "Search hosts")
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
            .toolbar {
                ToolbarItemGroup {
                    Button { app.showingQuickConnect = true } label: {
                        Label("Quick Connect", systemImage: "magnifyingglass")
                    }
                    .help("Quick Connect (⌘K)")
                    Button { editing = .new } label: { Label("New Host", systemImage: "plus") }
                    Button { showingKeys = true } label: { Label("Keys", systemImage: "key") }
                    if BuildFlavor.hasLocalShell {
                        Button { app.openLocalShell() } label: { Label("Local Shell", systemImage: "terminal") }
                    }
                }
            }
        } detail: {
            VStack(spacing: 0) {
                if app.tabs.count > 1 {
                    TabBar()
                }
                if let tab = app.selectedTab {
                    PaneTreeView(node: tab.root, tab: tab)
                        .id(tab.id)
                        .navigationTitle(tab.focused?.terminalTitle ?? tab.title)
                } else {
                    EmptyState(onNewHost: { editing = .new })
                }
            }
        }
        .sheet(isPresented: $app.showingQuickConnect) {
            QuickConnect()
        }
        .sheet(item: $editing) { host in
            HostEditor(host: host)
        }
        .sheet(isPresented: $showingKeys) {
            KeysView()
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
}

extension HostRecord: @retroactive Identifiable {
    /// A blank record for the "new host" sheet; each call is a distinct sheet item.
    static var new: HostRecord {
        HostRecord(
            id: "", label: "", groupId: nil, hostname: "", port: 22, username: NSUserName(),
            auth: .password(saved: false), keepaliveSecs: 30, term: "xterm-256color", startupCommand: nil,
            themeId: nil)
    }
}

private struct HostRow: View {
    let host: HostRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(host.label.isEmpty ? host.hostname : host.label)
            Text(verbatim: "\(host.username)@\(host.hostname)\(host.port == 22 ? "" : ":\(host.port)")")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

private struct SessionRow: View {
    let tab: WorkspaceTab

    var body: some View {
        Label {
            Text(tab.title)
        } icon: {
            Circle().fill(color).frame(width: 8, height: 8)
        }
    }

    private var color: Color {
        switch tab.focused?.state {
        case .running: .green
        case .connecting: .yellow
        default: .red
        }
    }
}

private struct EmptyState: View {
    @Environment(AppModel.self) private var app
    let onNewHost: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "terminal").font(.system(size: 44)).foregroundStyle(.secondary)
            Text("Double-click a host to connect").font(.title3)
            Text("⌘K Quick Connect · ⌘D split · ⌘T local shell").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("New Host…", action: onNewHost)
                if BuildFlavor.hasLocalShell {
                    Button("Local Shell") { app.openLocalShell() }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
