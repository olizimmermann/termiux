import SwiftUI
import TermiuxCore

/// ⌘K palette: type to filter hosts, Enter to connect.
struct QuickConnect: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var selection = 0
    @FocusState private var fieldFocused: Bool

    private enum Item: Identifiable {
        case host(HostRecord)
        case local
        var id: String {
            switch self {
            case .host(let h): h.id
            case .local: "local"
            }
        }
    }

    private var items: [Item] {
        let hosts = app.hosts.filter { host in
            query.isEmpty
                || [host.label, host.hostname, host.username].contains { $0.localizedCaseInsensitiveContains(query) }
        }
        var items = hosts.map(Item.host)
        if BuildFlavor.hasLocalShell && (query.isEmpty || "local shell".localizedCaseInsensitiveContains(query)) {
            items.append(.local)
        }
        return items
    }

    var body: some View {
        VStack(spacing: 0) {
            TextField("Connect to…", text: $query)
                .textFieldStyle(.plain)
                .font(.title3)
                .padding(14)
                .focused($fieldFocused)
                .technicalInput()
                .onSubmit(open)
                .onChange(of: query) { selection = 0 }
            Divider()
            ScrollViewReader { proxy in
                List {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        row(item)
                            .padding(.vertical, 3)
                            .listRowBackground(index == selection ? Color.accentColor.opacity(0.25) : .clear)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                selection = index
                                open()
                            }
                            .id(index)
                    }
                }
                .listStyle(.plain)
                .onChange(of: selection) { proxy.scrollTo(selection) }
            }
        }
        #if os(macOS)
        .frame(width: 480, height: 340)
        .onExitCommand { dismiss() }
        #endif
        .onAppear { fieldFocused = true }
        .onKeyPress(.downArrow) {
            selection = min(selection + 1, max(items.count - 1, 0))
            return .handled
        }
        .onKeyPress(.upArrow) {
            selection = max(selection - 1, 0)
            return .handled
        }
    }

    @ViewBuilder private func row(_ item: Item) -> some View {
        switch item {
        case .host(let host):
            HStack {
                Image(systemName: "server.rack").foregroundStyle(.secondary)
                Text(host.label.isEmpty ? host.hostname : host.label)
                Spacer()
                Text(verbatim: "\(host.username)@\(host.hostname)").foregroundStyle(.secondary).font(.caption)
            }
        case .local:
            Label("Local Shell", systemImage: "terminal")
        }
    }

    private func open() {
        let items = items
        guard items.indices.contains(selection) else { return }
        switch items[selection] {
        case .host(let host): app.connect(host)
        case .local: app.openLocalShell()
        }
        dismiss()
    }
}
