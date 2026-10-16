import SwiftUI

struct TabBar: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                ForEach(app.tabs) { tab in
                    TabButton(tab: tab, selected: tab.id == app.selectedTabID)
                }
            }
            .padding(.horizontal, 6)
        }
        .frame(height: 30)
        .background(.bar)
    }
}

private struct TabButton: View {
    @Environment(AppModel.self) private var app
    let tab: WorkspaceTab
    let selected: Bool
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(statusColor).frame(width: 7, height: 7)
            Text(tab.title).lineLimit(1).font(.callout)
            Button {
                app.close(tab)
            } label: {
                Image(systemName: "xmark").font(.caption2.bold())
            }
            .buttonStyle(.plain)
            .opacity(hovering || selected ? 1 : 0)
            .help("Close Tab")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .frame(minWidth: 110, maxWidth: 220)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(selected ? Color.accentColor.opacity(0.22) : hovering ? Color.primary.opacity(0.06) : .clear)
        )
        .contentShape(Rectangle())
        .onTapGesture { app.selectedTabID = tab.id }
        .onHover { hovering = $0 }
    }

    private var statusColor: Color {
        switch tab.focused?.state {
        case .running: .green
        case .connecting: .yellow
        default: .red
        }
    }
}
