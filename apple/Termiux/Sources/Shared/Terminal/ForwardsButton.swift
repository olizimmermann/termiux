import SwiftUI
import TermiuxCore

/// Small overlay button on SSH panes with forwards: shows status, starts and stops them.
struct ForwardsButton: View {
    let session: TerminalSessionModel
    @State private var showing = false

    var body: some View {
        if !session.forwards.isEmpty {
            Button {
                showing.toggle()
            } label: {
                Label("\(runningCount)/\(session.forwards.count)", systemImage: "arrow.left.arrow.right")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(.regularMaterial, in: Capsule())
                    .foregroundStyle(hasError ? .red : .primary)
            }
            .buttonStyle(.plain)
            .help("Port forwards")
            .popover(isPresented: $showing, arrowEdge: .bottom) {
                ForwardList(session: session)
                    .frame(width: 380)
                    #if os(iOS)
                    .presentationCompactAdaptation(.popover)
                    #endif
            }
            .padding(8)
            .task(id: showing) { await session.refreshForwards() }
        }
    }

    private var runningCount: Int { session.forwards.filter(\.running).count }
    private var hasError: Bool { session.forwards.contains { $0.error != nil } }
}

private struct ForwardList: View {
    let session: TerminalSessionModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Port Forwards").font(.headline)
            ForEach(session.forwards, id: \.forward.id) { status in
                HStack(alignment: .top) {
                    Circle().fill(status.running ? .green : status.error != nil ? .red : .secondary)
                        .frame(width: 8, height: 8).padding(.top, 5)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(status.forward.summary).font(.callout.monospaced())
                        if let host = status.boundHost, let port = status.boundPort, status.running {
                            Text("Listening on \(host):\(String(port))").font(.caption).foregroundStyle(.secondary)
                        }
                        if let error = status.error {
                            Text(error).font(.caption).foregroundStyle(.red)
                        }
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { status.running },
                        set: { on in Task { await session.setForward(status.forward.id, running: on) } }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                }
            }
        }
        .padding()
    }
}
