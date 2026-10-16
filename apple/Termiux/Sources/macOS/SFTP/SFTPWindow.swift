import AppKit
import SwiftUI
import TermiuxCore
import UniformTypeIdentifiers

/// Two-pane file transfer window: this Mac on the left, the server on the right.
struct SFTPWindow: View {
    @Environment(AppModel.self) private var app
    let target: SFTPTarget
    @State private var remote = RemotePaneModel()
    @State private var local = LocalPaneModel()
    @State private var transfers: [TransferItem] = []
    @State private var remoteSelection = Set<String>()
    @State private var localSelection = Set<String>()

    private var host: HostRecord? { app.hosts.first { $0.id == target.hostID } }

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                LocalPane(model: local, selection: $localSelection, upload: upload)
                    .frame(minWidth: 280)
                RemotePane(model: remote, selection: $remoteSelection, download: download, uploadURLs: uploadURLs)
                    .frame(minWidth: 280)
            }
            if !transfers.isEmpty {
                Divider()
                TransferList(transfers: $transfers)
            }
        }
        .frame(minWidth: 720, minHeight: 420)
        .navigationTitle(host.map { "Files – \($0.label.isEmpty ? $0.hostname : $0.label)" } ?? "Files")
        .task { await remote.connect(app: app, hostID: target.hostID) }
        .onDisappear {
            transfers.forEach { $0.cancel() }
            remote.close()
        }
    }

    private func upload(_ items: [FileItem]) {
        uploadURLs(items.map { URL(fileURLWithPath: $0.path) })
    }

    /// Uploads into the remote pane's current folder.
    private func uploadURLs(_ urls: [URL]) {
        guard let browser = remote.browser else { return }
        for url in urls {
            let item = TransferItem(name: url.lastPathComponent, direction: .upload)
            item.onSuccess = { Task { await remote.refresh() } }
            let destination = (remote.path as NSString).appendingPathComponent(url.lastPathComponent)
            item.transfer = browser.upload(localPath: url.path, remotePath: destination, listener: TransferItem.Listener(item))
            transfers.append(item)
        }
    }

    /// Downloads into the local pane's current folder, never overwriting silently.
    private func download(_ items: [FileItem]) {
        guard let browser = remote.browser else { return }
        for file in items {
            let destination = uniqueURL(local.url.appendingPathComponent(file.name))
            let item = TransferItem(name: file.name, direction: .download)
            item.onSuccess = { local.refresh() }
            item.transfer = browser.download(remotePath: file.path, localPath: destination.path, listener: TransferItem.Listener(item))
            transfers.append(item)
        }
    }

    private func uniqueURL(_ url: URL) -> URL {
        var candidate = url
        var n = 2
        let base = url.deletingPathExtension().lastPathComponent
        let ext = url.pathExtension
        while FileManager.default.fileExists(atPath: candidate.path) {
            let name = ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)"
            candidate = url.deletingLastPathComponent().appendingPathComponent(name)
            n += 1
        }
        return candidate
    }
}

// MARK: panes

private struct PaneHeader: View {
    let title: String
    let path: String
    let canGoUp: Bool
    let up: () -> Void
    let refresh: () -> Void
    var extra: AnyView? = nil

    var body: some View {
        HStack(spacing: 6) {
            Text(title).font(.headline)
            Button(action: up) { Image(systemName: "chevron.up") }.disabled(!canGoUp).help("Enclosing folder")
            Text(path).font(.callout.monospaced()).lineLimit(1).truncationMode(.head).foregroundStyle(.secondary)
            Spacer()
            if let extra { extra }
            Button(action: refresh) { Image(systemName: "arrow.clockwise") }.help("Refresh")
        }
        .buttonStyle(.borderless)
        .padding(8)
    }
}

private struct FileTable: View {
    let items: [FileItem]
    @Binding var selection: Set<String>
    let open: (FileItem) -> Void

    var body: some View {
        Table(items, selection: $selection) {
            TableColumn("Name") { item in
                Label {
                    Text(item.name)
                } icon: {
                    Image(systemName: item.isDirectory ? "folder.fill" : item.isSymlink ? "arrow.turn.up.right" : "doc")
                        .foregroundStyle(item.isDirectory ? Color.accentColor : .secondary)
                }
            }
            TableColumn("Size") { item in
                Text(item.isDirectory ? "–" : ByteCountFormatter.string(fromByteCount: Int64(item.size), countStyle: .file))
                    .foregroundStyle(.secondary).monospacedDigit()
            }
            .width(80)
            TableColumn("Modified") { item in
                Text(item.modified?.formatted(date: .abbreviated, time: .shortened) ?? "").foregroundStyle(.secondary)
            }
            .width(140)
        }
        .contextMenu(forSelectionType: String.self) { _ in
            EmptyView()
        } primaryAction: { ids in
            if let id = ids.first, let item = items.first(where: { $0.id == id }) { open(item) }
        }
    }
}

private struct LocalPane: View {
    let model: LocalPaneModel
    @Binding var selection: Set<String>
    let upload: ([FileItem]) -> Void

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(
                title: BuildFlavor.sandboxed ? "Downloads" : "This Mac", path: model.url.path, canGoUp: model.canGoUp,
                up: model.up, refresh: model.refresh,
                extra: AnyView(
                    Button("Upload") { upload(selected) }.disabled(selected.isEmpty).help("Upload selected to the server")))
            FileTable(items: model.items, selection: $selection) { item in
                if item.isDirectory { model.load(URL(fileURLWithPath: item.path)) }
            }
            if let error = model.error { ErrorBar(text: error) }
        }
    }

    private var selected: [FileItem] { model.items.filter { selection.contains($0.id) } }
}

private struct RemotePane: View {
    let model: RemotePaneModel
    @Binding var selection: Set<String>
    let download: ([FileItem]) -> Void
    let uploadURLs: ([URL]) -> Void

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(
                title: "Server", path: model.path, canGoUp: model.path != "/" && !model.path.isEmpty,
                up: { Task { await model.up() } }, refresh: { Task { await model.refresh() } },
                extra: AnyView(HStack {
                    Button("Download") { download(selected) }.disabled(selected.isEmpty)
                    Button { newFolder() } label: { Image(systemName: "folder.badge.plus") }.help("New folder")
                    Button { renameSelected() } label: { Image(systemName: "pencil") }.disabled(selected.count != 1).help("Rename")
                    Button { deleteSelected() } label: { Image(systemName: "trash") }.disabled(selected.isEmpty).help("Delete")
                }))
            ZStack {
                FileTable(items: model.items, selection: $selection) { item in
                    if item.isDirectory || item.isSymlink { Task { await model.load(item.path) } }
                }
                if model.loading { ProgressView() }
            }
            // Files from Finder or the local pane.
            .dropDestination(for: URL.self) { urls, _ in
                uploadURLs(urls.filter(\.isFileURL))
                return true
            }
            if let error = model.error { ErrorBar(text: error) }
        }
    }

    private var selected: [FileItem] { model.items.filter { selection.contains($0.id) } }

    private func newFolder() {
        guard let name = Prompts.form(title: "New Folder", message: "", fields: [("Name", false)])?.first, !name.isEmpty
        else { return }
        let path = (model.path as NSString).appendingPathComponent(name)
        Task { await model.run { try await $0.mkdir(path: path) } }
    }

    private func renameSelected() {
        guard let item = selected.first,
            let name = Prompts.form(title: "Rename “\(item.name)”", message: "", fields: [("New name", false)])?.first,
            !name.isEmpty, name != item.name
        else { return }
        let to = (model.path as NSString).appendingPathComponent(name)
        Task { await model.run { try await $0.rename(from: item.path, to: to) } }
    }

    private func deleteSelected() {
        let items = selected
        let alert = NSAlert()
        alert.messageText = items.count == 1 ? "Delete “\(items[0].name)”?" : "Delete \(items.count) items?"
        alert.informativeText = items.contains(where: \.isDirectory)
            ? "Folders are deleted with everything in them. This cannot be undone."
            : "This cannot be undone."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            await model.run { browser in
                for item in items { try await browser.remove(path: item.path) }
            }
            selection.removeAll()
        }
    }
}

private struct ErrorBar: View {
    let text: String
    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.caption).foregroundStyle(.red).padding(6).frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: transfers

private struct TransferList: View {
    @Binding var transfers: [TransferItem]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Transfers").font(.headline)
                Spacer()
                Button("Clear Finished") { transfers.removeAll { $0.state != .running } }
                    .buttonStyle(.borderless)
                    .disabled(!transfers.contains { $0.state != .running })
            }
            .padding(8)
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(transfers) { TransferRow(item: $0) }
                }
                .padding(.horizontal, 8)
                .padding(.bottom, 8)
            }
            .frame(maxHeight: 150)
        }
    }
}

private struct TransferRow: View {
    let item: TransferItem

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: item.direction == .upload ? "arrow.up.circle" : "arrow.down.circle")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).lineLimit(1)
                switch item.state {
                case .running:
                    ProgressView(value: item.fraction)
                    Text("\(bytes(item.done)) of \(bytes(item.total))").font(.caption).foregroundStyle(.secondary)
                case .finished:
                    Text("Done · \(bytes(item.total))").font(.caption).foregroundStyle(.green)
                case .cancelled:
                    Text("Cancelled").font(.caption).foregroundStyle(.secondary)
                case .failed(let message):
                    Text(message).font(.caption).foregroundStyle(.red).lineLimit(2)
                }
            }
            Spacer()
            if item.state == .running {
                Button { item.cancel() } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless).help("Cancel")
            }
        }
    }

    private func bytes(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }
}
