import SwiftTerm
import SwiftUI

struct TerminalPane: NSViewRepresentable {
    let connection: TerminalConnection

    func makeCoordinator() -> Coordinator { Coordinator(connection: connection) }

    func makeNSView(context: Context) -> TerminalView {
        let view = TerminalView(frame: .zero)
        view.terminalDelegate = context.coordinator
        view.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        connection.outputSink = { [weak view] bytes in view?.feed(byteArray: bytes[...]) }
        connection.exitSink = { [weak view] status in
            view?.feed(text: "\r\n[session closed\(status.map { ", exit \($0)" } ?? "")]\r\n")
        }
        view.feed(byteArray: connection.drainPending()[...])
        DispatchQueue.main.async { view.window?.makeFirstResponder(view) }
        return view
    }

    func updateNSView(_ nsView: TerminalView, context: Context) {}

    final class Coordinator: NSObject, TerminalViewDelegate {
        let connection: TerminalConnection
        init(connection: TerminalConnection) { self.connection = connection }

        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            connection.session?.write(data: Data(data))
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            connection.session?.resize(cols: UInt32(newCols), rows: UInt32(newRows))
        }

        func setTerminalTitle(source: TerminalView, title: String) {
            source.window?.title = title
        }

        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func scrolled(source: TerminalView, position: Double) {}
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
            if let url = URL(string: link) { NSWorkspace.shared.open(url) }
        }
        func bell(source: TerminalView) { NSSound.beep() }
        func clipboardCopy(source: TerminalView, content: Data) {
            if let s = String(data: content, encoding: .utf8) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(s, forType: .string)
            }
        }
        func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    }
}
