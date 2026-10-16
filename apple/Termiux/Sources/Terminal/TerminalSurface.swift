import AppKit
import SwiftTerm
import TermiuxCore

/// The terminal emulator + renderer behind a pane. SwiftTerm today; libghostty is the
/// candidate replacement, so the rest of the app only talks to this protocol.
@MainActor
protocol TerminalSurface: AnyObject {
    var view: NSView { get }
    var dimensions: (cols: Int, rows: Int) { get }
    /// Keystrokes and pasted text to send to the session.
    var onInput: ((Data) -> Void)? { get set }
    var onResize: ((Int, Int) -> Void)? { get set }
    var onTitle: ((String) -> Void)? { get set }
    /// The user clicked into the surface.
    var onFocus: (() -> Void)? { get set }

    func feed(_ data: Data)
    func feed(text: String)
    func apply(theme: ThemeRecord, appearance: Appearance)
    func focus()
}

final class SwiftTermSurface: NSObject, TerminalSurface, TerminalViewDelegate {
    private let terminalView: FocusReportingTerminalView
    var onInput: ((Data) -> Void)?
    var onResize: ((Int, Int) -> Void)?
    var onTitle: ((String) -> Void)?
    var onFocus: (() -> Void)?

    override init() {
        terminalView = FocusReportingTerminalView(frame: NSRect(x: 0, y: 0, width: 800, height: 500))
        super.init()
        terminalView.terminalDelegate = self
        terminalView.onMouseDown = { [weak self] in self?.onFocus?() }
    }

    var view: NSView { terminalView }

    var dimensions: (cols: Int, rows: Int) {
        let d = terminalView.terminalDimensions
        return (d.cols, d.rows)
    }

    func feed(_ data: Data) {
        terminalView.feed(byteArray: [UInt8](data)[...])
    }

    func feed(text: String) {
        terminalView.feed(text: text)
    }

    func focus() {
        terminalView.window?.makeFirstResponder(terminalView)
    }

    func apply(theme: ThemeRecord, appearance: Appearance) {
        terminalView.font = appearance.font
        let palette = theme.palette.compactMap { NSColor(hex: $0) }
        if palette.count == 16 {
            terminalView.installColors(palette.map(\.swiftTermColor))
        }
        if let fg = NSColor(hex: theme.foreground) { terminalView.nativeForegroundColor = fg }
        if let bg = NSColor(hex: theme.background) {
            terminalView.nativeBackgroundColor = bg
            terminalView.layer?.backgroundColor = bg.cgColor
        }
        if let cursor = NSColor(hex: theme.cursor) { terminalView.caretColor = cursor }
        terminalView.caretTextColor = theme.cursorText.flatMap { NSColor(hex: $0) }
        if let selection = NSColor(hex: theme.selectionBackground) {
            terminalView.selectedTextBackgroundColor = selection
        }
        terminalView.setCursorStyle(appearance.cursorStyle)
        terminalView.optionAsMetaKey = appearance.optionAsMeta
    }

    // MARK: TerminalViewDelegate (SwiftTerm calls these on the main thread)

    nonisolated func send(source: TerminalView, data: ArraySlice<UInt8>) {
        MainActor.assumeIsolated { onInput?(Data(data)) }
    }

    nonisolated func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        MainActor.assumeIsolated { onResize?(newCols, newRows) }
    }

    nonisolated func setTerminalTitle(source: TerminalView, title: String) {
        MainActor.assumeIsolated { onTitle?(title) }
    }

    nonisolated func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    nonisolated func scrolled(source: TerminalView, position: Double) {}
    nonisolated func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    nonisolated func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
    nonisolated func bell(source: TerminalView) {
        MainActor.assumeIsolated { NSSound.beep() }
    }

    nonisolated func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        guard let url = URL(string: link), ["http", "https"].contains(url.scheme) else { return }
        MainActor.assumeIsolated { _ = NSWorkspace.shared.open(url) }
    }

    nonisolated func clipboardCopy(source: TerminalView, content: Data) {
        guard let text = String(data: content, encoding: .utf8) else { return }
        MainActor.assumeIsolated {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
    }
}

/// Reports clicks so the pane under the mouse becomes the focused pane.
private final class FocusReportingTerminalView: TerminalView {
    var onMouseDown: (() -> Void)?

    override func mouseDown(with event: NSEvent) {
        onMouseDown?()
        super.mouseDown(with: event)
    }
}

extension NSColor {
    /// `#rrggbb` in sRGB.
    convenience init?(hex: String) {
        let s = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(
            srgbRed: CGFloat((v >> 16) & 0xff) / 255, green: CGFloat((v >> 8) & 0xff) / 255,
            blue: CGFloat(v & 0xff) / 255, alpha: 1)
    }

    var swiftTermColor: SwiftTerm.Color {
        let c = usingColorSpace(.sRGB) ?? self
        func channel(_ v: CGFloat) -> UInt16 { UInt16((v * 65535).rounded()) }
        return SwiftTerm.Color(red: channel(c.redComponent), green: channel(c.greenComponent), blue: channel(c.blueComponent))
    }
}
