import SwiftTerm
#if os(macOS)
import AppKit
#else
import UIKit
#endif
import TermiuxCore

/// The terminal emulator + renderer behind a pane. SwiftTerm today; libghostty is the
/// candidate replacement, so the rest of the app only talks to this protocol.
@MainActor
protocol TerminalSurface: AnyObject {
    var view: PlatformView { get }
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
        terminalView = FocusReportingTerminalView(frame: CGRect(x: 0, y: 0, width: 800, height: 500))
        super.init()
        terminalView.terminalDelegate = self
        terminalView.onMouseDown = { [weak self] in self?.onFocus?() }
    }

    var view: PlatformView { terminalView }

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
        #if os(macOS)
        terminalView.window?.makeFirstResponder(terminalView)
        #else
        _ = terminalView.becomeFirstResponder()
        #endif
    }

    func apply(theme: ThemeRecord, appearance: Appearance) {
        terminalView.font = appearance.font
        let palette = theme.palette.compactMap { PlatformColor(hex: $0) }
        if palette.count == 16 {
            terminalView.installColors(palette.map(\.swiftTermColor))
        }
        if let fg = PlatformColor(hex: theme.foreground) { terminalView.nativeForegroundColor = fg }
        if let bg = PlatformColor(hex: theme.background) {
            terminalView.nativeBackgroundColor = bg
            #if os(macOS)
            terminalView.layer?.backgroundColor = bg.cgColor
            #else
            terminalView.backgroundColor = bg
            #endif
        }
        if let cursor = PlatformColor(hex: theme.cursor) { terminalView.caretColor = cursor }
        terminalView.caretTextColor = theme.cursorText.flatMap { PlatformColor(hex: $0) }
        if let selection = PlatformColor(hex: theme.selectionBackground) {
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
        #if os(macOS)
        MainActor.assumeIsolated { NSSound.beep() }
        #else
        MainActor.assumeIsolated { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
        #endif
    }

    nonisolated func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        guard let url = URL(string: link), ["http", "https"].contains(url.scheme) else { return }
        #if os(macOS)
        MainActor.assumeIsolated { _ = NSWorkspace.shared.open(url) }
        #else
        MainActor.assumeIsolated { UIApplication.shared.open(url) }
        #endif
    }

    nonisolated func clipboardCopy(source: TerminalView, content: Data) {
        guard let text = String(data: content, encoding: .utf8) else { return }
        MainActor.assumeIsolated { Clipboard.copy(text) }
    }
}

/// Reports clicks so the pane under the mouse becomes the focused pane.
private final class FocusReportingTerminalView: TerminalView {
    var onMouseDown: (() -> Void)?

    #if os(macOS)
    override func mouseDown(with event: NSEvent) {
        onMouseDown?()
        super.mouseDown(with: event)
    }
    #else
    override func becomeFirstResponder() -> Bool {
        onMouseDown?()
        return super.becomeFirstResponder()
    }
    #endif
}
