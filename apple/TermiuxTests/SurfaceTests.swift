import AppKit
import SwiftTerm
import TermiuxCore
import XCTest

@testable import Termiux

@MainActor
final class SurfaceTests: XCTestCase {
    private let theme = ThemeRecord(
        id: "t", name: "Test", foreground: "#d7dae0", background: "#15171c", cursor: "#6fa8ff", cursorText: nil,
        selectionBackground: "#2c3240", selectionForeground: nil,
        palette: Array(repeating: "#112233", count: 16), builtin: true)

    private func spin(_ seconds: TimeInterval = 0.3) {
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
    }

    func testThemeBackgroundSticks() throws {
        let surface = SwiftTermSurface()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300), styleMask: [.titled],
                              backing: .buffered, defer: false)
        window.contentView = surface.view
        surface.apply(theme: theme, appearance: Appearance.load())
        spin()
        surface.feed(text: "hello\r\n")
        spin()
        let view = try XCTUnwrap(surface.view as? TerminalView)
        let bg = view.nativeBackgroundColor.usingColorSpace(.sRGB)!
        XCTAssertEqual(bg.redComponent * 255, 0x15, accuracy: 1, "native bg is \(bg)")
        let layerBG = try XCTUnwrap(view.layer?.backgroundColor.flatMap { NSColor(cgColor: $0)?.usingColorSpace(.sRGB) })
        XCTAssertEqual(layerBG.blueComponent * 255, 0x1c, accuracy: 1, "layer bg is \(layerBG)")
    }

    /// Renders the view like the screen would and samples an empty area.
}
