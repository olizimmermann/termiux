import SwiftUI
import SwiftTerm

#if os(macOS)
import AppKit
typealias PlatformColor = NSColor
typealias PlatformFont = NSFont
typealias PlatformView = NSView
#else
import UIKit
typealias PlatformColor = UIColor
typealias PlatformFont = UIFont
typealias PlatformView = UIView
#endif

extension PlatformColor {
    /// `#rrggbb` in sRGB.
    convenience init?(hex: String) {
        let s = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(
            red: CGFloat((v >> 16) & 0xff) / 255, green: CGFloat((v >> 8) & 0xff) / 255,
            blue: CGFloat(v & 0xff) / 255, alpha: 1)
    }

    var swiftTermColor: SwiftTerm.Color {
        var (r, g, b, a): (CGFloat, CGFloat, CGFloat, CGFloat) = (0, 0, 0, 0)
        #if os(macOS)
        (usingColorSpace(.sRGB) ?? self).getRed(&r, green: &g, blue: &b, alpha: &a)
        #else
        getRed(&r, green: &g, blue: &b, alpha: &a)
        #endif
        func channel(_ v: CGFloat) -> UInt16 { UInt16((min(max(v, 0), 1) * 65535).rounded()) }
        return SwiftTerm.Color(red: channel(r), green: channel(g), blue: channel(b))
    }
}

extension SwiftUI.Color {
    /// A theme colour, or `fallback` when the hex string is invalid.
    init(hex: String, fallback: SwiftUI.Color = .gray) {
        if let color = PlatformColor(hex: hex) {
            #if os(macOS)
            self.init(nsColor: color)
            #else
            self.init(uiColor: color)
            #endif
        } else {
            self = fallback
        }
    }
}

enum Clipboard {
    @MainActor
    static func copy(_ text: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}

extension View {
    /// Text fields for hostnames, usernames, paths: no auto-capitalisation or autocorrect.
    func technicalInput() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        self
        #endif
    }

    /// Number pad on iOS.
    func numericInput() -> some View {
        #if os(iOS)
        self.keyboardType(.numberPad)
        #else
        self
        #endif
    }
}

/// Form sheet chrome: bottom button row with a fixed size on macOS, navigation bar buttons on iOS.
struct EditorSheet<Content: View>: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    let confirmTitle: String
    var cancelTitle = "Cancel"
    var canConfirm = true
    var width: CGFloat = 440
    var height: CGFloat = 400
    let onConfirm: () -> Void
    @ViewBuilder let content: Content

    var body: some View {
        #if os(macOS)
        VStack(spacing: 0) {
            content.formStyle(.grouped)
            HStack {
                Spacer()
                Button(cancelTitle) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(confirmTitle, action: onConfirm).keyboardShortcut(.defaultAction).disabled(!canConfirm)
            }
            .padding()
        }
        .frame(width: width, height: height)
        #else
        NavigationStack {
            content
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button(cancelTitle) { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button(confirmTitle, action: onConfirm).disabled(!canConfirm)
                    }
                }
        }
        #endif
    }
}

enum Device {
    /// "this Mac" / "this iPhone" in UI text.
    @MainActor static var thisDevice: String {
        #if os(macOS)
        "this Mac"
        #else
        UIDevice.current.userInterfaceIdiom == .pad ? "this iPad" : "this iPhone"
        #endif
    }
}
