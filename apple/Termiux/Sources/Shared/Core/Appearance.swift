import SwiftTerm
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Per-device appearance (fonts differ between machines, so these do not sync).
struct Appearance: Equatable {
    var fontName: String
    var fontSize: Double
    var cursorShape: CursorShape
    var cursorBlink: Bool
    var optionAsMeta: Bool
    var defaultThemeID: String

    enum CursorShape: String, CaseIterable, Identifiable {
        case block, bar, underline
        var id: String { rawValue }
        var label: String { rawValue.capitalized }
    }

    enum Key {
        static let fontName = "appearance.fontName"
        static let fontSize = "appearance.fontSize"
        static let cursorShape = "appearance.cursorShape"
        static let cursorBlink = "appearance.cursorBlink"
        static let optionAsMeta = "appearance.optionAsMeta"
        static let defaultThemeID = "appearance.defaultThemeID"
    }

    static func load(_ defaults: UserDefaults = .standard) -> Appearance {
        Appearance(
            fontName: defaults.string(forKey: Key.fontName) ?? "",
            fontSize: defaults.object(forKey: Key.fontSize) as? Double ?? 13,
            cursorShape: CursorShape(rawValue: defaults.string(forKey: Key.cursorShape) ?? "") ?? .block,
            cursorBlink: defaults.object(forKey: Key.cursorBlink) as? Bool ?? true,
            optionAsMeta: defaults.object(forKey: Key.optionAsMeta) as? Bool ?? true,
            defaultThemeID: defaults.string(forKey: Key.defaultThemeID) ?? "")
    }

    /// Empty name means the system monospaced font (SF Mono).
    var font: PlatformFont {
        let size = CGFloat(min(max(fontSize, 8), 40))
        #if os(macOS)
        if !fontName.isEmpty, let font = NSFont(name: fontName, size: size) { return font }
        #else
        if !fontName.isEmpty, UIFont.familyNames.contains(fontName) {
            return UIFont(descriptor: UIFontDescriptor(fontAttributes: [.family: fontName]), size: size)
        }
        #endif
        return PlatformFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }

    var cursorStyle: CursorStyle {
        switch (cursorShape, cursorBlink) {
        case (.block, true): .blinkBlock
        case (.block, false): .steadyBlock
        case (.bar, true): .blinkBar
        case (.bar, false): .steadyBar
        case (.underline, true): .blinkUnderline
        case (.underline, false): .steadyUnderline
        }
    }

    /// Installed fixed-pitch font families, for the font picker.
    static var monospacedFamilies: [String] {
        #if os(macOS)
        NSFontManager.shared.availableFontFamilies.filter { family in
            guard let font = NSFont(name: family, size: 12) else { return false }
            return font.isFixedPitch || family.localizedCaseInsensitiveContains("mono")
        }
        #else
        UIFont.familyNames.sorted().filter { family in
            guard let name = UIFont.fontNames(forFamilyName: family).first,
                let font = UIFont(name: name, size: 12)
            else { return false }
            return font.fontDescriptor.symbolicTraits.contains(.traitMonoSpace)
                || family.localizedCaseInsensitiveContains("mono")
        }
        #endif
    }
}
