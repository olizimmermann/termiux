import SwiftUI
import TermiuxCore

/// Small background/foreground chip.
struct Swatch: View {
    let theme: ThemeRecord

    var body: some View {
        RoundedRectangle(cornerRadius: 3)
            .fill(color(theme.background))
            .overlay(Text("A").font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(color(theme.foreground)))
            .frame(width: 18, height: 14)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(.separator))
    }

    private func color(_ hex: String) -> Color { Color(hex: hex) }
}

/// A fake prompt and listing rendered in the theme's colours.
struct ThemePreview: View {
    let theme: ThemeRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            line([("me@server", 2), (":", nil), ("~/src", 4), ("$ ", nil), ("ls -la", nil)])
            line([("drwxr-xr-x ", nil), ("build", 4)])
            line([("-rwxr-xr-x ", nil), ("deploy.sh", 2)])
            line([("error: ", 1), ("connection refused", nil)])
            line([("warning: ", 3), ("disk 91% full", nil)])
            HStack(spacing: 0) {
                ForEach(0..<16, id: \.self) { i in
                    Rectangle().fill(color(theme.palette[safe: i] ?? "")).frame(width: 18, height: 14)
                }
            }
            .padding(.top, 6)
        }
        .font(.system(size: 12, design: .monospaced))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color(theme.background), in: RoundedRectangle(cornerRadius: 8))
    }

    private func line(_ parts: [(String, Int?)]) -> some View {
        parts.reduce(Text("")) { text, part in
            text + Text(part.0).foregroundColor(color(part.1.map { theme.palette[safe: $0] ?? "" } ?? theme.foreground))
        }
    }

    private func color(_ hex: String) -> Color { Color(hex: hex) }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}
