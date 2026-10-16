import SwiftUI
#if os(macOS)
import AppKit
#endif

/// Renders a tab's split tree with draggable dividers; `leaf` draws one terminal pane.
struct PaneTreeView<Leaf: View>: View {
    let node: PaneNode
    let tab: WorkspaceTab
    @ViewBuilder let leaf: (TerminalSessionModel) -> Leaf

    var body: some View {
        switch node {
        case .leaf(let session):
            leaf(session).id(session.id)
        case .split(let split):
            SplitView(split: split, tab: tab, leaf: leaf)
        }
    }
}

private struct SplitView<Leaf: View>: View {
    @Bindable var split: SplitNode
    let tab: WorkspaceTab
    let leaf: (TerminalSessionModel) -> Leaf
    private let divider: CGFloat = 1

    var body: some View {
        GeometryReader { geo in
            let horizontal = split.axis == .horizontal
            let total = horizontal ? geo.size.width : geo.size.height
            let firstLength = max(0, total * split.ratio - divider / 2)
            let layout = horizontal ? AnyLayout(HStackLayout(spacing: 0)) : AnyLayout(VStackLayout(spacing: 0))
            layout {
                PaneTreeView(node: split.first, tab: tab, leaf: leaf)
                    .frame(width: horizontal ? firstLength : nil, height: horizontal ? nil : firstLength)
                PaneDivider(horizontal: horizontal) { delta in
                    guard total > 0 else { return }
                    split.ratio = min(0.9, max(0.1, split.ratio + delta / total))
                }
                PaneTreeView(node: split.second, tab: tab, leaf: leaf)
            }
        }
    }
}

/// 1pt line with a wider invisible grab area (the resize cursor on macOS, a touch-sized handle on iPad).
private struct PaneDivider: View {
    let horizontal: Bool
    let onDrag: (CGFloat) -> Void
    @State private var last: CGFloat = 0

    #if os(macOS)
    private let grabWidth: CGFloat = 8
    #else
    private let grabWidth: CGFloat = 22
    #endif

    var body: some View {
        Rectangle()
            .fill(.separator)
            .frame(width: horizontal ? 1 : nil, height: horizontal ? nil : 1)
            .overlay {
                Color.clear
                    .frame(width: horizontal ? grabWidth : nil, height: horizontal ? nil : grabWidth)
                    .contentShape(Rectangle())
                    #if os(macOS)
                    .onHover { inside in
                        if inside {
                            (horizontal ? NSCursor.resizeLeftRight : NSCursor.resizeUpDown).push()
                        } else {
                            NSCursor.pop()
                        }
                    }
                    #else
                    .overlay {
                        Capsule().fill(.secondary)
                            .frame(width: horizontal ? 4 : 36, height: horizontal ? 36 : 4)
                    }
                    .hoverEffect(.highlight)
                    #endif
                    .gesture(
                        DragGesture(minimumDistance: 1, coordinateSpace: .global)
                            .onChanged { value in
                                let position = horizontal ? value.translation.width : value.translation.height
                                onDrag(position - last)
                                last = position
                            }
                            .onEnded { _ in last = 0 }
                    )
            }
            .zIndex(1)
    }
}
