import AppKit
import SwiftUI

/// Renders a tab's split tree with draggable dividers.
struct PaneTreeView: View {
    let node: PaneNode
    let tab: WorkspaceTab

    var body: some View {
        switch node {
        case .leaf(let session):
            TerminalPane(session: session, tab: tab).id(session.id)
        case .split(let split):
            SplitView(split: split, tab: tab)
        }
    }
}

private struct SplitView: View {
    @Bindable var split: SplitNode
    let tab: WorkspaceTab
    private let divider: CGFloat = 1

    var body: some View {
        GeometryReader { geo in
            let horizontal = split.axis == .horizontal
            let total = horizontal ? geo.size.width : geo.size.height
            let firstLength = max(0, total * split.ratio - divider / 2)
            let layout = horizontal ? AnyLayout(HStackLayout(spacing: 0)) : AnyLayout(VStackLayout(spacing: 0))
            layout {
                PaneTreeView(node: split.first, tab: tab)
                    .frame(width: horizontal ? firstLength : nil, height: horizontal ? nil : firstLength)
                Divider(horizontal: horizontal) { delta in
                    guard total > 0 else { return }
                    split.ratio = min(0.9, max(0.1, split.ratio + delta / total))
                }
                PaneTreeView(node: split.second, tab: tab)
            }
        }
    }
}

/// 1pt line with a wider invisible grab area and the resize cursor.
private struct Divider: View {
    let horizontal: Bool
    let onDrag: (CGFloat) -> Void
    @State private var last: CGFloat = 0

    var body: some View {
        Rectangle()
            .fill(Color(nsColor: .separatorColor))
            .frame(width: horizontal ? 1 : nil, height: horizontal ? nil : 1)
            .overlay {
                Color.clear
                    .frame(width: horizontal ? 8 : nil, height: horizontal ? nil : 8)
                    .contentShape(Rectangle())
                    .onHover { inside in
                        if inside {
                            (horizontal ? NSCursor.resizeLeftRight : NSCursor.resizeUpDown).push()
                        } else {
                            NSCursor.pop()
                        }
                    }
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
