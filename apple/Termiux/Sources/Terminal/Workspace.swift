import Foundation
import Observation

/// A split: `first` is left/top, `second` right/bottom.
@MainActor
@Observable
final class SplitNode: Identifiable {
    enum Axis { case horizontal, vertical }

    let id = UUID()
    /// `.horizontal` places panes side by side.
    let axis: Axis
    var ratio: CGFloat
    var first: PaneNode
    var second: PaneNode

    init(axis: Axis, ratio: CGFloat = 0.5, first: PaneNode, second: PaneNode) {
        self.axis = axis
        self.ratio = ratio
        self.first = first
        self.second = second
    }
}

enum PaneNode {
    case leaf(TerminalSessionModel)
    case split(SplitNode)

    @MainActor var sessions: [TerminalSessionModel] {
        switch self {
        case .leaf(let s): [s]
        case .split(let n): n.first.sessions + n.second.sessions
        }
    }

    /// Replaces the leaf `id` with `replacement`.
    @MainActor func replacing(_ id: TerminalSessionModel.ID, with replacement: PaneNode) -> PaneNode {
        switch self {
        case .leaf(let s): return s.id == id ? replacement : self
        case .split(let n):
            n.first = n.first.replacing(id, with: replacement)
            n.second = n.second.replacing(id, with: replacement)
            return self
        }
    }

    /// Removes the leaf `id`; its sibling takes the split's place. Nil if nothing is left.
    @MainActor func removing(_ id: TerminalSessionModel.ID) -> PaneNode? {
        switch self {
        case .leaf(let s): return s.id == id ? nil : self
        case .split(let n):
            let first = n.first.removing(id)
            let second = n.second.removing(id)
            switch (first, second) {
            case (nil, nil): return nil
            case (let only?, nil), (nil, let only?): return only
            case (let f?, let s?):
                n.first = f
                n.second = s
                return self
            }
        }
    }

    /// Each pane's frame within the unit square, for directional focus moves.
    @MainActor func frames(in rect: CGRect = CGRect(x: 0, y: 0, width: 1, height: 1))
        -> [(TerminalSessionModel, CGRect)]
    {
        switch self {
        case .leaf(let s): return [(s, rect)]
        case .split(let n):
            let (a, b): (CGRect, CGRect)
            if n.axis == .horizontal {
                let w = rect.width * n.ratio
                a = CGRect(x: rect.minX, y: rect.minY, width: w, height: rect.height)
                b = CGRect(x: rect.minX + w, y: rect.minY, width: rect.width - w, height: rect.height)
            } else {
                let h = rect.height * n.ratio
                a = CGRect(x: rect.minX, y: rect.minY, width: rect.width, height: h)
                b = CGRect(x: rect.minX, y: rect.minY + h, width: rect.width, height: rect.height - h)
            }
            return n.first.frames(in: a) + n.second.frames(in: b)
        }
    }
}

enum FocusDirection { case left, right, up, down }

/// A tab: a tree of panes with one focused pane.
@MainActor
@Observable
final class WorkspaceTab: Identifiable {
    let id = UUID()
    var root: PaneNode
    var focusedID: TerminalSessionModel.ID

    init(session: TerminalSessionModel) {
        root = .leaf(session)
        focusedID = session.id
    }

    var sessions: [TerminalSessionModel] { root.sessions }
    var focused: TerminalSessionModel? { sessions.first { $0.id == focusedID } ?? sessions.first }

    var title: String {
        guard let focused else { return "" }
        let count = sessions.count
        return count > 1 ? "\(focused.name) (+\(count - 1))" : focused.name
    }

    func split(_ id: TerminalSessionModel.ID, axis: SplitNode.Axis, with session: TerminalSessionModel) {
        guard let existing = sessions.first(where: { $0.id == id }) else { return }
        let node = SplitNode(axis: axis, first: .leaf(existing), second: .leaf(session))
        root = root.replacing(id, with: .split(node))
        focusedID = session.id
    }

    /// Removes a pane; returns false when the tab is now empty.
    func remove(_ id: TerminalSessionModel.ID) -> Bool {
        let order = sessions.map(\.id)
        guard let newRoot = root.removing(id) else { return false }
        root = newRoot
        if focusedID == id, let index = order.firstIndex(of: id) {
            let remaining = sessions.map(\.id)
            focusedID = remaining[min(index, remaining.count - 1)]
        }
        return true
    }

    /// Moves focus to the nearest pane in `direction`, measured between pane centres.
    func moveFocus(_ direction: FocusDirection) {
        let frames = root.frames()
        guard let current = frames.first(where: { $0.0.id == focusedID })?.1 else { return }
        let candidates = frames.filter { _, r in
            switch direction {
            case .left: r.maxX <= current.minX + 0.001
            case .right: r.minX >= current.maxX - 0.001
            case .up: r.maxY <= current.minY + 0.001
            case .down: r.minY >= current.maxY - 0.001
            }
        }
        let distance = { (r: CGRect) in hypot(r.midX - current.midX, r.midY - current.midY) }
        if let best = candidates.min(by: { distance($0.1) < distance($1.1) }) {
            focusedID = best.0.id
        }
    }
}
