import Foundation
import TermiuxCore
import XCTest

@testable import Termiux

private final class NoSecrets: SecretStore, @unchecked Sendable {
    func get(id: String) throws -> Data? { nil }
    func set(id: String, value: Data) throws {}
    func delete(id: String) throws {}
}

@MainActor
final class WorkspaceTests: XCTestCase {
    private var core: TermiuxCore!

    override func setUp() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        core = try TermiuxCore.open(dataDir: dir.path, secrets: NoSecrets(), platform: nil, agentSocket: nil)
    }

    private func session() -> TerminalSessionModel {
        TerminalSessionModel(kind: .local, core: core)
    }

    func testSplitFocusesNewPaneAndKeepsOrder() {
        let a = session(), b = session(), c = session()
        let tab = WorkspaceTab(session: a)
        tab.split(a.id, axis: .horizontal, with: b)
        XCTAssertEqual(tab.focusedID, b.id)
        tab.split(b.id, axis: .vertical, with: c)
        XCTAssertEqual(tab.sessions.map(\.id), [a.id, b.id, c.id])
    }

    func testRemovingCollapsesSplitsAndRefocuses() {
        let a = session(), b = session(), c = session()
        let tab = WorkspaceTab(session: a)
        tab.split(a.id, axis: .horizontal, with: b)
        tab.split(b.id, axis: .vertical, with: c)

        XCTAssertTrue(tab.remove(c.id))
        XCTAssertEqual(tab.sessions.map(\.id), [a.id, b.id])
        XCTAssertEqual(tab.focusedID, b.id, "focus moves to the neighbour that took the closed pane's place")

        XCTAssertTrue(tab.remove(a.id))
        guard case .leaf(let only) = tab.root else { return XCTFail("expected a single pane") }
        XCTAssertEqual(only.id, b.id)

        XCTAssertFalse(tab.remove(b.id), "removing the last pane empties the tab")
    }

    func testDirectionalFocus() {
        // a | b
        //   | c
        let a = session(), b = session(), c = session()
        let tab = WorkspaceTab(session: a)
        tab.split(a.id, axis: .horizontal, with: b)
        tab.split(b.id, axis: .vertical, with: c)

        tab.moveFocus(.up)
        XCTAssertEqual(tab.focusedID, b.id)
        tab.moveFocus(.left)
        XCTAssertEqual(tab.focusedID, a.id)
        tab.moveFocus(.left)
        XCTAssertEqual(tab.focusedID, a.id, "no pane further left")
        tab.moveFocus(.right)
        XCTAssertTrue([b.id, c.id].contains(tab.focusedID))
    }

    func testFramesFollowRatio() {
        let a = session(), b = session()
        let tab = WorkspaceTab(session: a)
        tab.split(a.id, axis: .horizontal, with: b)
        guard case .split(let node) = tab.root else { return XCTFail() }
        node.ratio = 0.25
        let frames = tab.root.frames()
        XCTAssertEqual(frames[0].1.width, 0.25, accuracy: 0.0001)
        XCTAssertEqual(frames[1].1.minX, 0.25, accuracy: 0.0001)
    }
}
