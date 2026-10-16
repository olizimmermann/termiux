# Termiux

A fast, lightweight SSH client and terminal. macOS first; iOS, Linux, Windows and Android later.

- `core/`: Rust workspace (SSH via russh, data model, UniFFI bindings)
- `apple/`: SwiftUI app for macOS and iOS (`project.yml` is the source of truth; run `xcodegen generate`)
- `scripts/build-xcframework.sh`: builds the Rust core for Apple platforms
- `scripts/test-sshd.sh`: SSH integration tests against a throwaway OpenSSH server in Docker

Licensed under GPL-3.0-or-later.

## Development

```sh
scripts/build-xcframework.sh          # Rust core -> apple/Packages/TermiuxCore (PROFILE=debug PLATFORMS=macos for speed)
(cd apple && xcodegen generate)       # regenerate Termiux.xcodeproj from project.yml
(cd core && cargo test --workspace)   # Rust tests (Docker SSH tests: scripts/test-sshd.sh)
scripts/dev-sshd.sh                   # SSH server on 127.0.0.1:2222 (termiux/termiux) for trying the app
xcodebuild -project apple/Termiux.xcodeproj -scheme Termiux -skipPackagePluginValidation test
```

Shortcuts: ⌘K quick connect · ⌘T local shell · ⌘D / ⌘⇧D split right/down · ⌘⌥←→↑↓ move between panes ·
⌘W close pane · ⌘⇧W close tab · ⌘⇧[ ⌘⇧] / ⌘1–9 switch tabs.
