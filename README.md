# Termiux

A fast, lightweight SSH client and terminal. macOS first; iOS, Linux, Windows and Android later.

- `core/`: Rust workspace (SSH via russh, data model, UniFFI bindings)
- `apple/`: SwiftUI app for macOS and iOS (`project.yml` is the source of truth; run `xcodegen generate`)
- `scripts/build-xcframework.sh`: builds the Rust core for Apple platforms
- `scripts/test-sshd.sh`: SSH integration tests against a throwaway OpenSSH server in Docker

Licensed under GPL-3.0-or-later.
