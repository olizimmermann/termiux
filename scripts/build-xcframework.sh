#!/usr/bin/env bash
# Builds the Rust core for Apple platforms and packages it as TermiuxCoreFFI.xcframework
# plus generated Swift bindings inside apple/Packages/TermiuxCore.
#   PROFILE=release|debug (default release)   PLATFORMS="macos ios" (default both)
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

PROFILE="${PROFILE:-release}"
PLATFORMS="${PLATFORMS:-macos ios}"
CARGO_FLAGS=""; [[ "$PROFILE" == release ]] && CARGO_FLAGS="--release"
LIB=libtermiux_ffi.a
PKG=apple/Packages/TermiuxCore
OUT=apple/build/ffi
rm -rf "$OUT" "$PKG/TermiuxCoreFFI.xcframework"
mkdir -p "$OUT/headers" "$PKG/Sources/TermiuxCore"

build() { (cd core && cargo build -p termiux-ffi --lib $CARGO_FLAGS --target "$1"); }
lib() { echo "core/target/$1/$PROFILE/$LIB"; }

XC_ARGS=()
if [[ " $PLATFORMS " == *" macos "* ]]; then
  build aarch64-apple-darwin; build x86_64-apple-darwin
  mkdir -p "$OUT/macos"
  lipo -create "$(lib aarch64-apple-darwin)" "$(lib x86_64-apple-darwin)" -output "$OUT/macos/$LIB"
  XC_ARGS+=(-library "$OUT/macos/$LIB" -headers "$OUT/headers")
fi
if [[ " $PLATFORMS " == *" ios "* ]]; then
  build aarch64-apple-ios; build aarch64-apple-ios-sim
  XC_ARGS+=(-library "$(lib aarch64-apple-ios)" -headers "$OUT/headers")
  XC_ARGS+=(-library "$(lib aarch64-apple-ios-sim)" -headers "$OUT/headers")
fi

# Generate Swift bindings from the first built library's metadata.
FIRST_LIB=$(ls -t core/target/*-apple-*/$PROFILE/$LIB | head -1)
(cd core && cargo run -q -p termiux-ffi --bin uniffi-bindgen -- generate --library "../$FIRST_LIB" --language swift --out-dir "../$OUT/gen")
mv "$OUT/gen/termiux_ffi.swift" "$PKG/Sources/TermiuxCore/"
cp "$OUT/gen/termiux_ffiFFI.h" "$OUT/headers/"
cat > "$OUT/headers/module.modulemap" <<MAP
module termiux_ffiFFI {
    header "termiux_ffiFFI.h"
    export *
}
MAP

xcodebuild -create-xcframework "${XC_ARGS[@]}" -output "$PKG/TermiuxCoreFFI.xcframework" >/dev/null
echo "Built $PKG/TermiuxCoreFFI.xcframework ($PROFILE: $PLATFORMS)"
