// swift-tools-version: 6.0
import PackageDescription

// Wraps the Rust core. Build the xcframework first: scripts/build-xcframework.sh
let package = Package(
    name: "TermiuxCore",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "TermiuxCore", targets: ["TermiuxCore"])],
    targets: [
        .binaryTarget(name: "TermiuxCoreFFI", path: "TermiuxCoreFFI.xcframework"),
        .target(
            name: "TermiuxCore",
            dependencies: ["TermiuxCoreFFI"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
