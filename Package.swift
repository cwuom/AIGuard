// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AIGuard",
    platforms: [.macOS(.v26)],
    products: [
        .executable(name: "AIGuard", targets: ["AIGuard"]),
        .executable(name: "aiguardd", targets: ["aiguardd"]),
    ],
    targets: [
        .target(name: "AIGuardCore"),
        .executableTarget(name: "aiguardd", dependencies: ["AIGuardCore"]),
        .executableTarget(name: "AIGuard", dependencies: ["AIGuardCore"]),
        .testTarget(name: "AIGuardCoreTests", dependencies: ["AIGuardCore"]),
    ]
)
