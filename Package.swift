// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Keycard",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "Keycard",
            targets: ["Keycard"]),
    ],
    dependencies: [
        .package(url: "https://github.com/gnosis/secp256k1.swift.git", .branch("master")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.0.0"))

    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Keycard",
            dependencies: ["secp256k1", "CryptoSwift"]),
        .testTarget(
            name: "KeycardTests",
            dependencies: ["Keycard"]),
    ]
)
