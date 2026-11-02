// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NotificationsGateway",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", exact: "4.77.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(name: "NotificationsGateway", dependencies: [
            .product(name: "Vapor", package: "vapor"),
            .product(name: "Logging", package: "swift-log"),
        ]),
    ]
)
