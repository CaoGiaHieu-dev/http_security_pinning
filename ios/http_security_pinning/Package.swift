// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "http_security_pinning",
    platforms: [
        .iOS("12.0")
    ],
    products: [
        .library(name: "http-security-pinning", targets: ["http_security_pinning"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "http_security_pinning",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            publicHeadersPath: "include"
        )
    ]
)
