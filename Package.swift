// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "powervpn-cli",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "powervpn", targets: ["PowerVPNCLI"])
  ],
  targets: [
    .target(name: "PowerVPNCore"),
    .target(name: "PowerVPNPortal"),
    .executableTarget(
      name: "PowerVPNCLI",
      dependencies: ["PowerVPNCore", "PowerVPNPortal"]
    ),
    .testTarget(
      name: "PowerVPNCoreTests",
      dependencies: ["PowerVPNCore"]
    ),
    .testTarget(
      name: "PowerVPNPortalTests",
      dependencies: ["PowerVPNPortal", "PowerVPNCLI"]
    ),
  ]
)
