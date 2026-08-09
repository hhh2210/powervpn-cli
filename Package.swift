// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "powervpn-cli",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "powervpn", targets: ["PowerVPNCLI"])
  ],
  targets: [
    .target(
      name: "CPortalCurl",
      linkerSettings: [.linkedLibrary("curl")]
    ),
    .target(name: "PowerVPNCore"),
    .target(name: "PowerVPNPortal", dependencies: ["CPortalCurl"]),
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
      dependencies: ["CPortalCurl", "PowerVPNPortal", "PowerVPNCLI"]
    ),
  ]
)
