// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "powervpn-cli",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "powervpn", targets: ["PowerVPNCLI"]),
    .executable(
      name: "powervpn-tls-evidence",
      targets: ["PowerVPNTLSEvidenceCLI"]
    ),
  ],
  targets: [
    .target(
      name: "CPortalCurl",
      linkerSettings: [.linkedLibrary("curl")]
    ),
    .target(name: "PowerVPNCore"),
    .target(name: "PowerVPNPortal", dependencies: ["CPortalCurl"]),
    .target(name: "PowerVPNTLSEvidence"),
    .executableTarget(
      name: "PowerVPNCLI",
      dependencies: ["PowerVPNCore", "PowerVPNPortal"]
    ),
    .executableTarget(
      name: "PowerVPNTLSEvidenceCLI",
      dependencies: ["PowerVPNTLSEvidence"]
    ),
    .testTarget(
      name: "PowerVPNCoreTests",
      dependencies: ["PowerVPNCore"]
    ),
    .testTarget(
      name: "PowerVPNPortalTests",
      dependencies: ["CPortalCurl", "PowerVPNPortal", "PowerVPNCLI"]
    ),
    .testTarget(
      name: "PowerVPNTLSEvidenceTests",
      dependencies: ["PowerVPNTLSEvidence"],
      resources: [.copy("Fixtures")]
    ),
  ]
)
