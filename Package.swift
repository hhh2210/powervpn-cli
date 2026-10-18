// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "powervpn-cli",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "powervpn-native-trial", targets: ["PowerVPNNativeTrial"]),
    .executable(name: "powervpn", targets: ["PowerVPNCLI"]),
    .executable(name: "powervpn-native-helper", targets: ["PowerVPNNativeHelper"]),
    .executable(
      name: "powervpn-tls-evidence",
      targets: ["PowerVPNTLSEvidenceCLI"]
    ),
  ],
  targets: [
    .executableTarget(
      name: "PowerVPNNativeTrial",
      dependencies: ["PowerVPNCore", "PowerVPNPortal", "PowerVPNProduct"]),
    .executableTarget(name: "PowerVPNNativeHelper", dependencies: ["PowerVPNCore"]),
    .target(
      name: "CPortalCurl",
      linkerSettings: [.linkedLibrary("curl")]
    ),
    .target(
      name: "CPowerVPNXPCSession",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .target(name: "PowerVPNCore", dependencies: ["CPowerVPNXPCSession"]),
    .target(name: "PowerVPNPortal", dependencies: ["CPortalCurl"]),
    .target(
      name: "PowerVPNProduct",
      dependencies: ["PowerVPNCore", "PowerVPNPortal"]
    ),
    .target(name: "PowerVPNTLSEvidence", dependencies: ["PowerVPNPortal"]),
    .executableTarget(
      name: "PowerVPNCLI",
      dependencies: ["PowerVPNCore", "PowerVPNPortal", "PowerVPNProduct"]
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
      name: "PowerVPNProductTests",
      dependencies: ["PowerVPNCore", "PowerVPNPortal", "PowerVPNProduct", "PowerVPNCLI"]
    ),
    .testTarget(
      name: "PowerVPNTLSEvidenceTests",
      dependencies: ["PowerVPNTLSEvidence"],
      resources: [.copy("Fixtures")]
    ),
  ]
)
