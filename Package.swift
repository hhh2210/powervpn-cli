// swift-tools-version: 6.0

import PackageDescription

// -ftyped-memory-operations arrived with the Enhanced Security toolchains
// (Swift 6.2); the clang of older ones rejects it.
#if compiler(>=6.2)
  let typedAllocation = ["-ftyped-memory-operations"]
#else
  let typedAllocation: [String] = []
#endif

/// The compiler side of Xcode's Enhanced Security for our own C code (see
/// docs/security-settings.md): security warnings, stack zero-initialization
/// and, where the toolchain has it, type-aware allocation.
let hardenedC: [CSetting] = [
  .unsafeFlags(
    [
      "-Werror=return-type", "-Wuninitialized", "-Wconditional-uninitialized",
      "-Wimplicit-fallthrough", "-Wshorten-64-to-32", "-Werror=implicit-function-declaration",
      "-Wshadow", "-Wempty-body", "-Wformat-nonliteral", "-Warray-bounds",
      "-Warray-bounds-pointer-arithmetic", "-Wsuspicious-memaccess", "-Wsizeof-array-div",
      "-Wsizeof-pointer-div", "-Wreturn-stack-address", "-Wbuiltin-memcpy-chk-size",
      "-ftrivial-auto-var-init=zero",
    ] + typedAllocation)
]

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
      cSettings: hardenedC,
      linkerSettings: [.linkedLibrary("curl")]
    ),
    .target(
      name: "CPowerVPNXPCSession",
      cSettings: hardenedC,
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
