import CryptoKit
import Foundation

extension SystemInspector {
  public static let vendorHelperPaths = [
    "/Library/PrivilegedHelperTools/com.leadsec.charon-xpc",
    "/Library/PrivilegedHelperTools/com.leadsec.ipsec-xpc",
    "\(appPath)/Contents/Library/LaunchServices/com.leadsec.charon-xpc",
    "\(appPath)/Contents/Library/LaunchServices/com.leadsec.ipsec-xpc",
    "\(appPath)/Contents/Library/LaunchServices/com.leadsec.sh-xpc",
    "\(appPath)/Contents/Library/LaunchServices/com.leadsec.cs-xpc",
  ]

  public func oracleInventory() -> VendorHelperInventory {
    let bundle = Bundle(url: URL(fileURLWithPath: Self.appPath))
    let vendor = VendorBuildInfo(
      version: bundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        ?? "unknown",
      build: bundle?.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
    )
    let helpers = Self.vendorHelperPaths.compactMap { helperArtifact(at: $0, build: vendor.build) }
    let charonPath = Self.vendorHelperPaths.first {
      $0.hasSuffix("com.leadsec.charon-xpc") && FileManager.default.fileExists(atPath: $0)
    }
    let symbolText = charonPath.flatMap {
      try? runner.run("/usr/bin/nm", ["-a", "-j", $0])
    } ?? ""
    let printableStrings = charonPath.flatMap {
      try? runner.run("/usr/bin/strings", ["-a", $0])
    } ?? ""
    let allowlistedLogText = AllowlistedLogReader.readLines(
      path: Self.logPath,
      maximumBytes: 2 * 1_024 * 1_024,
      markers: VendorOracleAnalyzer.allowlistedLogMarkers,
      sanitizer: VendorOracleAnalyzer.sanitizeAllowlistedLogLine
    )
    let findings = VendorOracleAnalyzer.analyze(
      symbolText: symbolText,
      printableStrings: printableStrings,
      allowlistedLogText: allowlistedLogText
    )

    return VendorHelperInventory(
      vendor: vendor,
      helpers: helpers,
      loadedPlugins: findings.loadedPlugins,
      upstreamStrongSwanVersion: findings.upstreamStrongSwanVersion,
      staticEvidence: findings.staticEvidence,
      leadsecbridgeClassification: findings.leadsecbridgeClassification
    )
  }

  private func helperArtifact(at path: String, build: String) -> VendorHelperArtifact? {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
      !isDirectory.boolValue
    else { return nil }
    return VendorHelperArtifact(
      path: path,
      architectures: architectures(of: path),
      sha256: sha256(of: path) ?? "unknown",
      vendorBuild: build
    )
  }

  private func sha256(of path: String) -> String? {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
    else { return nil }
    let digest = SHA256.hash(data: data)
    return digest.map { String(format: "%02x", $0) }.joined()
  }
}
