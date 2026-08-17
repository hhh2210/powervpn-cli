import Foundation

public struct VendorOracleFindings: Equatable, Sendable {
  public let loadedPlugins: [String]
  public let upstreamStrongSwanVersion: OracleVersionFinding
  public let staticEvidence: VendorStaticEvidence
  public let leadsecbridgeClassification: LeadsecBridgeClassification
}

public enum VendorOracleAnalyzer {
  public static let allowlistedLogMarkers = [
    "loaded plugins:",
    "feature CUSTOM:kernel-ipsec in critical plugin 'leadsecbridge' failed to load",
    "generating QUICK_MODE request",
    "[ HASH ADDRULE ]",
    "intergration v1,send expandrule payload",
    "intergration v1,parse expandrule payload",
  ]

  public static func analyze(
    symbolText: String,
    printableStrings: String,
    allowlistedLogText: String
  ) -> VendorOracleFindings {
    let loadedPlugins = LoadedPluginParser.parse(allowlistedLogText)
    let upstreamVersion = StrongSwanVersionParser.parse(symbolText)
    let combinedStaticText = symbolText + "\n" + printableStrings

    let strongSwanMarkers = markers([
      (upstreamVersion.value != "unknown", "strongswan_debug_path"),
      (combinedStaticText.contains("_strongswan_thread_create"), "strongswan_symbols"),
    ])
    let leadsecbridgeMarkers = markers([
      (loadedPlugins.contains("leadsecbridge"), "loaded_plugin"),
      (
        allowlistedLogText.contains(
          "feature CUSTOM:kernel-ipsec in critical plugin 'leadsecbridge' failed to load"
        ),
        "custom_kernel_ipsec_feature"
      ),
      (
        combinedStaticText.contains("_vpn_ipsec_create")
          && combinedStaticText.contains("_vpn_kernel_ipsec_register"),
        "vendor_kernel_ipsec_symbols"
      ),
      (combinedStaticText.contains("_ncv1_add_policy"), "ncv1_policy_symbols"),
      (
        combinedStaticText.contains("_expandrule_payload_create")
          && combinedStaticText.contains("_add_expandrule"),
        "expandrule_symbols"
      ),
      (
        allowlistedLogText.contains("generating QUICK_MODE request")
          && allowlistedLogText.contains("[ HASH ADDRULE ]"),
        "quick_mode_addrule_log"
      ),
      (
        allowlistedLogText.contains("intergration v1,send expandrule payload")
          || allowlistedLogText.contains("intergration v1,parse expandrule payload"),
        "expandrule_v1_log"
      ),
    ])
    let kernelLibIPSecMarkers = markers([
      (
        combinedStaticText.contains("_kernel_libipsec_ipsec_create")
          || combinedStaticText.contains("_kernel_libipsec_plugin_create"),
        "kernel_libipsec_symbols"
      )
    ])
    let kernelOSXMarkers = markers([
      (
        combinedStaticText.contains("_kernel_osx_net_create")
          && combinedStaticText.contains("_kernel_osx_router_create"),
        "kernel_osx_symbols"
      ),
      (combinedStaticText.contains("com.apple.net.utun_control"), "utun_control_string"),
    ])
    let xAuthMarkers = markers([
      (
        combinedStaticText.contains("_xauth_create")
          || combinedStaticText.contains("_xauth_manager_create"),
        "xauth_symbols"
      )
    ])
    let modeConfigMarkers = markers([
      (
        combinedStaticText.contains("_mode_config_create")
          || combinedStaticText.contains("_queue_mode_config_push"),
        "mode_config_symbols"
      )
    ])
    let viciMarkers = markers([
      (
        combinedStaticText.contains("_vici_")
          || combinedStaticText.contains("vici_plugin_create")
          || combinedStaticText.contains("/plugins/vici/"),
        "vici_symbols"
      )
    ])

    let staticEvidence = VendorStaticEvidence(
      strongSwan: OracleEvidenceMarker(markers: strongSwanMarkers),
      leadsecbridge: OracleEvidenceMarker(markers: leadsecbridgeMarkers),
      kernelLibIPSec: OracleEvidenceMarker(markers: kernelLibIPSecMarkers),
      kernelOSX: OracleEvidenceMarker(markers: kernelOSXMarkers),
      xAuth: OracleEvidenceMarker(markers: xAuthMarkers),
      modeConfig: OracleEvidenceMarker(markers: modeConfigMarkers),
      vici: OracleEvidenceMarker(markers: viciMarkers)
    )
    let customPlugin: OracleClassificationState =
      leadsecbridgeMarkers.contains(
        "custom_kernel_ipsec_feature"
      ) ? .confirmed : .unknown
    let privateWireExtension: OracleClassificationState =
      leadsecbridgeMarkers.contains(
        "expandrule_symbols"
      )
        && (leadsecbridgeMarkers.contains("quick_mode_addrule_log")
          || leadsecbridgeMarkers.contains("expandrule_v1_log"))
      ? .confirmed : .unknown

    return VendorOracleFindings(
      loadedPlugins: loadedPlugins,
      upstreamStrongSwanVersion: upstreamVersion,
      staticEvidence: staticEvidence,
      leadsecbridgeClassification: LeadsecBridgeClassification(
        customStrongSwanPlugin: customPlugin,
        privateIKEv1ResourceRuleExtension: privateWireExtension
      )
    )
  }

  public static func sanitizeAllowlistedLogLine(_ line: String) -> String? {
    var events: [String] = []
    if line.contains("loaded plugins:") {
      let plugins = LoadedPluginParser.parse(line)
      events.append(
        plugins.isEmpty ? "loaded plugins:" : "loaded plugins: \(plugins.joined(separator: " "))"
      )
    }
    for marker in allowlistedLogMarkers where marker != "loaded plugins:" && line.contains(marker) {
      events.append(marker)
    }
    return events.isEmpty ? nil : events.joined(separator: " ")
  }

  private static func markers(_ candidates: [(Bool, String)]) -> [String] {
    candidates.compactMap { observed, marker in observed ? marker : nil }
  }
}

public enum LoadedPluginParser {
  private static let safePluginNames: Set<String> = [
    "leadsecbridge", "charon", "nonce", "sm4", "sm3", "openssl", "hash_null",
    "fips-prf", "hmac", "socket-default", "random", "pubkey", "pkcs1", "pkcs8",
    "pem", "xcbc", "eap-identity", "eap-mschapv2", "eap-md5", "eap-gtc",
  ]

  public static func parse(_ text: String) -> [String] {
    var seen = Set<String>()
    var plugins: [String] = []
    for line in text.split(whereSeparator: \.isNewline) {
      guard let marker = line.range(of: "loaded plugins:") else { continue }
      for token in line[marker.upperBound...].split(whereSeparator: \.isWhitespace).prefix(128) {
        let plugin = String(token)
        guard safePluginNames.contains(plugin), plugin.count <= 64,
          plugin.range(
            of: #"^[A-Za-z0-9][A-Za-z0-9_.+-]*$"#,
            options: .regularExpression
          ) != nil,
          seen.insert(plugin).inserted
        else { continue }
        plugins.append(plugin)
      }
    }
    return plugins
  }
}

public enum StrongSwanVersionParser {
  public static func parse(_ symbolText: String) -> OracleVersionFinding {
    let pattern = #"(?i)strongswan(?:/lib|-)([0-9]+\.[0-9]+\.[0-9]+)"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
      return OracleVersionFinding(value: "unknown", evidence: "not_observed")
    }
    let range = NSRange(symbolText.startIndex..., in: symbolText)
    let versions = Set(
      regex.matches(in: symbolText, range: range).compactMap { match -> String? in
        guard let versionRange = Range(match.range(at: 1), in: symbolText) else { return nil }
        return String(symbolText[versionRange])
      })
    guard versions.count == 1, let version = versions.first else {
      return OracleVersionFinding(
        value: "unknown",
        evidence: versions.isEmpty ? "not_observed" : "conflicting_debug_symbol_paths"
      )
    }
    return OracleVersionFinding(value: version, evidence: "debug_symbol_path")
  }
}
