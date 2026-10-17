import Testing

@testable import PowerVPNCore

@Test func extractsOnlyAllowlistedLoadedPlugins() {
  let log = """
    prefix loaded plugins: leadsecbridge charon nonce sessionToken rawCredential
    unrelated session=secret
    prefix loaded plugins: charon openssl eap-mschapv2
    """

  #expect(
    LoadedPluginParser.parse(log) == [
      "leadsecbridge", "charon", "nonce", "openssl", "eap-mschapv2",
    ])
}

@Test func extractsSingleStrongSwanDebugPathVersionWithoutGuessing() {
  let symbols = """
    /build/strongswan/lib5.8.0/libcharon.a(child_sa.o)
    /build/strongswan/strongswan-5.8.0/src/libcharon/daemon.c
    """
  #expect(
    StrongSwanVersionParser.parse(symbols)
      == OracleVersionFinding(value: "5.8.0", evidence: "debug_symbol_path")
  )
  #expect(StrongSwanVersionParser.parse("no debug paths").value == "unknown")
}

@Test func conflictingStrongSwanDebugVersionsStayUnknown() {
  let symbols = """
    /build/strongswan/lib5.8.0/libcharon.a(child_sa.o)
    /build/strongswan/strongswan-5.9.0/src/libcharon/daemon.c
    """
  let finding = StrongSwanVersionParser.parse(symbols)
  #expect(finding.value == "unknown")
  #expect(finding.evidence == "conflicting_debug_symbol_paths")
}

@Test func classifiesVendorPluginAndPrivateResourceRuleExtensionFromAllowlistedMarkers() {
  let symbols = """
    /build/strongswan/lib5.8.0/libcharon.a(child_sa.o)
    _strongswan_thread_create
    _vpn_ipsec_create
    _vpn_kernel_ipsec_register
    _ncv1_add_policy
    _kernel_libipsec_ipsec_create
    _kernel_osx_net_create
    _kernel_osx_router_create
    _xauth_create
    _mode_config_create
    _expandrule_payload_create
    _add_expandrule
    """
  let printableStrings = "com.apple.net.utun_control"
  let log = """
    loaded plugins: leadsecbridge charon nonce openssl
    feature CUSTOM:kernel-ipsec in critical plugin 'leadsecbridge' failed to load
    generating QUICK_MODE request 1 [ HASH ADDRULE ]
    intergration v1,send expandrule payload
    """

  let findings = VendorOracleAnalyzer.analyze(
    symbolText: symbols,
    printableStrings: printableStrings,
    allowlistedLogText: log
  )

  #expect(findings.upstreamStrongSwanVersion.value == "5.8.0")
  #expect(findings.staticEvidence.strongSwan.observed)
  #expect(findings.staticEvidence.leadsecbridge.observed)
  #expect(findings.staticEvidence.kernelLibIPSec.observed)
  #expect(findings.staticEvidence.kernelOSX.observed)
  #expect(findings.staticEvidence.xAuth.observed)
  #expect(findings.staticEvidence.modeConfig.observed)
  #expect(!findings.staticEvidence.vici.observed)
  #expect(findings.leadsecbridgeClassification.configurationAdapter == .unknown)
  #expect(findings.leadsecbridgeClassification.customStrongSwanPlugin == .confirmed)
  #expect(findings.leadsecbridgeClassification.privateIKEv1ResourceRuleExtension == .confirmed)
}
