import PowerVPNCore

@testable import PowerVPNProduct

func completeValidation() -> VendorCharonStartValidation {
  let lineage = VendorCharonStartLineage()
  return VendorCharonStartValidator.validate(
    VendorCharonStartCandidate(
      lineage: lineage,
      common: completeCommonCandidate(lineage: lineage),
      tunnels: completeTunnelCandidates(lineage: lineage)
    )
  )
}

func completeCommonCandidate(
  lineage: VendorCharonStartLineage
) -> VendorCharonStartCommonCandidate {
  VendorCharonStartCommonCandidate(
    sessionID: productText("session-id", lineage: lineage),
    gateway: productText("gateway", lineage: lineage),
    ikePort: productInteger(500, lineage: lineage),
    majorVersion: productInteger(1, lineage: lineage),
    ike: productText("aes128-sha1-modp1024", lineage: lineage),
    esp: productText("aes128-sha1", lineage: lineage),
    psk: productText("psk", lineage: lineage),
    ikeLifetime: productInteger(3_600, lineage: lineage),
    ipsecLifetime: productInteger(3_600, lineage: lineage)
  )
}

func completeTunnelCandidates(
  lineage: VendorCharonStartLineage
) -> [VendorCharonStartTunnelCandidate] {
  [
    VendorCharonStartTunnelCandidate(
      authority: productInteger(1, lineage: lineage),
      status: productInteger(1, lineage: lineage),
      tunnelName: productText("tunnel", lineage: lineage),
      family: productInteger(4, lineage: lineage),
      resourceFlag: productInteger(0, lineage: lineage),
      name: productText("resource", lineage: lineage),
      routes: [],
      mapID: productText("map-id", lineage: lineage)
    )
  ]
}

func productText(
  _ value: String,
  lineage: VendorCharonStartLineage
) -> VendorCharonStartTextValue {
  VendorCharonStartTextValue(
    value: ProductTestTextMaterial(value),
    source: .authenticatedPortalResource,
    lineage: lineage
  )
}

func productInteger(
  _ value: Int32,
  lineage: VendorCharonStartLineage
) -> VendorCharonStartIntegerValue {
  VendorCharonStartIntegerValue(
    value: value,
    source: .authenticatedPortalResource,
    lineage: lineage
  )
}

func productSummary(_ suffix: String) -> ProductResourceSummary {
  ProductResourceSummary(
    handle: "synthetic-handle-\(suffix)",
    displayName: "synthetic-\(suffix)"
  )
}

private struct ProductTestTextMaterial: VendorCharonStartTextMaterial {
  private let bytes: [UInt8]

  init(_ value: String) {
    bytes = Array(value.utf8)
  }

  var byteCount: Int { bytes.count }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
}

struct FixedProductObservation: ProductReadinessObserving {
  let value: ProductReadinessObservation

  init(_ value: ProductReadinessObservation) {
    self.value = value
  }

  func observe() -> ProductReadinessObservation { value }
}
