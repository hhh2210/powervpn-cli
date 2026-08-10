import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonStartContractTests {
  @Test func contractLocksExactConsumerOrderAndOptionalityWithoutHostItem() {
    #expect(
      VendorCharonStartContract.orderedRules.map(\.field) == [
        .type, .rpc, .common, .tunnels, .sessionID, .vip, .vipv6, .gateway,
        .ikePort, .majorVersion, .ike, .esp, .psk, .ikeLifetime, .ipsecLifetime,
        .authority, .status, .tunnelName, .family, .resourceFlag, .name, .routes,
        .mapID, .negotiateMode, .routeNetwork, .routePrefix,
      ])
    #expect(VendorCharonStartContract.requestType == "rpc")
    #expect(VendorCharonStartContract.requestRPC == "start_connection")
    #expect(!VendorCharonStartField.allCases.map(\.rawValue).contains("common.hostItem"))
    #expect(rule(.vip).requirement == .optional)
    #expect(rule(.vipv6).requirement == .optional)
    #expect(rule(.negotiateMode).requirement == .optionalPerTunnel)
    #expect(rule(.routeNetwork).requirement == .requiredPerRoute)
    #expect(rule(.routePrefix).valueKind == .routePrefix)
    #expect(rule(.name).allowsEmptyText)
    #expect(!rule(.sessionID).allowsEmptyText)
  }

  @Test func fieldNameSetCannotSubstituteForNestedTypedMaterial() {
    let allNames = Set(VendorCharonStartField.allCases)
    #expect(allNames.count == VendorCharonStartContract.orderedRules.count)

    let validation = VendorCharonStartValidator.validate(VendorCharonStartCandidate())
    #expect(!validation.complete)
    #expect(validation.snapshot == nil)
    #expect(validation.lineageStatus == .missing)
    #expect(validation.firstMissingField == .sessionID)
    #expect(validation.firstMissingPath == "common.sessionid")
    #expect(validation.fieldReports[0].availability == .generated)
    #expect(validation.fieldReports[1].availability == .generated)
    #expect(validation.fieldReports[2].availability == .generated)
    #expect(validation.fieldReports[3].availability == .generated)
  }

  @Test func generatedTunnelsContainerStillRequiresOneCompleteTunnel() {
    let values = CoreStartTestValues()
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: values.completeCommon(),
      tunnels: []
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(!validation.complete)
    #expect(report(.tunnels, in: validation).availability == .generated)
    #expect(validation.firstMissingField == .authority)
    #expect(validation.firstMissingPath == "tunnels[].authority")
  }

  @Test func completeNestedCandidateProducesOpaqueNonCodableSnapshot() throws {
    let values = CoreStartTestValues()
    let validation = VendorCharonStartValidator.validate(values.completeCandidate())
    let snapshot = try #require(validation.snapshot)

    #expect(validation.complete)
    #expect(validation.lineageStatus == .consistent)
    #expect(validation.firstMissingField == nil)
    #expect(snapshot.tunnelCount == 1)
    #expect(report(.vip, in: validation).availability == .absentOptional)
    #expect(report(.vipv6, in: validation).availability == .absentOptional)
    #expect(report(.negotiateMode, in: validation).availability == .absentOptional)
    #expect(report(.sessionID, in: validation).sources == [.authenticatedPortalResource])
    #expect(!isCodableType(VendorCharonStartCandidate.self))
    #expect(!isCodableType(VendorCharonStartSnapshot.self))
    #expect(!isCodableType(VendorCharonStartLineage.self))
    #expect(isCodableType(VendorCharonStartFieldReport.self))
  }

  @Test func oneIncompleteTunnelCannotBorrowAFieldFromAnotherTunnel() {
    let values = CoreStartTestValues()
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: values.completeCommon(),
      tunnels: [values.completeTunnel(), values.completeTunnel(includeName: false)]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(!validation.complete)
    #expect(validation.firstMissingField == .name)
    #expect(validation.firstMissingPath == "tunnels[1].name")
    #expect(report(.name, in: validation).availability == .missingRequired)
  }

  @Test func everyMaterializedRouteRequiresItsOwnNetworkAndPrefix() {
    let values = CoreStartTestValues()
    let missingPrefix = VendorCharonStartRouteCandidate(network: values.text("network"))
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: values.completeCommon(),
      tunnels: [values.completeTunnel(routes: [values.completeRoute(), missingPrefix])]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(!validation.complete)
    #expect(validation.firstMissingField == .routePrefix)
    #expect(validation.firstMissingPath == "tunnels[0].routes[1].prfix")
  }

  @Test func emptyPresentRoutesArrayDoesNotInventPerRouteFields() {
    let values = CoreStartTestValues()
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: values.completeCommon(),
      tunnels: [values.completeTunnel(routes: [])]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.complete)
    #expect(report(.routes, in: validation).availability == .available)
    #expect(report(.routeNetwork, in: validation).availability == .notApplicable)
    #expect(report(.routePrefix, in: validation).availability == .notApplicable)
  }

  @Test func invalidTextAndPrefixFailWithoutEchoingMaterial() throws {
    let values = CoreStartTestValues()
    let marker = "sensitive-test-marker"
    let invalidSession = values.text(marker + "\0")
    let invalidRoute = VendorCharonStartRouteCandidate(
      network: values.text("network"),
      prefix: values.prefix(129)
    )
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: values.completeCommon(sessionID: invalidSession),
      tunnels: [values.completeTunnel(routes: [invalidRoute])]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(!validation.complete)
    #expect(validation.firstMissingField == .sessionID)
    #expect(report(.sessionID, in: validation).availability == .invalid)
    #expect(report(.routePrefix, in: validation).availability == .invalid)
    let encoded = try JSONEncoder().encode(validation.fieldReports)
    #expect(!String(decoding: encoded, as: UTF8.self).contains(marker))
  }

  @Test func decimalPrefixIsValidatedWithoutMaterializingAString() {
    let values = CoreStartTestValues()
    let valid = values.completeCandidate(
      routes: [
        VendorCharonStartRouteCandidate(
          network: values.text("network"),
          prefix: VendorCharonStartPrefixValue(
            value: .decimalText(TestTextMaterial("128")),
            source: .authenticatedPortalResource,
            lineage: values.lineage
          )
        )
      ])
    let invalid = values.completeCandidate(
      routes: [
        VendorCharonStartRouteCandidate(
          network: values.text("network"),
          prefix: VendorCharonStartPrefixValue(
            value: .decimalText(TestTextMaterial("12x")),
            source: .authenticatedPortalResource,
            lineage: values.lineage
          )
        )
      ])

    #expect(VendorCharonStartValidator.validate(valid).complete)
    #expect(VendorCharonStartValidator.validate(invalid).firstMissingField == .routePrefix)
  }

  private func rule(_ field: VendorCharonStartField) -> VendorCharonStartFieldRule {
    VendorCharonStartContract.orderedRules.first { $0.field == field }!
  }

  private func report(
    _ field: VendorCharonStartField,
    in validation: VendorCharonStartValidation
  ) -> VendorCharonStartFieldReport {
    validation.fieldReports.first { $0.field == field }!
  }
}

private final class TestTextMaterial: @unchecked Sendable, VendorCharonStartTextMaterial {
  private let bytes: [UInt8]
  let byteCount: Int

  init(_ value: String, advertisedByteCount: Int? = nil) {
    bytes = Array(value.utf8)
    byteCount = advertisedByteCount ?? bytes.count
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
}

struct CoreStartTestValues {
  let lineage = VendorCharonStartLineage()

  func text(_ value: String) -> VendorCharonStartTextValue {
    VendorCharonStartTextValue(
      value: TestTextMaterial(value),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  func integer(_ value: Int32) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  func prefix(_ value: Int32) -> VendorCharonStartPrefixValue {
    VendorCharonStartPrefixValue(
      value: .integer(value),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  func completeCommon() -> VendorCharonStartCommonCandidate {
    completeCommon(sessionID: text("session"))
  }

  func completeCommon(
    sessionID: VendorCharonStartTextValue
  ) -> VendorCharonStartCommonCandidate {
    VendorCharonStartCommonCandidate(
      sessionID: sessionID,
      gateway: text("gateway"),
      ikePort: integer(500),
      majorVersion: integer(1),
      ike: text("ike"),
      esp: text("esp"),
      psk: text("psk"),
      ikeLifetime: integer(3_600),
      ipsecLifetime: integer(3_600)
    )
  }

  func completeRoute() -> VendorCharonStartRouteCandidate {
    VendorCharonStartRouteCandidate(network: text("network"), prefix: prefix(32))
  }

  func completeTunnel(
    includeName: Bool = true,
    routes: [VendorCharonStartRouteCandidate]? = nil
  ) -> VendorCharonStartTunnelCandidate {
    VendorCharonStartTunnelCandidate(
      authority: integer(1),
      status: integer(1),
      tunnelName: text("tunnel"),
      family: integer(2),
      resourceFlag: integer(1),
      name: includeName ? text("resource") : nil,
      routes: routes ?? [completeRoute()],
      mapID: text("map")
    )
  }

  func completeCandidate(
    routes: [VendorCharonStartRouteCandidate]? = nil
  ) -> VendorCharonStartCandidate {
    VendorCharonStartCandidate(
      lineage: lineage,
      common: completeCommon(),
      tunnels: [completeTunnel(routes: routes)]
    )
  }
}

private func isCodableType(_ type: Any.Type) -> Bool {
  type is any Codable.Type
}
