import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonStartLineageTests {
  @Test func opaqueLineageUsesReferenceIdentityAndIsNotCodable() {
    let first = VendorCharonStartLineage()
    let second = VendorCharonStartLineage()

    #expect(first !== second)
    #expect(!(VendorCharonStartLineage.self is any Codable.Type))
  }

  @Test func completeValuesWithoutCandidateLineageCannotProduceSnapshot() {
    let values = CoreStartTestValues()
    let complete = values.completeCandidate()
    let candidate = VendorCharonStartCandidate(
      common: complete.common,
      tunnels: complete.tunnels
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.lineageStatus == .missing)
    #expect(!validation.complete)
    #expect(validation.snapshot == nil)
    #expect(validation.firstMissingField == .sessionID)
    #expect(report(.sessionID, validation).availability == .invalid)
  }

  @Test func crossGenerationCommonValueIsInvalidAtItsExactField() {
    let expected = CoreStartTestValues()
    let foreignGeneration = CoreStartTestValues()
    let common = VendorCharonStartCommonCandidate(
      sessionID: expected.text("session"),
      gateway: foreignGeneration.text("gateway"),
      ikePort: expected.integer(500),
      majorVersion: expected.integer(1),
      ike: expected.text("ike"),
      esp: expected.text("esp"),
      psk: expected.text("psk"),
      ikeLifetime: expected.integer(3_600),
      ipsecLifetime: expected.integer(3_600)
    )
    let candidate = VendorCharonStartCandidate(
      lineage: expected.lineage,
      common: common,
      tunnels: [expected.completeTunnel()]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.lineageStatus == .mixed)
    #expect(!validation.complete)
    #expect(validation.firstMissingField == .gateway)
    #expect(validation.firstMissingPath == "common.gateway")
    #expect(report(.gateway, validation).availability == .invalid)
  }

  @Test func crossResourceTunnelValueCannotJoinOtherwiseCompleteCandidate() {
    let expected = CoreStartTestValues()
    let siblingResource = CoreStartTestValues()
    let tunnel = VendorCharonStartTunnelCandidate(
      authority: expected.integer(1),
      status: expected.integer(1),
      tunnelName: expected.text("tunnel"),
      family: expected.integer(2),
      resourceFlag: expected.integer(1),
      name: siblingResource.text("resource"),
      routes: [expected.completeRoute()],
      mapID: expected.text("map")
    )
    let candidate = VendorCharonStartCandidate(
      lineage: expected.lineage,
      common: expected.completeCommon(),
      tunnels: [tunnel]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.lineageStatus == .mixed)
    #expect(!validation.complete)
    #expect(validation.firstMissingField == .name)
    #expect(validation.firstMissingPath == "tunnels[0].name")
  }

  @Test func crossResourceRouteValueIsRejectedIndependently() {
    let expected = CoreStartTestValues()
    let siblingResource = CoreStartTestValues()
    let route = VendorCharonStartRouteCandidate(
      network: siblingResource.text("network"),
      prefix: expected.prefix(32)
    )
    let candidate = VendorCharonStartCandidate(
      lineage: expected.lineage,
      common: expected.completeCommon(),
      tunnels: [expected.completeTunnel(routes: [route])]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.lineageStatus == .mixed)
    #expect(!validation.complete)
    #expect(validation.firstMissingField == .routeNetwork)
    #expect(validation.firstMissingPath == "tunnels[0].routes[0].net")
  }

  @Test func presentOptionalValueMustAlsoMatchCandidateLineage() {
    let expected = CoreStartTestValues()
    let siblingResource = CoreStartTestValues()
    let base = expected.completeCommon()
    let common = VendorCharonStartCommonCandidate(
      sessionID: base.sessionID,
      vip: siblingResource.text("vip"),
      gateway: base.gateway,
      ikePort: base.ikePort,
      majorVersion: base.majorVersion,
      ike: base.ike,
      esp: base.esp,
      psk: base.psk,
      ikeLifetime: base.ikeLifetime,
      ipsecLifetime: base.ipsecLifetime
    )
    let candidate = VendorCharonStartCandidate(
      lineage: expected.lineage,
      common: common,
      tunnels: [expected.completeTunnel()]
    )
    let validation = VendorCharonStartValidator.validate(candidate)

    #expect(validation.lineageStatus == .mixed)
    #expect(validation.firstMissingField == .vip)
    #expect(report(.vip, validation).availability == .invalid)
  }

  @Test func reportsExposeNoSerializableLineageIdentifier() throws {
    let values = CoreStartTestValues()
    let validation = VendorCharonStartValidator.validate(values.completeCandidate())

    #expect(validation.lineageStatus == .consistent)
    #expect(validation.complete)
    let encoded = try JSONEncoder().encode(validation.fieldReports)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(!json.contains("lineage"))
  }

  private func report(
    _ field: VendorCharonStartField,
    _ validation: VendorCharonStartValidation
  ) -> VendorCharonStartFieldReport {
    validation.fieldReports.first { $0.field == field }!
  }
}
