import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite(.serialized) struct InstalledConfigDiscoveryTests {
  @Test func exactInjectedEvidenceProducesOnlyTheSealedProfile() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }

    let profile = try InstalledConfigDiscovery.discover(
      evidence: fixture.evidence,
      owner: getuid()
    )

    #expect(profile.origin.absoluteString == "https://166.111.143.19:4443")
    #expect(profile.portalVersion == "2.0")
    #expect(profile.selectionSemantics == .latestPrimaryKeyFallback)
    #expect(profile.vendorLanguageIndex == 0)
  }

  @Test func missingArtifactFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    try FileManager.default.removeItem(at: fixture.url(for: .encryptedAddressDatabase))

    #expect(throws: InstalledConfigDiscoveryError.missingArtifact) {
      _ = try discover(fixture)
    }
  }

  @Test func symbolicLinkArtifactFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    let app = fixture.url(for: .appExecutable)
    let target = fixture.root.appendingPathComponent("target")
    try Data("synthetic-app".utf8).write(to: target)
    try FileManager.default.removeItem(at: app)
    try FileManager.default.createSymbolicLink(at: app, withDestinationURL: target)

    #expect(throws: InstalledConfigDiscoveryError.symbolicLink) {
      _ = try discover(fixture)
    }
  }

  @Test func extraArtifactFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    fixture.replaceEvidence(artifacts: fixture.evidence.artifacts + [fixture.evidence.artifacts[0]])

    #expect(throws: InstalledConfigDiscoveryError.malformedEvidence) {
      _ = try discover(fixture)
    }
  }

  @Test func ownerMismatchFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }

    #expect(throws: InstalledConfigDiscoveryError.ownerMismatch) {
      _ = try InstalledConfigDiscovery.discover(
        evidence: fixture.evidence,
        owner: getuid() &+ 1
      )
    }
  }

  @Test func modeDriftFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    #expect(chmod(fixture.url(for: .preferences).path, 0o644) == 0)

    #expect(throws: InstalledConfigDiscoveryError.modeMismatch) {
      _ = try discover(fixture)
    }
  }

  @Test func hashDriftFailsClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    let app = fixture.url(for: .appExecutable)
    try Data("changed-app".utf8).write(to: app)
    #expect(chmod(app.path, 0o755) == 0)

    #expect(throws: InstalledConfigDiscoveryError.hashMismatch) {
      _ = try discover(fixture)
    }
  }

  @Test func boundedReaderRejectsOversizedArtifactBeforeHashing() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    var artifacts = fixture.evidence.artifacts
    let index = try #require(artifacts.firstIndex(where: { $0.role == .appExecutable }))
    let app = artifacts[index]
    artifacts[index] = InstalledArtifactSpec(
      role: app.role,
      path: app.path,
      sha256: app.sha256,
      mode: app.mode,
      maximumByteCount: 1
    )
    fixture.replaceEvidence(artifacts: artifacts)

    #expect(throws: InstalledConfigDiscoveryError.sizeOutOfBounds) {
      _ = try discover(fixture)
    }
  }

  @Test func selectedAddressMustBeExactIntegerZero() throws {
    for value: Any in [1, "0", false, 0.0] {
      let fixture = try InstalledConfigFixture()
      defer { fixture.cleanup() }
      try fixture.rewritePreferences(selectedAddress: value)

      #expect(throws: InstalledConfigDiscoveryError.selectedAddressMismatch) {
        _ = try discover(fixture)
      }
    }
  }

  @Test func vendorLanguagePreferenceIsSealedToTheObservedMismatch() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    let preferences = fixture.url(for: .preferences)
    let data = try PropertyListSerialization.data(
      fromPropertyList: [
        "address_selectedID": 0,
        "currentLanguageKey": "en",
      ],
      format: .binary,
      options: 0
    )
    try data.write(to: preferences)
    #expect(chmod(preferences.path, 0o600) == 0)
    fixture.replaceArtifact(.preferences, sha256: InstalledConfigFixture.sha256(data))

    #expect(throws: InstalledConfigDiscoveryError.languageMismatch) {
      _ = try discover(fixture)
    }
  }

  @Test func hostPortAndVersionDriftFailClosed() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    let locked = fixture.evidence.endpoint
    let drifts = [
      SealedPortalEndpoint(
        scheme: locked.scheme, host: "example.invalid", port: locked.port,
        portalVersion: locked.portalVersion, selectionSemantics: locked.selectionSemantics),
      SealedPortalEndpoint(
        scheme: locked.scheme, host: locked.host, port: 443,
        portalVersion: locked.portalVersion, selectionSemantics: locked.selectionSemantics),
      SealedPortalEndpoint(
        scheme: locked.scheme, host: locked.host, port: locked.port,
        portalVersion: "2.1", selectionSemantics: locked.selectionSemantics),
    ]

    for drift in drifts {
      fixture.replaceEvidence(endpoint: drift)
      #expect(throws: InstalledConfigDiscoveryError.endpointMismatch) {
        _ = try discover(fixture)
      }
    }
  }

  @Test func resourceXMLIsExplicitlyForbidden() throws {
    let fixture = try InstalledConfigFixture()
    defer { fixture.cleanup() }
    let forbidden = fixture.root.appendingPathComponent("resource.xml")
    let data = Data("must-not-be-consumed".utf8)
    try data.write(to: forbidden)
    #expect(chmod(forbidden.path, 0o644) == 0)
    var artifacts = fixture.evidence.artifacts
    artifacts[0] = InstalledArtifactSpec(
      role: .appExecutable,
      path: forbidden.path,
      sha256: InstalledConfigFixture.sha256(data),
      mode: 0o644,
      maximumByteCount: 4_096
    )
    fixture.replaceEvidence(artifacts: artifacts)

    #expect(throws: InstalledConfigDiscoveryError.forbiddenArtifact) {
      _ = try discover(fixture)
    }
  }

  private func discover(_ fixture: InstalledConfigFixture) throws -> InstalledPortalProfile {
    try InstalledConfigDiscovery.discover(evidence: fixture.evidence, owner: getuid())
  }
}
