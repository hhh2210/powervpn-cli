import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite(.serialized)
struct ProductPortalDryRunAcquisitionStatusTests {
  @Test func everyRejectedPortalStatusMapsToItsRedactedAcquisitionStatus() async throws {
    let expected: [(PortalLoginStatus, ProductPortalAcquisitionStatus)] = [
      (.configurationRejected, .configurationRejected),
      (.credentialInputRejected, .credentialInputRejected),
      (.transportRejected, .transportRejected),
      (.tlsRejected, .tlsRejected),
      (.redirectRejected, .redirectRejected),
      (.loginRejected, .loginRejected),
      (.challengeRequired, .challengeRequired),
      (.loginResponseRejected, .loginResponseRejected),
      (.sessionRejected, .sessionRejected),
      (.resourceListRejected, .resourceListRejected),
      (.authenticatedSnapshotRejected, .authenticatedSnapshotRejected),
      (.logoutRejected, .logoutRejected),
      (.cancelled, .cancelled),
      (.internalFailure, .internalFailure),
    ]

    for (loginStatus, acquisitionStatus) in expected {
      let runtime = ProductPortalDryRunRuntime {
        .rejected(rejectedPortalLoginReport(status: loginStatus))
      }

      let report = await runtime.run(request())

      #expect(report.schemaVersion == 2)
      #expect(report.portalAcquisitionStatus == acquisitionStatus)
      #expect(
        report.outcome
          == (loginStatus == .cancelled ? .cancelled : .portalAcquisitionRejected))
      #expect(report.operations.portalAcquisitionRequested)
      #expect(!report.helperMutationRequested)
      #expect(!report.sshRequested)
      #expect(!report.m2CoordinatorRequested)
      #expect(!report.containsSecrets)
      #expect(report.ownedMaterialErased)
      #expect(!report.dryRunAccepted)

      let encoded = try JSONEncoder().encode(report)
      let object = try #require(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any]
      )
      #expect(object["portalAcquisitionStatus"] as? String == acquisitionStatus.rawValue)
      #expect(object["schemaVersion"] as? Int == 2)
      #expect(object["error"] == nil)
      #expect(object["message"] == nil)
      #expect(object["endpoint"] == nil)
      #expect(object["identity"] == nil)
      #expect(object["session"] == nil)
      #expect(object["cookie"] == nil)
      #expect(object["resources"] == nil)
      #expect(object["response"] == nil)
      #expect(object["logs"] == nil)
      #expect(object["credentials"] == nil)
    }
  }

  @Test func rejectedAcquisitionPublishesOnlyExactTransportDiscriminator() async throws {
    let sentinel = "server-cookie-value-must-not-survive"
    let evidence = PortalTransportFailureEvidence(
      category: .headerFramingRejected,
      setCookieFieldCount: 2,
      setCookieWireSelection: .lastFieldWins,
      duplicateSetCookieRejected: false
    )
    let runtime = ProductPortalDryRunRuntime {
      .rejected(
        rejectedPortalLoginReport(
          status: .transportRejected,
          transportFailure: evidence
        ))
    }

    let report = await runtime.run(request())
    let encoded = try JSONEncoder().encode(report)
    let object = try #require(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    let transport = try #require(
      object["portalTransportFailure"] as? [String: Any]
    )

    #expect(report.schemaVersion == 2)
    #expect(report.portalAcquisitionStatus == .transportRejected)
    #expect(report.portalTransportFailure == evidence)
    #expect(transport["category"] as? String == "header_framing_rejected")
    #expect(transport["setCookieFieldCount"] as? Int == 2)
    #expect(transport["setCookieWireSelection"] as? String == "last_field_wins")
    #expect(transport["duplicateSetCookieRejected"] as? Bool == false)
    #expect(!String(decoding: encoded, as: UTF8.self).contains(sentinel))
    #expect(object["cookie"] == nil)
    #expect(object["response"] == nil)
  }

  @Test func invalidRequestReportsAcquisitionNotRequested() async {
    let observation = PortalDryRunAcquisitionObservation()
    let runtime = ProductPortalDryRunRuntime {
      observation.record()
      return .rejected(rejectedPortalLoginReport(status: .internalFailure))
    }

    let report = await runtime.run(
      ProductPortalDryRunRequest(resourceDisplayName: " \n", sshTarget: .thu21)
    )

    #expect(report.schemaVersion == 2)
    #expect(report.outcome == .invalidRequest)
    #expect(report.portalAcquisitionStatus == .notRequested)
    #expect(!report.operations.portalAcquisitionRequested)
    #expect(!report.helperMutationRequested)
    #expect(!report.sshRequested)
    #expect(!report.m2CoordinatorRequested)
    #expect(!report.containsSecrets)
    #expect(report.ownedMaterialErased)
    #expect(observation.invocationCount == 0)
  }

  @Test func preCancelledRequestReportsAcquisitionNotRequested() async {
    let observation = PortalDryRunAcquisitionObservation()
    let runtime = ProductPortalDryRunRuntime {
      observation.record()
      return .rejected(rejectedPortalLoginReport(status: .internalFailure))
    }
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await runtime.run(request())
    }

    let report = await task.value

    #expect(report.schemaVersion == 2)
    #expect(report.outcome == .cancelled)
    #expect(report.portalAcquisitionStatus == .notRequested)
    #expect(!report.operations.portalAcquisitionRequested)
    #expect(!report.helperMutationRequested)
    #expect(!report.sshRequested)
    #expect(!report.m2CoordinatorRequested)
    #expect(!report.containsSecrets)
    #expect(report.ownedMaterialErased)
    #expect(observation.invocationCount == 0)
  }

  private func request() -> ProductPortalDryRunRequest {
    ProductPortalDryRunRequest(resourceDisplayName: "login21", sshTarget: .thu21)
  }
}

private func rejectedPortalLoginReport(
  status: PortalLoginStatus,
  transportFailure: PortalTransportFailureEvidence? = nil
) -> PortalLoginReport {
  PortalLoginReport(
    status: status,
    operations: PortalOperationEvidence(
      loginRequested: false,
      loginAccepted: false,
      sessionCheckRequested: false,
      sessionCheckAccepted: false,
      resourceListRequested: false,
      resourceListAccepted: false,
      logoutRequested: false,
      logoutAccepted: false
    ),
    ownedMaterial: PortalOwnedMaterialEvidence(
      credentialsErased: true,
      requestBodiesErased: true,
      responseBodiesErased: true,
      sessionMaterialErased: true
    ),
    transportFailure: transportFailure
  )
}

private final class PortalDryRunAcquisitionObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var invocations = 0

  func record() {
    lock.withLock { invocations += 1 }
  }

  var invocationCount: Int {
    lock.withLock { invocations }
  }
}
