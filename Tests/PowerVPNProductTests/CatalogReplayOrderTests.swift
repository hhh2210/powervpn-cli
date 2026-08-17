import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Order-invariance: shape serving order must not change any
/// classification — the acquisition state machine must hold no static or
/// cross-acquisition state. Seeds come from `CATALOG_REPLAY_PERMUTATIONS`
/// (deterministic rotations; nightly CI passes one seed per matrix leg).
@Suite struct CatalogReplayOrderTests {

  @Test func classificationIsInvariantToShapeServingOrder() async throws {
    let seeds = CatalogReplayMatrix.permutationSeeds()
    #expect(!seeds.isEmpty)

    for seed in seeds {
      for shape in CatalogReplayMatrix.order(seed: seed) {
        let fixture = try authenticatedSnapshot(resourceXML: shape.resourceXML)
        defer { fixture.erase() }
        let clock = ProductM2ManualClock()
        let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
        clock.set(milliseconds: 36_000)
        let trace = ProductM2TestTrace()

        let report = await ProductM2ConnectOnceCoordinator(
          dependencies: productM2TestDependencies(
            snapshot: fixture.snapshot, trace: trace
          )
        ).run(catalogReplayRequest(), budget: budget)

        #expect(
          report.selectionFailureClass == shape.expectedClass,
          "seed \(seed) shape \(shape.label)")
        #expect(
          report.resourceCatalogFailure == shape.expectedFailure,
          "seed \(seed) shape \(shape.label)")
        #expect(report.automaticRetryCount == 0)
      }
    }
  }
}
