import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

extension CatalogReplayMatrix {
  /// Deterministic Fisher-Yates order for order-dependence replay. The
  /// generator is deliberately local and stable across Swift releases;
  /// CI selects seeds via `CATALOG_REPLAY_PERMUTATIONS` (comma-separated),
  /// default "0". It is test input generation, not cryptography.
  static func order(seed: Int) -> [CatalogReplayShape] {
    guard shapes.count > 1 else { return shapes }
    var ordered = shapes
    var generator = CatalogReplaySeededGenerator(seed: seed)
    for upperBound in stride(from: ordered.count - 1, through: 1, by: -1) {
      let index = Int(generator.next() % UInt64(upperBound + 1))
      ordered.swapAt(upperBound, index)
    }
    return ordered
  }

  static func permutationSeeds() -> [Int] {
    let raw =
      ProcessInfo.processInfo.environment["CATALOG_REPLAY_PERMUTATIONS"]
      ?? "0"
    return
      raw
      .split(separator: ",")
      .compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
  }
}

private struct CatalogReplaySeededGenerator {
  private var state: UInt64

  init(seed: Int) {
    state = UInt64(truncatingIfNeeded: seed) &+ 0x9E37_79B9_7F4A_7C15
  }

  mutating func next() -> UInt64 {
    state &+= 0x9E37_79B9_7F4A_7C15
    var value = state
    value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
    value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
    return value ^ (value >> 31)
  }
}

/// Order-invariance: shape serving order must not change any
/// classification — the acquisition state machine must hold no static or
/// cross-acquisition state. Seeds come from `CATALOG_REPLAY_PERMUTATIONS`
/// (stable deterministic shuffles; nightly CI passes one seed per matrix leg).
@Suite struct CatalogReplayOrderTests {

  @Test func seededOrdersAreDistinctAndVaryEveryShapesNeighbors() {
    let seeds = Array(0...10)
    let expectedIDs = Set(CatalogReplayMatrix.shapeIDs)
    let orders = seeds.map { CatalogReplayMatrix.order(seed: $0).map(\.label) }

    #expect(Set(orders.map { $0.joined(separator: ",") }).count == seeds.count)
    for order in orders {
      #expect(Set(order) == expectedIDs)
      #expect(order.count == expectedIDs.count)
    }

    for shapeID in expectedIDs {
      var predecessors: Set<String> = []
      var successors: Set<String> = []
      for order in orders {
        guard let index = order.firstIndex(of: shapeID) else {
          Issue.record("missing \(shapeID) from seeded order")
          continue
        }
        if index > order.startIndex {
          predecessors.insert(order[order.index(before: index)])
        }
        if index < order.index(before: order.endIndex) {
          successors.insert(order[order.index(after: index)])
        }
      }
      #expect(predecessors.count >= 5, "\(shapeID) predecessor coverage")
      #expect(successors.count >= 5, "\(shapeID) successor coverage")
    }
  }

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
        try assertCatalogReplayValueFree(report, shape: shape)
      }
    }
  }
}
