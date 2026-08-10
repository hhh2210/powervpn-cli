package enum VendorCharonStatusClassification: String, Equatable, Sendable {
  case connected
  case disconnected
  case unclassified
}

/// Identity-free projection of one exact vendor status dictionary.
///
/// The installed helper also sends a resource name. Core validates that field's
/// wire type but deliberately does not copy its bytes into retained state.
package struct VendorCharonStatusSignal: Equatable, Sendable {
  package let type: Int64
  package let phase: Int64
  package let state: Int64

  package var classification: VendorCharonStatusClassification {
    switch (phase, state) {
    case (2, 5): .connected
    case (2, 7): .disconnected
    default: .unclassified
    }
  }

  package init(type: Int64, phase: Int64, state: Int64) {
    self.type = type
    self.phase = phase
    self.state = state
  }
}
