import PowerVPNCore

public enum ProductM2VendorStatusOutcome: String, Encodable, Equatable, Sendable {
  case notAttempted = "not_attempted"
  case connected
  case disconnected
  case timeout
  case cancelled
  case leaseClosed = "lease_closed"
  case terminalError = "terminal_error"
}

public enum ProductM2VendorStatusClassification: String, Encodable, Equatable, Sendable {
  case connected
  case disconnected
  case unclassified
}

public struct ProductM2VendorStatusEvidence: Encodable, Equatable, Sendable {
  public let outcome: ProductM2VendorStatusOutcome
  public let statusEventCount: Int
  public let latestClassification: ProductM2VendorStatusClassification?
  public let terminalControlOutcome: ProductM2ControlOutcome?
  public let containsRawStatus = false
  public let containsResourceName = false

  public init(
    outcome: ProductM2VendorStatusOutcome,
    statusEventCount: Int,
    latestClassification: ProductM2VendorStatusClassification?,
    terminalControlOutcome: ProductM2ControlOutcome?
  ) {
    self.outcome = outcome
    self.statusEventCount = statusEventCount
    self.latestClassification = latestClassification
    self.terminalControlOutcome = terminalControlOutcome
  }

  public var connectedProven: Bool {
    outcome == .connected && statusEventCount > 0
      && latestClassification == .connected && terminalControlOutcome == nil
  }

  package static let notAttempted = Self(
    outcome: .notAttempted,
    statusEventCount: 0,
    latestClassification: nil,
    terminalControlOutcome: nil
  )

  package init(_ result: VendorCharonStatusWaitResult) {
    self.init(
      outcome: ProductM2VendorStatusOutcome(result.outcome),
      statusEventCount: result.statusEventCount,
      latestClassification: result.latestClassification.map(
        ProductM2VendorStatusClassification.init),
      terminalControlOutcome: result.terminalOutcome.map(ProductM2ControlOutcome.init)
    )
  }
}

public struct ProductM2ActiveNetworkEvidence: Encodable, Equatable, Sendable {
  public let complete: Bool
  public let helperSingleRunningGeneration: Bool
  public let surgeStable: Bool
  public let vendorGUIAbsent: Bool
  public let unrelatedVendorHelpersAbsent: Bool
  public let selectedRouteBindingDeltaCount: Int
  public let effectiveSelectedRouteBindingIntroduced: Bool
  public let newUtunCount: Int
  public let defaultRouteChanged: Bool
  public let dnsChanged: Bool
  public let persistentRoutesChanged: Bool
  public let selectedResourcePathProven: Bool
  public let containsRawRoutes = false
  public let containsRawState = false
  public let containsSecrets = false

  public init(
    complete: Bool,
    helperSingleRunningGeneration: Bool,
    surgeStable: Bool,
    vendorGUIAbsent: Bool,
    unrelatedVendorHelpersAbsent: Bool,
    selectedRouteBindingDeltaCount: Int,
    effectiveSelectedRouteBindingIntroduced: Bool,
    newUtunCount: Int,
    defaultRouteChanged: Bool,
    dnsChanged: Bool,
    persistentRoutesChanged: Bool,
    selectedResourcePathProven: Bool
  ) {
    self.complete = complete
    self.helperSingleRunningGeneration = helperSingleRunningGeneration
    self.surgeStable = surgeStable
    self.vendorGUIAbsent = vendorGUIAbsent
    self.unrelatedVendorHelpersAbsent = unrelatedVendorHelpersAbsent
    self.selectedRouteBindingDeltaCount = selectedRouteBindingDeltaCount
    self.effectiveSelectedRouteBindingIntroduced = effectiveSelectedRouteBindingIntroduced
    self.newUtunCount = newUtunCount
    self.defaultRouteChanged = defaultRouteChanged
    self.dnsChanged = dnsChanged
    self.persistentRoutesChanged = persistentRoutesChanged
    self.selectedResourcePathProven = selectedResourcePathProven
  }

  public var connectionProven: Bool {
    complete && helperSingleRunningGeneration && surgeStable
      && vendorGUIAbsent && unrelatedVendorHelpersAbsent
      && selectedRouteBindingDeltaCount > 0
      && effectiveSelectedRouteBindingIntroduced && selectedResourcePathProven
  }

  package static let unavailable = Self(
    complete: false,
    helperSingleRunningGeneration: false,
    surgeStable: false,
    vendorGUIAbsent: false,
    unrelatedVendorHelpersAbsent: false,
    selectedRouteBindingDeltaCount: 0,
    effectiveSelectedRouteBindingIntroduced: false,
    newUtunCount: 0,
    defaultRouteChanged: false,
    dnsChanged: false,
    persistentRoutesChanged: false,
    selectedResourcePathProven: false
  )

  package init(_ result: NetworkConnectionResult) {
    self.init(
      complete: result.complete,
      helperSingleRunningGeneration: result.helperSingleRunningGeneration,
      surgeStable: result.surgeStable,
      vendorGUIAbsent: result.vendorGUIAbsent,
      unrelatedVendorHelpersAbsent: result.unrelatedVendorHelpersAbsent,
      selectedRouteBindingDeltaCount: result.selectedRouteBindingDeltaCount,
      effectiveSelectedRouteBindingIntroduced:
        result.effectiveSelectedRouteBindingIntroduced,
      newUtunCount: result.newUtunCount,
      defaultRouteChanged: result.defaultRouteChanged,
      dnsChanged: result.dnsChanged,
      persistentRoutesChanged: result.persistentRoutesChanged,
      selectedResourcePathProven: result.selectedResourcePathProven
    )
  }
}

/// One active-network baseline capture plus its value-free diagnostic
/// classification. Purely additive reporting: gates keep keying off
/// `baseline == nil` exactly as before.
package struct ProductM2ActiveCaptureOutcome: Equatable, Sendable {
  package let baseline: ProductM2NetworkBaseline?
  package let state: ProductM2ActiveCaptureState
  package let changeAxes: [ProductM2ActiveCaptureChangeAxis]
  package let incompleteReason: ProductM2ActiveCaptureIncompleteReason?

  package init(
    baseline: ProductM2NetworkBaseline?,
    state: ProductM2ActiveCaptureState,
    changeAxes: [ProductM2ActiveCaptureChangeAxis] = [],
    incompleteReason: ProductM2ActiveCaptureIncompleteReason? = nil
  ) {
    self.baseline = baseline
    self.state = state
    self.changeAxes = changeAxes
    self.incompleteReason = incompleteReason
  }

  /// Synthetic mapping for baseline sources that do not wrap a snapshot
  /// (test doubles): a present baseline behaves as measured-complete.
  package init(baseline: ProductM2NetworkBaseline?) {
    self.init(
      baseline: baseline,
      state: baseline == nil ? .measuredIncomplete : .measuredComplete
    )
  }

  /// Faithful mapping from the observer's snapshot. Sub-observation states map
  /// 1:1 onto `ProductM2ActiveCaptureState` tokens; `changeAxes` lists, in the
  /// observer's observation order, every axis that did not observe cleanly.
  /// When several axes failed, the summary token carries the most severe
  /// cause with precedence changed_during_capture > command_failed >
  /// output_too_large > invalid_output. A capture where every axis observed
  /// but the completeness predicate still failed is `measured_incomplete`:
  /// `generation_not_exact` when the helper generation fence cannot hold,
  /// otherwise `vendor_processes_inconsistent` (the active-state vendor
  /// process-set rule), which is what separates a helper lifecycle change
  /// from a structural rejection using the JSON alone.
  package init(snapshot: NetworkCleanupSnapshot) {
    if snapshot.complete {
      self.init(
        baseline: ProductM2NetworkBaseline(snapshot: snapshot),
        state: .measuredComplete
      )
      return
    }
    var axes: [ProductM2ActiveCaptureChangeAxis] = []
    var states: Set<NetworkCleanupObservationState> = []
    if snapshot.helperObservationState != .observed {
      axes.append(.helperGeneration)
      states.insert(snapshot.helperObservationState)
    }
    if !snapshot.surge.isObserved {
      axes.append(.helperProcesses)
      states.insert(snapshot.surge.fingerprint.state)
    }
    if !snapshot.defaultRoute.isObserved {
      axes.append(.defaultRoute)
      states.insert(snapshot.defaultRoute.state)
    }
    if !snapshot.dns.isObserved {
      axes.append(.dns)
      states.insert(snapshot.dns.state)
    }
    if !snapshot.interfaces.isObserved {
      axes.append(.interfaces)
      states.insert(snapshot.interfaces.inventory.state)
    }
    if !snapshot.ipv4Routes.isObserved {
      axes.append(.ipv4Routes)
      states.insert(snapshot.ipv4Routes.structural.state)
      states.insert(snapshot.ipv4Routes.persistent.state)
    }
    if !snapshot.ipv6Routes.isObserved {
      axes.append(.ipv6Routes)
      states.insert(snapshot.ipv6Routes.structural.state)
      states.insert(snapshot.ipv6Routes.persistent.state)
    }
    if !snapshot.vendorProcesses.isObserved {
      axes.append(.vendorProcesses)
      states.insert(snapshot.vendorProcesses.fingerprint.state)
    }

    let failureStates = states.subtracting([.observed])
    if failureStates.contains(.changedDuringCapture) {
      self.init(baseline: nil, state: .changedDuringCapture, changeAxes: axes)
    } else if axes.isEmpty {
      self.init(
        baseline: nil,
        state: .measuredIncomplete,
        changeAxes: axes,
        incompleteReason:
          snapshot.helperGeneration.exactInactive || snapshot.helperGeneration.exactRunning
          ? .vendorProcessesInconsistent : .generationNotExact
      )
    } else if failureStates.isEmpty {
      self.init(
        baseline: nil,
        state: .measuredIncomplete,
        changeAxes: axes,
        incompleteReason: .subobservationFailed
      )
    } else if failureStates.contains(.commandFailed) {
      self.init(
        baseline: nil, state: .commandFailed, changeAxes: axes,
        incompleteReason: .subobservationFailed)
    } else if failureStates.contains(.outputTooLarge) {
      self.init(
        baseline: nil, state: .outputTooLarge, changeAxes: axes,
        incompleteReason: .subobservationFailed)
    } else {
      self.init(
        baseline: nil, state: .invalidOutput, changeAxes: axes,
        incompleteReason: .subobservationFailed)
    }
  }
}

extension ProductM2VendorStatusOutcome {
  fileprivate init(_ outcome: VendorCharonStatusWaitOutcome) {
    switch outcome {
    case .connected: self = .connected
    case .disconnected: self = .disconnected
    case .timeout: self = .timeout
    case .cancelled: self = .cancelled
    case .leaseClosed: self = .leaseClosed
    case .terminalError: self = .terminalError
    }
  }
}

extension ProductM2VendorStatusClassification {
  package init(_ classification: VendorCharonStatusClassification) {
    switch classification {
    case .connected: self = .connected
    case .disconnected: self = .disconnected
    case .unclassified: self = .unclassified
    }
  }
}
