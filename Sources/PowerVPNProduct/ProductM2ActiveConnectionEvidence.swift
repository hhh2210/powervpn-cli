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
