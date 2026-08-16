import Foundation

public struct VPNTarget: Codable, Hashable, Sendable {
  public let name: String
  public let host: String
  public let port: UInt16

  public init(name: String, host: String, port: UInt16 = 22) {
    self.name = name
    self.host = host
    self.port = port
  }

}

public enum ProbeStatus: String, Codable, Sendable {
  case healthy
  case bannerTimeout = "banner_timeout"
  case connectionFailed = "connection_failed"
  case nonSSHBanner = "non_ssh_banner"
}

public struct ProbeResult: Codable, Sendable {
  public let target: VPNTarget
  public let status: ProbeStatus
  public let latencyMilliseconds: Int
  public let detail: String

  public init(
    target: VPNTarget,
    status: ProbeStatus,
    latencyMilliseconds: Int,
    detail: String
  ) {
    self.target = target
    self.status = status
    self.latencyMilliseconds = latencyMilliseconds
    self.detail = detail
  }
}

public struct HelperState: Codable, Sendable {
  public let state: String?
  public let pid: Int?
  public let runs: Int?
  public let successiveCrashes: Int?
  public let lastTerminatingSignal: String?

  public var isRunning: Bool { state == "running" && pid != nil }
}

public struct PowerVPNInstallation: Codable, Sendable {
  public let appVersion: String?
  public let appBuild: String?
  public let appArchitectures: [String]
  public let appRunning: Bool

  public init(
    appVersion: String?,
    appBuild: String?,
    appArchitectures: [String],
    appRunning: Bool
  ) {
    self.appVersion = appVersion
    self.appBuild = appBuild
    self.appArchitectures = appArchitectures
    self.appRunning = appRunning
  }
}

public enum TunnelHealth: String, Codable, Sendable {
  case healthy
  case stopped
  case staleAuthentication = "stale_authentication"
  case retrying
  case unknown
}

public struct TunnelLogState: Codable, Sendable {
  public let health: TunnelHealth
  public let latestEvent: String
  public let historicalHint: Bool

  public init(health: TunnelHealth, latestEvent: String, historicalHint: Bool = true) {
    self.health = health
    self.latestEvent = latestEvent
    self.historicalHint = historicalHint
  }
}

public struct PowerVPNStatus: Codable, Sendable {
  public let appVersion: String?
  public let appBuild: String?
  public let appArchitectures: [String]
  public let appRunning: Bool
  public let helper: HelperState
  public let tunnel: TunnelLogState
}
